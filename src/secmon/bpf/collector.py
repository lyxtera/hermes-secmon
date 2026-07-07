"""Collect BPF metadata via bpftool JSON."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from secmon.bpf.identity import map_stable_key, program_stable_key, xlated_sha256_from_dump
from secmon.bpf.models import AttachPoint, BpfLink, BpfMap, BpfProgram, BpfScanResult
from secmon.bpf.provenance import resolve_loader
from secmon.shell import run_cmd_json, run_cmd_safe


def _read_boot_id() -> str:
    return run_cmd_safe(["cat", "/proc/sys/kernel/random/boot_id"]).strip()


def _bpftool_available() -> bool:
    return bool(run_cmd_safe(["which", "bpftool"]).strip())


def _normalize_prog_list(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [p for p in raw if isinstance(p, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def _normalize_map_list(raw: Any) -> list[dict[str, Any]]:
    return _normalize_prog_list(raw)


def _normalize_link_list(raw: Any) -> list[dict[str, Any]]:
    return _normalize_prog_list(raw)


def _pinned_paths(raw: dict[str, Any]) -> list[str]:
    pinned = raw.get("pinned_path") or raw.get("pinned") or []
    if isinstance(pinned, str):
        return [pinned] if pinned else []
    if isinstance(pinned, list):
        return [str(p) for p in pinned if p]
    return []


def _pids_from_raw(raw: dict[str, Any]) -> list[int]:
    pids: list[int] = []
    for key in ("pids", "pid"):
        val = raw.get(key)
        if val is None:
            continue
        if isinstance(val, int):
            pids.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, int):
                    pids.append(item)
                elif isinstance(item, dict) and "pid" in item:
                    pids.append(int(item["pid"]))
    return sorted(set(pids))


def _btf_hash(btf_id: int | None) -> str:
    if not btf_id:
        return "none"
    raw = run_cmd_json(["bpftool", "-j", "btf", "dump", "id", str(btf_id)])
    if raw is None:
        return "none"
    return hashlib.sha256(str(raw).encode()).hexdigest()[:16]


def _dump_xlated(prog_id: int) -> str:
    data = run_cmd_safe(["bpftool", "prog", "dump", "xlated", "id", str(prog_id)], default="")
    return xlated_sha256_from_dump(data.encode("utf-8", errors="replace"))


def _parse_links(raw_links: list[dict[str, Any]]) -> list[BpfLink]:
    links: list[BpfLink] = []
    for item in raw_links:
        link_id = int(item.get("id", item.get("link_id", 0)) or 0)
        prog_id = int(item.get("prog_id", item.get("progId", 0)) or 0)
        attach_type = str(item.get("attach_type", item.get("attachType", "")))
        link_type = str(item.get("type", item.get("link_type", "")))
        target = str(
            item.get("target_name")
            or item.get("target")
            or item.get("cgroup")
            or item.get("ifname")
            or item.get("tracepoint")
            or item.get("kprobe")
            or item.get("fentry")
            or item.get("fexit")
            or item.get("hook")
            or ""
        )
        target_kind = str(item.get("target_kind", item.get("targetKind", link_type or "unknown")))
        pinned = _pinned_paths(item)
        links.append(
            BpfLink(
                link_id=link_id,
                prog_id=prog_id,
                link_type=link_type,
                attach_type=attach_type,
                target=target,
                target_kind=target_kind,
                pinned_path=pinned[0] if pinned else "",
            )
        )
    return links


def _attach_from_links(links: list[BpfLink], prog_id: int) -> list[AttachPoint]:
    points: list[AttachPoint] = []
    for link in links:
        if link.prog_id == prog_id:
            points.append(
                AttachPoint(
                    attach_type=link.attach_type or link.link_type,
                    target_kind=link.target_kind,
                    target=link.target,
                )
            )
    return points


def _attach_from_cgroup_net(
    prog_id: int,
    cgroup_raw: Any,
    net_raw: Any,
) -> list[AttachPoint]:
    points: list[AttachPoint] = []

    def walk_cgroup(node: Any, path: str = "/") -> None:
        if isinstance(node, dict):
            current = str(node.get("path", path))
            for key, val in node.items():
                if key in ("ingress", "egress", "devices") and isinstance(val, list):
                    for entry in val:
                        if isinstance(entry, dict):
                            pid = int(entry.get("id", entry.get("prog_id", 0)) or 0)
                            if pid == prog_id:
                                points.append(
                                    AttachPoint(
                                        attach_type=f"cgroup_{key}",
                                        target_kind="cgroup",
                                        target=current,
                                    )
                                )
                        elif isinstance(entry, int) and entry == prog_id:
                            points.append(
                                AttachPoint(
                                    attach_type=f"cgroup_{key}",
                                    target_kind="cgroup",
                                    target=current,
                                )
                            )
                elif isinstance(val, (dict, list)):
                    walk_cgroup(val, current)
        elif isinstance(node, list):
            for item in node:
                walk_cgroup(item, path)

    walk_cgroup(cgroup_raw)

    if isinstance(net_raw, dict):
        for ifname, data in net_raw.items():
            if not isinstance(data, dict):
                continue
            for section, entries in data.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    eid = entry if isinstance(entry, int) else int(
                        entry.get("id", entry.get("prog_id", 0)) or 0
                    ) if isinstance(entry, dict) else 0
                    if eid == prog_id:
                        points.append(
                            AttachPoint(
                                attach_type=str(section),
                                target_kind="interface",
                                target=str(ifname),
                            )
                        )
    return points


def _build_map(raw: dict[str, Any]) -> BpfMap:
    map_id = int(raw.get("id", 0) or 0)
    btf_id = raw.get("btf_id")
    btf_id_int = int(btf_id) if btf_id is not None else None
    m = BpfMap(
        id=map_id,
        name=str(raw.get("name", "")),
        map_type=str(raw.get("type", "")),
        key_size=int(raw.get("key_size", raw.get("key_sz", 0)) or 0),
        value_size=int(raw.get("value_size", raw.get("value_sz", 0)) or 0),
        max_entries=int(raw.get("max_entries", raw.get("max_entries", 0)) or 0),
        flags=int(raw.get("flags", 0) or 0),
        btf_id=btf_id_int,
        pinned_paths=_pinned_paths(raw),
        fd_holder_pids=_pids_from_raw(raw),
        owner_program_ids=[
            int(x) for x in (raw.get("prog_ids") or raw.get("owner_prog_ids") or [])
        ],
        btf_hash=_btf_hash(btf_id_int),
    )
    m.stable_key = map_stable_key(m)
    return m


def _build_program(
    raw: dict[str, Any],
    links: list[BpfLink],
    cgroup_raw: Any,
    net_raw: Any,
    maps_by_id: dict[int, BpfMap],
) -> BpfProgram:
    prog_id = int(raw.get("id", 0) or 0)
    map_ids = [int(x) for x in (raw.get("map_ids") or [])]
    btf_id = raw.get("btf_id")
    btf_id_int = int(btf_id) if btf_id is not None else None
    attach_points = _attach_from_links(links, prog_id)
    attach_points.extend(_attach_from_cgroup_net(prog_id, cgroup_raw, net_raw))
    # dedupe attach points
    seen: set[tuple[str, str, str]] = set()
    unique_attach: list[AttachPoint] = []
    for ap in attach_points:
        t = ap.as_tuple()
        if t not in seen:
            seen.add(t)
            unique_attach.append(ap)

    fd_pids = _pids_from_raw(raw)
    loader_pid = fd_pids[0] if fd_pids else None

    prog = BpfProgram(
        id=prog_id,
        name=str(raw.get("name", "")),
        prog_type=str(raw.get("type", "")),
        tag=str(raw.get("tag", "")),
        uid=int(raw["uid"]) if raw.get("uid") is not None else None,
        loaded_at=str(raw.get("loaded_at", raw.get("loaded_at_ns", ""))),
        map_ids=map_ids,
        btf_id=btf_id_int,
        verified_insns=int(raw["verified_insns"]) if raw.get("verified_insns") is not None else None,
        xlated_sha256=_dump_xlated(prog_id),
        pinned_paths=_pinned_paths(raw),
        fd_holder_pids=fd_pids,
        attach_points=unique_attach,
        links=[lnk for lnk in links if lnk.prog_id == prog_id],
        loader=resolve_loader(loader_pid),
    )
    prog.stable_key = program_stable_key(prog, maps_by_id)
    return prog


def collect_bpf_scan(cfg: dict | None = None) -> BpfScanResult:
    """Full BPF inventory via bpftool JSON."""
    _ = cfg
    result = BpfScanResult(boot_id=_read_boot_id(), bpftool_available=_bpftool_available())
    if not result.bpftool_available:
        return result

    raw_progs = run_cmd_json(["bpftool", "-j", "prog", "show"])
    raw_maps = run_cmd_json(["bpftool", "-j", "map", "show"])
    raw_links = run_cmd_json(["bpftool", "-j", "link", "show"])
    cgroup_raw = run_cmd_json(["bpftool", "-j", "cgroup", "show", "/"])
    if cgroup_raw is None and os.path.isdir("/sys/fs/cgroup"):
        cgroup_raw = run_cmd_json(["bpftool", "-j", "cgroup", "show", "/sys/fs/cgroup"])
    net_raw = run_cmd_json(["bpftool", "-j", "net", "show"])

    prog_list = _normalize_prog_list(raw_progs)
    map_list = _normalize_map_list(raw_maps)
    link_list = _normalize_link_list(raw_links)
    links = _parse_links(link_list)

    maps: list[BpfMap] = []
    maps_by_id: dict[int, BpfMap] = {}
    for raw in map_list:
        m = _build_map(raw)
        maps.append(m)
        maps_by_id[m.id] = m

    programs: list[BpfProgram] = []
    for raw in prog_list:
        programs.append(_build_program(raw, links, cgroup_raw, net_raw, maps_by_id))

    result.programs = programs
    result.maps = maps
    result.links = links
    result.programs_loaded = bool(programs)
    return result
