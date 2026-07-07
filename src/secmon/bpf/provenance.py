"""Process provenance for BPF loader PIDs."""

from __future__ import annotations

import hashlib
import os
import re

from secmon.bpf.models import LoaderProvenance
from secmon.shell import run_cmd_safe


def _sha256_file(path: str) -> str | None:
    real = os.path.realpath(path) if path and not path.endswith("(deleted)") else path
    if not real or real.endswith("(deleted)"):
        return None
    try:
        h = hashlib.sha256()
        with open(real, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _read_stat(pid: int) -> tuple[str, int, str] | None:
    try:
        stat = open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace").read()
        m = re.match(r"(\d+) \((.+?)\) \S (\d+)", stat)
        if not m:
            return None
        start_ticks = stat.split()[21] if len(stat.split()) > 21 else ""
        return m.group(2), int(m.group(3)), start_ticks
    except OSError:
        return None


def _read_status_field(pid: int, prefix: str) -> str:
    try:
        for line in open(f"/proc/{pid}/status", encoding="utf-8", errors="replace"):
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def _systemd_unit(pid: int) -> str:
    cgroup = _read_status_field(pid, "Cgroup")
    for part in cgroup.split("/"):
        if part.endswith(".service"):
            return part
    out = run_cmd_safe(
        ["systemctl", "status", str(pid), "--no-pager", "-n", "0"],
        timeout=5,
    )
    for line in out.splitlines():
        if "└─" in line or "├─" in line:
            continue
        if ".service" in line:
            m = re.search(r"([\w@.-]+\.service)", line)
            if m:
                return m.group(1)
    return ""


def _dpkg_owner(path: str) -> str:
    if not path or path.endswith("(deleted)"):
        return ""
    real = os.path.realpath(path)
    out = run_cmd_safe(["dpkg", "-S", real], timeout=10)
    if out:
        return out.split(":", 1)[0].strip()
    return ""


def _parent_chain(pid: int, limit: int = 8) -> list[dict]:
    chain: list[dict] = []
    current = pid
    seen: set[int] = set()
    while current > 1 and len(chain) < limit:
        if current in seen:
            break
        seen.add(current)
        stat = _read_stat(current)
        if not stat:
            break
        comm, ppid, _ = stat
        exe = ""
        try:
            exe = os.readlink(f"/proc/{current}/exe")
        except OSError:
            pass
        chain.append({"pid": current, "comm": comm, "exe": exe})
        current = ppid
    return chain


def resolve_loader(pid: int | None) -> LoaderProvenance:
    """Collect loader metadata from /proc for a BPF FD holder PID."""
    if pid is None:
        return LoaderProvenance()

    stat = _read_stat(pid)
    comm, ppid, start_ticks = stat if stat else ("", 0, "")
    exe = ""
    cmdline = ""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        cmdline = (
            open(f"/proc/{pid}/cmdline", "rb")
            .read()
            .replace(b"\x00", b" ")
            .decode("utf-8", errors="replace")
            .strip()
        )
    except OSError:
        pass

    uid_field = _read_status_field(pid, "Uid")
    uids = uid_field.split()
    uid = int(uids[0]) if uids else None
    euid = int(uids[1]) if len(uids) > 1 else None
    auid = None
    try:
        for line in open(f"/proc/{pid}/status", encoding="utf-8", errors="replace"):
            if line.startswith("Loginuid:"):
                auid = int(line.split()[1])
                break
    except OSError:
        pass

    cap = _read_status_field(pid, "CapEff")
    cgroup = _read_status_field(pid, "Cgroup")
    unit = _systemd_unit(pid)

    namespaces: dict[str, str] = {}
    ns_dir = f"/proc/{pid}/ns"
    if os.path.isdir(ns_dir):
        for name in os.listdir(ns_dir):
            try:
                namespaces[name] = os.readlink(os.path.join(ns_dir, name))
            except OSError:
                continue

    return LoaderProvenance(
        pid=pid,
        ppid=ppid,
        pid_start_time=start_ticks,
        exe=exe,
        exe_sha256=_sha256_file(exe),
        cmdline=cmdline or comm,
        uid=uid,
        euid=euid,
        auid=auid,
        capabilities=cap,
        systemd_unit=unit,
        cgroup=cgroup,
        namespaces=namespaces,
        dpkg_package=_dpkg_owner(exe),
        parent_chain=_parent_chain(pid),
    )
