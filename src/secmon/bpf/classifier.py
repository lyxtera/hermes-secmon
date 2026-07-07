"""BPF risk scoring, systemd whitelist, and classification decisions."""

from __future__ import annotations

import os
import re

from secmon.bpf.models import (
    BpfMap,
    BpfProgram,
    ClassificationResult,
    LoaderProvenance,
    WatchState,
)

HIGH_RISK_PROG_TYPES = {
    "lsm",
    "kprobe",
    "kretprobe",
    "fentry",
    "fexit",
    "raw_tracepoint",
    "tracepoint",
    "perf_event",
    "struct_ops",
}

HIGH_RISK_ATTACH_PATTERNS = [
    re.compile(r"security_", re.I),
    re.compile(r"commit_creds", re.I),
    re.compile(r"prepare_kernel_cred", re.I),
    re.compile(r"execve", re.I),
    re.compile(r"openat", re.I),
    re.compile(r"vfs_read|vfs_write", re.I),
    re.compile(r"tcp_connect|tcp_sendmsg", re.I),
    re.compile(r"bpf_", re.I),
    re.compile(r"ptrace", re.I),
    re.compile(r"process_vm_readv|process_vm_writev", re.I),
]

HIGH_RISK_MAP_TYPES = {
    "prog_array",
    "array_of_maps",
    "hash_of_maps",
    "ringbuf",
    "user_ringbuf",
    "perf_event_array",
    "sockmap",
    "sockhash",
    "devmap",
    "cpumap",
    "xskmap",
    "task_storage",
    "inode_storage",
    "sk_storage",
}

SUSPICIOUS_LOADER_COMMS = re.compile(
    r"(^|/)(bash|sh|dash|zsh|python[0-9.]*|perl|node|curl|wget)( |$)",
    re.I,
)

SUSPICIOUS_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

DEFAULT_SYSTEMD_LOADERS = ("/usr/lib/systemd/systemd", "/lib/systemd/systemd")
DEFAULT_SYSTEMD_CGROUP_PREFIXES = ("/system.slice",)

SYSTEMD_WHITELIST_RULES = {
    "sd_fw_ingress": {
        "prog_type": "cgroup_skb",
        "attach": "cgroup_ingress",
    },
    "sd_fw_egress": {
        "prog_type": "cgroup_skb",
        "attach": "cgroup_egress",
    },
    "sd_devices": {
        "prog_type": "cgroup_device",
        "attach": "cgroup_device",
    },
}


def bpf_config(cfg: dict) -> dict:
    return cfg.get("bpf", {})


def _is_systemd_loader(loader: LoaderProvenance, cfg: dict) -> bool:
    paths = tuple(bpf_config(cfg).get("systemd_loader_paths", list(DEFAULT_SYSTEMD_LOADERS)))
    exe = os.path.realpath(loader.exe) if loader.exe else ""
    if exe in paths:
        return True
    if loader.systemd_unit in ("systemd.service", "init.scope"):
        return True
    base = os.path.basename(loader.exe)
    return base == "systemd" and exe.endswith("/systemd")


def _cgroup_matches_systemd(attach_target: str, loader: LoaderProvenance, cfg: dict) -> bool:
    prefixes = bpf_config(cfg).get("systemd_cgroup_prefixes", list(DEFAULT_SYSTEMD_CGROUP_PREFIXES))
    haystack = f"{attach_target} {loader.cgroup}"
    return any(p in haystack for p in prefixes)


def _attach_matches(prog: BpfProgram, expected: str) -> bool:
    expected_norm = expected.lower().replace(" ", "_")
    for ap in prog.attach_points:
        at = ap.attach_type.lower().replace(" ", "_")
        if expected_norm in at or at in expected_norm:
            return True
        if expected_norm == "cgroup_device" and ap.target_kind == "cgroup" and "device" in at:
            return True
    return False


def is_systemd_whitelisted(prog: BpfProgram, cfg: dict) -> bool:
    """Hard whitelist — all conditions must match; never by name alone."""
    rule = SYSTEMD_WHITELIST_RULES.get(prog.name)
    if not rule:
        return False
    if prog.prog_type != rule["prog_type"]:
        return False
    if not _attach_matches(prog, rule["attach"]):
        return False
    if not _is_systemd_loader(prog.loader, cfg):
        return False
    if not prog.attach_points:
        return False
    return all(_cgroup_matches_systemd(ap.target, prog.loader, cfg) for ap in prog.attach_points)


def _loader_risk(loader: LoaderProvenance) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    exe = loader.exe or ""
    if any(exe.startswith(p) for p in SUSPICIOUS_EXE_PREFIXES):
        score += 40
        reasons.append("loader_exe_tmp")
    if "(deleted)" in exe:
        score += 30
        reasons.append("loader_exe_deleted")
    if exe and not loader.dpkg_package:
        score += 20
        reasons.append("loader_not_in_dpkg")
    if (loader.euid == 0 or loader.uid == 0) and not loader.systemd_unit:
        score += 25
        reasons.append("root_without_systemd_unit")
    cmd = f"{loader.cmdline} {exe}"
    if SUSPICIOUS_LOADER_COMMS.search(cmd):
        score += 35
        reasons.append("suspicious_loader_comm")
    return score, reasons


def _program_type_risk(prog_type: str) -> tuple[int, list[str]]:
    if prog_type in HIGH_RISK_PROG_TYPES:
        return 40, [f"high_risk_type:{prog_type}"]
    return 0, []


def _attach_risk(prog: BpfProgram) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    type_is_high = prog.prog_type in HIGH_RISK_PROG_TYPES
    for ap in prog.attach_points:
        target = f"{ap.attach_type} {ap.target}"
        for pattern in HIGH_RISK_ATTACH_PATTERNS:
            if pattern.search(target):
                pts = 60 if type_is_high else 50
                score += pts
                reasons.append(f"high_risk_attach:{target[:80]}")
                break
    return score, reasons


def _map_type_risk(map_type: str) -> tuple[int, list[str]]:
    if map_type in HIGH_RISK_MAP_TYPES:
        return 30, [f"high_risk_map:{map_type}"]
    return 0, []


def score_program(prog: BpfProgram, maps_by_id: dict[int, BpfMap], cfg: dict) -> ClassificationResult:
    if is_systemd_whitelisted(prog, cfg):
        return ClassificationResult(WatchState.IGNORED, 0, ["systemd_whitelist"], whitelisted=True)

    score = 0
    reasons: list[str] = []
    pts, rs = _program_type_risk(prog.prog_type)
    score += pts
    reasons.extend(rs)
    pts, rs = _attach_risk(prog)
    score += pts
    reasons.extend(rs)
    pts, rs = _loader_risk(prog.loader)
    score += pts
    reasons.extend(rs)

    for mid in prog.map_ids:
        m = maps_by_id.get(mid)
        if m:
            pts, rs = _map_type_risk(m.map_type)
            score += pts
            reasons.extend(rs)

    score = min(score, 150)
    return ClassificationResult(_state_from_score(score), score, reasons)


def score_map(m: BpfMap, cfg: dict) -> ClassificationResult:
    _ = cfg
    score = 0
    reasons: list[str] = []
    pts, rs = _map_type_risk(m.map_type)
    score += pts
    reasons.extend(rs)
    score = min(score, 150)
    return ClassificationResult(_state_from_score(score), score, reasons)


def _state_from_score(score: int) -> WatchState:
    if score >= 100:
        return WatchState.ALERT_CRITICAL
    if score >= 70:
        return WatchState.ALERT_HIGH
    return WatchState.SURVEILLANCE


def classify_program(
    prog: BpfProgram,
    maps_by_id: dict[int, BpfMap],
    cfg: dict,
    baseline_keys: set[str],
) -> ClassificationResult:
    if prog.stable_key in baseline_keys:
        return ClassificationResult(WatchState.BASELINE_MATCH, 0, ["baseline_match"])
    return score_program(prog, maps_by_id, cfg)


def classify_map(m: BpfMap, cfg: dict, baseline_keys: set[str]) -> ClassificationResult:
    if m.stable_key in baseline_keys:
        return ClassificationResult(WatchState.BASELINE_MATCH, 0, ["baseline_match"])
    return score_map(m, cfg)


NON_PROMOTABLE_TYPES = {
    "lsm",
    "kprobe",
    "kretprobe",
    "fentry",
    "fexit",
    "raw_tracepoint",
    "struct_ops",
}


def can_promote_program(prog_meta: dict, maps_meta: list[dict]) -> tuple[bool, str]:
    prog_type = prog_meta.get("prog_type", "")
    if prog_type in NON_PROMOTABLE_TYPES:
        return False, f"program type {prog_type} cannot be auto-promoted"
    map_ids = set(prog_meta.get("map_ids", []))
    for m in maps_meta:
        if m.get("id") in map_ids and m.get("map_type") == "prog_array":
            return False, "program uses prog_array map"
    return True, ""
