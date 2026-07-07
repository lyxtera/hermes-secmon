"""BPF audit orchestration — scan, classify, watchlist, findings."""

from __future__ import annotations

from secmon.audit.base import AuditFinding
from secmon.bpf.auditd import check_audit_gap
from secmon.bpf.classifier import classify_map, classify_program
from secmon.bpf.collector import collect_bpf_scan
from secmon.bpf.models import WatchState
from secmon.bpf.watchlist import baseline_keys, ensure_bpf_state, update_watchlist_from_scan
from secmon.shell import run_cmd_safe


def _finding_for_program(prog_meta: dict, classification, *, first_seen: bool) -> AuditFinding | None:
    state = classification.watch_state
    detail = {
        "stable_key": prog_meta.get("stable_key"),
        "risk_score": classification.risk_score,
        "bpf_id": prog_meta.get("id"),
        "reasons": classification.reasons,
    }
    if state == WatchState.SURVEILLANCE and first_seen:
        return AuditFinding(
            "INFO",
            3,
            "NC-9-bpf-surveillance-started",
            f"BPF surveillance started: {prog_meta.get('name', prog_meta.get('stable_key'))}",
            detail,
        )
    if state == WatchState.ALERT_CRITICAL:
        return AuditFinding(
            "CRITICAL",
            3,
            "NC-9-bpf-critical-program",
            f"Critical BPF program: {prog_meta.get('name')} ({prog_meta.get('prog_type')})",
            detail,
        )
    if state == WatchState.ALERT_HIGH:
        return AuditFinding(
            "HIGH",
            3,
            "NC-9-bpf-high-risk-program",
            f"High-risk BPF program: {prog_meta.get('name')} ({prog_meta.get('prog_type')})",
            detail,
        )
    return None


def _finding_for_map(map_meta: dict, classification, *, first_seen: bool) -> AuditFinding | None:
    state = classification.watch_state
    detail = {
        "stable_key": map_meta.get("stable_key"),
        "risk_score": classification.risk_score,
        "bpf_id": map_meta.get("id"),
        "reasons": classification.reasons,
    }
    if state == WatchState.SURVEILLANCE and first_seen:
        return AuditFinding(
            "INFO",
            3,
            "NC-9-bpf-surveillance-started",
            f"BPF surveillance started: map {map_meta.get('name', map_meta.get('stable_key'))}",
            detail,
        )
    if state in (WatchState.ALERT_HIGH, WatchState.ALERT_CRITICAL):
        sev = "CRITICAL" if state == WatchState.ALERT_CRITICAL else "HIGH"
        return AuditFinding(
            sev,
            3,
            "NC-9-bpf-high-risk-map",
            f"High-risk BPF map: {map_meta.get('name')} ({map_meta.get('map_type')})",
            detail,
        )
    return None


def run_bpf_audit(state: dict, cfg: dict) -> list[AuditFinding]:
    """Full BPF scan during audit layer — replaces ID-based NC-9 delta alerts."""
    findings: list[AuditFinding] = []
    ensure_bpf_state(state)

    scan = collect_bpf_scan(cfg)
    if not scan.bpftool_available:
        findings.append(AuditFinding("MEDIUM", 3, "NC-9-nobpftool", "bpftool not installed"))
        return findings
    if not scan.programs_loaded:
        findings.append(
            AuditFinding("MEDIUM", 3, "NC-9-nobpf", "bpftool available but no programs")
        )

    prog_wl_before = {
        k: v.get("state")
        for k, v in state.get("bpf", {}).get("watchlist", {}).get("programs", {}).items()
    }
    map_wl_before = {
        k: v.get("state")
        for k, v in state.get("bpf", {}).get("watchlist", {}).get("maps", {}).items()
    }

    maps_by_id = {m.id: m for m in scan.maps}
    bl_prog = baseline_keys(state, "programs")
    bl_map = baseline_keys(state, "maps")

    for prog in scan.programs:
        classification = classify_program(prog, maps_by_id, cfg, bl_prog)
        first_seen = prog.stable_key not in prog_wl_before
        finding = _finding_for_program(prog.to_dict(), classification, first_seen=first_seen)
        if finding:
            findings.append(finding)

    for m in scan.maps:
        classification = classify_map(m, cfg, bl_map)
        first_seen = m.stable_key not in map_wl_before
        finding = _finding_for_map(m.to_dict(), classification, first_seen=first_seen)
        if finding:
            findings.append(finding)

    update_watchlist_from_scan(state, scan, cfg)

    gap, detail = check_audit_gap(state)
    if gap:
        findings.append(
            AuditFinding(
                "HIGH",
                3,
                "NC-9-bpf-monitoring-gap",
                "BPF auditd monitoring gap — lost/backlog counter increased",
                detail,
            )
        )

    return findings


def bpftool_unpriv_check(state: dict) -> list[AuditFinding]:
    """Sysctl unprivileged BPF check — kept callable from process layer."""
    findings: list[AuditFinding] = []
    bpf_disabled = run_cmd_safe(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"]).strip()
    scan = collect_bpf_scan()
    if scan.programs_loaded and bpf_disabled != "1":
        findings.append(
            AuditFinding(
                "CRITICAL",
                3,
                "NC-9-unpriv",
                "Unprivileged BPF enabled with programs loaded",
            )
        )
    return findings
