"""BPF watcher — refresh watchlist, detect deltas, alert on escalation."""

from __future__ import annotations

from secmon.audit.base import AuditFinding
from secmon.bpf.auditd import check_audit_gap
from secmon.bpf.classifier import classify_map, classify_program, score_program
from secmon.bpf.collector import collect_bpf_scan
from secmon.bpf.models import WatchState
from secmon.bpf.watchlist import baseline_keys, ensure_bpf_state, get_watchlist, update_watchlist_from_scan


def _severity_rank(state: str | None) -> int:
    order = {
        WatchState.SURVEILLANCE.value: 1,
        WatchState.BENIGN_CANDIDATE.value: 2,
        WatchState.ALERT_HIGH.value: 3,
        WatchState.ALERT_CRITICAL.value: 4,
    }
    return order.get(state or "", 0)


def _escalation_finding(
    entry: dict,
    new_state: WatchState,
    message: str,
    check_id: str,
    severity: str,
) -> AuditFinding | None:
    prev_alert = entry.get("last_alert_state")
    prev_rank = _severity_rank(prev_alert)
    new_rank = _severity_rank(new_state.value)
    if new_rank <= prev_rank and prev_alert == new_state.value:
        return None
    detail = {
        "stable_key": entry.get("stable_key"),
        "risk_score": entry.get("risk_score"),
        "bpf_id": entry.get("current_id"),
        "prev_state": entry.get("state"),
        "new_state": new_state.value,
    }
    entry["last_alert_state"] = new_state.value
    return AuditFinding(severity, 3, check_id, message, detail)


def _detect_program_deltas(
    entry: dict,
    prog,
    maps_by_id: dict,
    cfg: dict,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    old_meta = entry.get("metadata", {})
    new_meta = prog.to_dict()

    old_links = {lnk.get("link_id") for lnk in old_meta.get("links", [])}
    new_links = new_meta.get("links", [])
    for lnk in new_links:
        if lnk.get("link_id") not in old_links:
            f = _escalation_finding(
                entry,
                WatchState.ALERT_HIGH,
                f"BPF link updated for {prog.name}",
                "NC-9-bpf-link-updated",
                "HIGH",
            )
            if f:
                findings.append(f)

    old_pins = set(old_meta.get("pinned_paths", []))
    new_pins = set(new_meta.get("pinned_paths", []))
    added_pins = new_pins - old_pins
    if added_pins:
        findings.append(
            AuditFinding(
                "MEDIUM",
                3,
                "NC-9-bpf-pinned-persistence",
                f"BPF pin added for {prog.name}: {sorted(added_pins)[0]}",
                {
                    "stable_key": prog.stable_key,
                    "pins": sorted(added_pins),
                    "bpf_id": prog.id,
                },
            )
        )

    old_loader = old_meta.get("loader", {})
    new_loader = new_meta.get("loader", {})
    if old_loader.get("exe") != new_loader.get("exe"):
        classification = score_program(prog, maps_by_id, cfg)
        if classification.risk_score >= 40:
            f = _escalation_finding(
                entry,
                WatchState.ALERT_HIGH,
                f"Suspicious BPF loader for {prog.name}: {new_loader.get('exe', '')}",
                "NC-9-bpf-loader-suspicious",
                "HIGH",
            )
            if f:
                findings.append(f)

    return findings


def _detect_map_deltas(entry: dict, m) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    old_meta = entry.get("metadata", {})
    new_meta = m.to_dict()
    if (
        old_meta.get("max_entries") != new_meta.get("max_entries")
        or old_meta.get("flags") != new_meta.get("flags")
        or set(old_meta.get("fd_holder_pids", [])) != set(new_meta.get("fd_holder_pids", []))
    ):
        findings.append(
            AuditFinding(
                "HIGH",
                3,
                "NC-9-bpf-map-mutated",
                f"BPF map mutated: {m.name}",
                {
                    "stable_key": m.stable_key,
                    "bpf_id": m.id,
                },
            )
        )
    return findings


def run_bpf_watch(state: dict, cfg: dict) -> list[AuditFinding]:
    """Refresh BPF watchlist and emit findings only on escalation or deltas."""
    findings: list[AuditFinding] = []
    ensure_bpf_state(state)

    if not collect_bpf_scan(cfg).bpftool_available:
        return findings

    scan = collect_bpf_scan(cfg)
    maps_by_id = {m.id: m for m in scan.maps}
    prog_by_key = {p.stable_key: p for p in scan.programs}
    prog_by_id = {p.id: p for p in scan.programs}
    map_by_key = {m.stable_key: m for m in scan.maps}

    prog_wl = get_watchlist(state, "programs")
    map_wl = get_watchlist(state, "maps")
    bl_prog = baseline_keys(state, "programs")
    bl_map = baseline_keys(state, "maps")

    for key, entry in list(prog_wl.items()):
        if entry.get("state") == WatchState.VANISHED.value:
            continue
        prog = prog_by_key.get(key)
        if prog is None and entry.get("current_id") is not None:
            prog = prog_by_id.get(int(entry["current_id"]))
        if not prog:
            continue
        classification = classify_program(prog, maps_by_id, cfg, bl_prog)
        prev_state = entry.get("state")
        findings.extend(_detect_program_deltas(entry, prog, maps_by_id, cfg))
        entry["metadata"] = prog.to_dict()
        entry["current_id"] = prog.id
        entry["risk_score"] = classification.risk_score
        entry["state"] = classification.watch_state.value
        if prog.stable_key != key:
            prog_wl.pop(key, None)
            prog_wl[prog.stable_key] = entry
            entry["stable_key"] = prog.stable_key

        if classification.watch_state in (WatchState.ALERT_HIGH, WatchState.ALERT_CRITICAL):
            sev = "CRITICAL" if classification.watch_state == WatchState.ALERT_CRITICAL else "HIGH"
            check_id = (
                "NC-9-bpf-critical-program"
                if classification.watch_state == WatchState.ALERT_CRITICAL
                else "NC-9-bpf-high-risk-program"
            )
            if _severity_rank(prev_state) < _severity_rank(classification.watch_state.value):
                f = _escalation_finding(
                    entry,
                    classification.watch_state,
                    f"BPF program escalated: {prog.name}",
                    check_id,
                    sev,
                )
                if f:
                    findings.append(f)

    for key, entry in list(map_wl.items()):
        if entry.get("state") == WatchState.VANISHED.value:
            continue
        m = map_by_key.get(key)
        if not m:
            continue
        classification = classify_map(m, cfg, bl_map)
        prev_state = entry.get("state")
        findings.extend(_detect_map_deltas(entry, m))
        entry["metadata"] = m.to_dict()
        entry["current_id"] = m.id
        entry["risk_score"] = classification.risk_score
        entry["state"] = classification.watch_state.value

        if classification.watch_state in (WatchState.ALERT_HIGH, WatchState.ALERT_CRITICAL):
            if _severity_rank(prev_state) < _severity_rank(classification.watch_state.value):
                f = _escalation_finding(
                    entry,
                    classification.watch_state,
                    f"BPF map escalated: {m.name}",
                    "NC-9-bpf-high-risk-map",
                    "HIGH",
                )
                if f:
                    findings.append(f)

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
