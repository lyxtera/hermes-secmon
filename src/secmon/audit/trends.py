"""Layer 8: Trend comparison."""

from __future__ import annotations

from secmon.audit.base import AuditFinding


def run(state: dict, cfg: dict, current_findings: list[AuditFinding]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    prev = state.get("last_audit_findings", [])
    # Exclude internal Trend-layer meta checks so they don't pollute resolved/persistent
    _INTERNAL_TREND_CHECKS = {"layer_count", "trend_new", "trend_resolved", "trend_persistent", "risk_increase"}
    prev_ids = {f.get("check_id") for f in prev if f.get("check_id") not in _INTERNAL_TREND_CHECKS}
    cur_ids = {f.check_id for f in current_findings if f.check_id not in _INTERNAL_TREND_CHECKS}

    new_ids = cur_ids - prev_ids
    resolved = prev_ids - cur_ids
    persistent = cur_ids & prev_ids

    for f in current_findings:
        if f.check_id in new_ids:
            findings.append(
                AuditFinding("INFO", 8, "trend_new", f"NEW: [{f.severity}] {f.message}")
            )

    # Build lookup from prev for enriched resolved messages
    prev_by_id: dict[str, dict] = {}
    for f in prev:
        cid = f.get("check_id")
        if cid and cid not in _INTERNAL_TREND_CHECKS:
            prev_by_id[cid] = f

    for pid in resolved:
        prev_finding = prev_by_id.get(pid, {})
        original = f" [{prev_finding.get('severity', '?')}] {prev_finding.get('message', pid)}" if prev_finding else f" [{pid}]"
        findings.append(AuditFinding("INFO", 8, "trend_resolved", f"RESOLVED{original}"))

    if persistent:
        findings.append(
            AuditFinding(
                "INFO", 8, "trend_persistent",
                f"{len(persistent)} persistent finding(s) from previous audit",
            )
        )

    current_score = sum(f.score for f in current_findings)
    prev_score = state.get("last_audit_score", 0)
    if prev_score and current_score > prev_score * 1.5:
        findings.append(
            AuditFinding(
                "HIGH", 8, "risk_increase",
                f"Risk score increased {prev_score} → {current_score}",
            )
        )

    # Category breakdown
    by_layer: dict[int, int] = {}
    for f in current_findings:
        by_layer[f.layer] = by_layer.get(f.layer, 0) + 1
    for layer, count in sorted(by_layer.items()):
        findings.append(
            AuditFinding("INFO", 8, "layer_count", f"Layer {layer}: {count} finding(s)")
        )

    state["last_audit_findings"] = [
        {"check_id": f.check_id, "severity": f.severity, "message": f.message}
        for f in current_findings
    ]
    state["last_audit_score"] = current_score
    return findings
