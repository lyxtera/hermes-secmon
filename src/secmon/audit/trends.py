"""Layer 8: Trend comparison."""

from __future__ import annotations

from secmon.audit.base import AuditFinding


def run(state: dict, cfg: dict, current_findings: list[AuditFinding]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    prev = state.get("last_audit_findings", [])
    prev_ids = {f.get("check_id") for f in prev}
    cur_ids = {f.check_id for f in current_findings}

    new_ids = cur_ids - prev_ids
    resolved = prev_ids - cur_ids
    persistent = cur_ids & prev_ids

    for f in current_findings:
        if f.check_id in new_ids:
            findings.append(
                AuditFinding("INFO", 8, "trend_new", f"NEW: [{f.severity}] {f.message}")
            )

    for pid in resolved:
        findings.append(AuditFinding("INFO", 8, "trend_resolved", f"RESOLVED: {pid}"))

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
