"""--audit mode: full multi-layer JSON audit."""

from __future__ import annotations

from secmon.alerts import dispatch, findings_to_alerts
from secmon.audit import run_audit
from secmon.output import format_audit_markdown
from secmon.remediate import remediate
from secmon.state import save_state


def run_audit_mode(state: dict, cfg: dict) -> int:
    result = run_audit(state, cfg)
    findings = result.get("findings", [])

    # Auto-remediate safe findings before formatting output
    remediated = remediate(findings, cfg)
    result["findings"] = remediated
    result["auto_resolved_count"] = sum(
        1 for f in remediated if f.get("auto_resolved")
    )

    state["last_audit_score"] = result.get("total_score", 0)
    state["last_audit_findings"] = result.get("findings", [])

    # Reconstruct AuditFinding-like objects for bridge
    from secmon.audit.base import AuditFinding

    findings = [
        AuditFinding(
            f["severity"],
            f["layer"],
            f["check_id"],
            f["message"],
            f.get("detail", {}),
        )
        for f in result.get("findings", [])
    ]
    alerts = findings_to_alerts(findings, min_severity="HIGH")
    dispatch(alerts, state, cfg, stdout=False)

    print(format_audit_markdown(result))
    save_state(cfg, state)
    return 1 if result.get("critical_count", 0) > 0 else 0
