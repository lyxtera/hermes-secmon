"""--tick mode: primary cron entry."""

from __future__ import annotations

import logging

from secmon.alerts import dispatch, findings_to_alerts
from secmon.anomaly import detect_anomalies
from secmon.audit import run_audit
from secmon.baseline import check_baseline_staleness, record_sample, suggest_calibration
from secmon.botnet import detect_and_block
from secmon.checks import run_checks
from secmon.metrics import collect_metrics_from_state
from secmon.modes.daily import run_daily
from secmon.state import save_state
from secmon.utils import parse_iso, utcnow

logger = logging.getLogger("secmon.tick")


def run_tick(state: dict, cfg: dict) -> int:
    logger.info("tick start")
    check_baseline_staleness(state)
    metrics = collect_metrics_from_state(cfg, state)
    alerts = []
    alerts.extend(run_checks(state, cfg))
    from secmon.bpf.watcher import run_bpf_watch

    alerts.extend(findings_to_alerts(run_bpf_watch(state, cfg), min_severity="HIGH"))
    alerts.extend(detect_anomalies(metrics, state, cfg))

    ms = state.setdefault("monitor_state", {})
    last_record = parse_iso(ms.get("last_record"))
    if not last_record or (utcnow() - last_record).total_seconds() >= 6 * 3600:
        if record_sample(state, cfg, metrics):
            for s in suggest_calibration(state, cfg):
                logger.info("calibration suggestion: %s", s)

    last_botnet = parse_iso(ms.get("last_botnet_check"))
    if not last_botnet or (utcnow() - last_botnet).total_seconds() >= 6 * 3600:
        alerts.extend(detect_and_block(state, cfg))

    # Deep audit every 6h — bridge CRITICAL/HIGH findings into alert pipeline
    last_audit = parse_iso(ms.get("last_audit_check"))
    if not last_audit or (utcnow() - last_audit).total_seconds() >= 6 * 3600:
        try:
            result = run_audit(state, cfg)
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
            alerts.extend(findings_to_alerts(findings, min_severity="HIGH"))
            state["last_audit_score"] = result.get("total_score", 0)
            state["last_audit_findings"] = result.get("findings", [])
            ms["last_audit_check"] = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception as exc:
            logger.error("scheduled audit failed: %s", exc)

    # Daily digest at 08:00 UTC
    now = utcnow()
    last_daily = parse_iso(ms.get("last_daily"))
    if now.hour >= 8 and (not last_daily or last_daily.date() < now.date()):
        run_daily(state, cfg, metrics, silent=True)
        save_state(cfg, state)

    new = dispatch(alerts, state, cfg)
    save_state(cfg, state)
    logger.info("tick end, %d new alerts", len(new))
    return 0 if not new else 1
