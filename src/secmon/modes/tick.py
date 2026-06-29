"""--tick mode: primary cron entry."""

from __future__ import annotations

import logging

from secmon.alerts import dispatch
from secmon.anomaly import detect_anomalies
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
