"""--check mode: threat checks + anomalies, read-only state mutations for dedup."""

from __future__ import annotations

from secmon.alerts import dispatch
from secmon.anomaly import detect_anomalies
from secmon.checks import run_checks
from secmon.metrics import collect_metrics_from_state
from secmon.state import save_state


def run_check(state: dict, cfg: dict) -> int:
    metrics = collect_metrics_from_state(cfg, state)
    alerts = []
    alerts.extend(run_checks(state, cfg))
    alerts.extend(detect_anomalies(metrics, state, cfg))
    new = dispatch(alerts, state, cfg)
    save_state(cfg, state)
    return 0 if not new else 1
