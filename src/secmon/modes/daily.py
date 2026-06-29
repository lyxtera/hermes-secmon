"""--daily mode: human-readable digest."""

from __future__ import annotations

from secmon.metrics import collect_metrics_from_state
from secmon.output import format_daily_digest
from secmon.utils import utcnow_iso


def run_daily(
    state: dict,
    cfg: dict,
    metrics: dict | None = None,
    *,
    silent: bool = False,
) -> int:
    if metrics is None:
        metrics = collect_metrics_from_state(cfg, state)
    report = format_daily_digest(state, metrics)
    if not silent:
        print(report)
    state.setdefault("monitor_state", {})["last_daily"] = utcnow_iso()
    return 0
