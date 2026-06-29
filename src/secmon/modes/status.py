"""--status mode: read-only report."""

from __future__ import annotations

from secmon.metrics import collect_metrics_from_state
from secmon.output import format_status


def run_status(state: dict, cfg: dict) -> int:
    metrics = collect_metrics_from_state(cfg, state, force=False)
    print(format_status(state, cfg, metrics))
    return 0
