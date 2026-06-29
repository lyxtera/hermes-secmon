"""--record mode: collect metrics and append baseline."""

from __future__ import annotations

from secmon.baseline import record_sample
from secmon.metrics import collect_metrics, invalidate_cache
from secmon.state import save_state
from secmon.utils import utcnow_iso


def run_record(state: dict, cfg: dict) -> int:
    invalidate_cache()
    metrics = collect_metrics(cfg, force=True)
    state["metric_cache"] = {
        "timestamp": utcnow_iso(),
        "values": metrics,
    }
    record_sample(state, cfg, metrics)
    save_state(cfg, state)
    return 0
