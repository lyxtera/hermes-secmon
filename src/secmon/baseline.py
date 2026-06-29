"""Rolling baseline computation."""

from __future__ import annotations

import math
from typing import Any

from secmon.config import METRIC_KEYS
from secmon.state import make_daily_sample, trim_daily_stats
from secmon.utils import parse_iso, utcnow, utcnow_iso


def compute_baselines(daily_stats: list[dict], min_samples: int) -> dict[str, dict]:
    baselines: dict[str, dict] = {}
    for key in METRIC_KEYS:
        values = [int(e.get(key, 0)) for e in daily_stats if key in e]
        if len(values) < min_samples:
            continue
        n = len(values)
        mean = sum(values) / n
        if n == 1:
            stdev = 0.0
        else:
            sq = sum((v - mean) ** 2 for v in values)
            stdev = math.sqrt(sq / (n - 1))
        baselines[key] = {
            "mean": mean,
            "stdev": stdev,
            "min": min(values),
            "max": max(values),
            "sample_size": n,
            "calibrated_at": utcnow_iso(),
        }
    return baselines


def record_sample(state: dict, cfg: dict, metrics: dict[str, int]) -> bool:
    """Append baseline sample if dedup slot elapsed."""
    ms = state.setdefault("monitor_state", {})
    last = parse_iso(ms.get("last_record"))
    slot_hours = cfg["anomaly"]["dedup_slot_hours"]
    if last and (utcnow() - last).total_seconds() < slot_hours * 3600:
        return False
    sample = make_daily_sample(metrics)
    state.setdefault("daily_stats", []).append(sample)
    max_days = cfg["anomaly"]["max_baseline_days"]
    state["daily_stats"] = trim_daily_stats(state["daily_stats"], max_days)
    min_samples = cfg["anomaly"]["baseline_min_samples"]
    state["baselines"] = compute_baselines(state["daily_stats"], min_samples)
    ms["last_record"] = utcnow_iso()
    return True


def suggest_calibration(state: dict, cfg: dict) -> list[str]:
    """Auto-calibration suggestions after 14+ samples (never auto-apply)."""
    suggestions: list[str] = []
    daily = state.get("daily_stats", [])
    if len(daily) < 14:
        return suggestions
    from secmon.config import get_threshold

    for key in METRIC_KEYS:
        values = sorted(int(e.get(key, 0)) for e in daily)
        if len(values) < 14:
            continue
        p10_idx = max(0, len(values) // 10)
        p90_idx = min(len(values) - 1, len(values) * 9 // 10)
        p10, p90 = values[p10_idx], values[p90_idx]
        observed_range = p90 - p10
        if observed_range <= 0:
            continue
        th = get_threshold(cfg, key)
        min_delta = th.get("min_delta", 0)
        low = observed_range * 0.2
        high = observed_range * 0.5
        if min_delta < low or min_delta > high:
            suggestions.append(
                f"Metric {key}: min_delta={min_delta} outside 20-50% of observed range "
                f"({observed_range}); consider {int(low)}-{int(high)}"
            )
    return suggestions


def check_baseline_staleness(state: dict) -> bool:
    """Clear baselines if no daily_stats entry in 72h."""
    daily = state.get("daily_stats", [])
    if not daily:
        return False
    last_ts = parse_iso(daily[-1].get("timestamp"))
    if last_ts and (utcnow() - last_ts).total_seconds() > 72 * 3600:
        state["baselines"] = {}
        state["daily_stats"] = []
        return True
    return False
