"""Two-gate statistical anomaly detection."""

from __future__ import annotations

import logging
from typing import Any

from secmon.alerts import Alert
from secmon.config import METRIC_KEYS, get_threshold
from secmon.utils import parse_iso, utcnow, utcnow_iso

logger = logging.getLogger("secmon.anomaly")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_from_deviation(deviation: float, sigma_threshold: float) -> str | None:
    if deviation <= 1.0 * sigma_threshold:
        return None
    if deviation > 2.0 * sigma_threshold:
        return "CRITICAL"
    if deviation > 1.5 * sigma_threshold:
        return "HIGH"
    return "MEDIUM"


def detect_anomalies(metrics: dict[str, int], state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    baselines = state.get("baselines", {})
    min_samples = cfg["anomaly"]["baseline_min_samples"]
    cooldown_min = cfg["anomaly"]["cooldown_minutes"]
    flagged = state.setdefault("last_flagged_anomalies", {})
    stale_counts = state.setdefault("monitor_state", {}).setdefault("stale_anomaly_counts", {})
    last_anomalies = state.setdefault("last_anomalies", [])

    for key in METRIC_KEYS:
        bl = baselines.get(key)
        if not bl or bl.get("sample_size", 0) < min_samples:
            continue
        current = int(metrics.get(key, 0))
        mean = float(bl["mean"])
        stdev = float(bl.get("stdev", 0))
        th = get_threshold(cfg, key)
        min_delta = int(th.get("min_delta", 0))
        direction = "above" if current > mean else "below"
        if current == mean:
            stale_counts.pop(key, None)
            continue
        abs_delta = abs(current - mean)
        # Gate 2
        if abs_delta < min_delta:
            continue
        sigma_above = th.get("sigma_above")
        sigma_below = th.get("sigma_below")
        sigma_th = sigma_above if direction == "above" else sigma_below
        if sigma_th is None and direction == "below":
            continue
        sigma_th = float(sigma_th or sigma_above or 3.0)
        # Gate 1
        if stdev == 0:
            gate1 = abs_delta >= min_delta
            deviation = abs_delta / max(min_delta, 1)
        else:
            deviation = abs_delta / stdev
            gate1 = deviation > sigma_th
        if not gate1:
            continue
        dedup_key = f"anomaly:{key}+{direction}"
        # Stale baseline rule
        prev = stale_counts.get(key, {"count": 0, "value": current})
        if prev.get("value") and abs(current - prev["value"]) / max(prev["value"], 1) <= 0.1:
            prev["count"] = prev.get("count", 0) + 1
        else:
            prev = {"count": 1, "value": current}
        stale_counts[key] = prev
        if prev["count"] >= 3:
            logger.warning(
                "stale baseline for %s (value ~%s); consider recalibration", key, current
            )
            continue
        # Cooldown
        last = flagged.get(dedup_key)
        if last:
            lt = parse_iso(last.get("time"))
            if lt and (utcnow() - lt).total_seconds() < cooldown_min * 60:
                if last.get("value") == current:
                    continue
        sev = _severity_from_deviation(deviation, sigma_th) or "MEDIUM"
        msg = f"Anomaly {key}: {current} vs baseline mean {mean:.1f} ({direction}, {deviation:.1f}σ)"
        alerts.append(
            Alert(
                severity=sev,
                source="anomaly",
                message=msg,
                dedup_key=dedup_key,
                structured={
                    "metric": key,
                    "direction": direction,
                    "current_value": current,
                    "mean": mean,
                    "stdev": stdev,
                    "sigma": deviation,
                },
            )
        )
        flagged[dedup_key] = {"time": utcnow_iso(), "value": current}
        last_anomalies.append(
            {
                "metric": key,
                "direction": direction,
                "severity": sev,
                "timestamp": utcnow_iso(),
                "current_value": current,
                "mean": mean,
                "stdev": stdev,
                "sigma": deviation,
            }
        )
        if len(last_anomalies) > 100:
            state["last_anomalies"] = last_anomalies[-100:]

    state["last_anomaly_check"] = utcnow_iso()
    return alerts
