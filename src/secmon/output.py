"""Output formatters for status, daily digest, audit."""

from __future__ import annotations

import json
from typing import Any

from secmon.config import METRIC_KEYS
from secmon.utils import parse_iso, utcnow


def format_status(state: dict, cfg: dict, metrics: dict[str, int] | None = None) -> str:
    lines = ["=== Security Monitor Status ===", ""]
    lines.append(f"State version: {state.get('version')}")
    lines.append(f"Updated: {state.get('updated_at')}")
    lines.append(f"Daily samples: {len(state.get('daily_stats', []))}")
    ms = state.get("monitor_state", {})
    lines.append(f"Last record: {ms.get('last_record', 'never')}")
    lines.append(f"Last botnet check: {ms.get('last_botnet_check', 'never')}")
    lines.append(f"Last daily: {ms.get('last_daily', 'never')}")
    lines.append(f"Last anomaly check: {state.get('last_anomaly_check', 'never')}")
    lines.append("")
    lines.append("--- Baselines ---")
    baselines = state.get("baselines", {})
    if not baselines:
        lines.append("(no baselines calibrated yet)")
    for key in METRIC_KEYS:
        bl = baselines.get(key)
        if bl:
            lines.append(
                f"  {key}: mean={bl['mean']:.1f} stdev={bl['stdev']:.2f} "
                f"n={bl['sample_size']} [{bl['min']}-{bl['max']}]"
            )
        else:
            lines.append(f"  {key}: (insufficient samples)")
    if metrics:
        lines.append("")
        lines.append("--- Current Metrics ---")
        for key in METRIC_KEYS:
            lines.append(f"  {key}: {metrics.get(key, 0)}")
    lines.append("")
    lines.append(f"Botnet chain rules: {metrics.get('botnet_chain_rules', 0) if metrics else 'n/a'}")
    own = cfg.get("whitelist", {}).get("own_ip", "")
    lines.append(f"Own IP configured: {own or '(not set)'}")
    return "\n".join(lines)


def format_daily_digest(state: dict, metrics: dict[str, int], findings_count: int = 0) -> str:
    lines = ["=== Daily Security Digest ===", f"Date: {utcnow().strftime('%Y-%m-%d')} UTC", ""]
    lines.append("--- 24h Metrics ---")
    for key in METRIC_KEYS:
        lines.append(f"  {key}: {metrics.get(key, 0)}")
    baselines = state.get("baselines", {})
    lines.append("")
    lines.append("--- Baseline Comparison ---")
    for key in METRIC_KEYS:
        bl = baselines.get(key)
        cur = metrics.get(key, 0)
        if bl:
            delta = cur - bl["mean"]
            lines.append(f"  {key}: {cur} (baseline {bl['mean']:.0f}, Δ{delta:+.0f})")
        else:
            lines.append(f"  {key}: {cur} (no baseline)")
    recent = state.get("last_anomalies", [])[-5:]
    if recent:
        lines.append("")
        lines.append("--- Recent Anomalies ---")
        for a in recent:
            lines.append(f"  [{a.get('severity')}] {a.get('metric')} {a.get('direction')}")
    lines.append("")
    lines.append(f"Findings in last period: {findings_count}")
    return "\n".join(lines)


def format_audit_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True)
