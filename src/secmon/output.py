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
    lines: list[str] = []
    baselines = state.get("baselines", {})

    # Human-friendly metric labels
    METRIC_LABELS = {
        "ssh_failed_24h": "SSH Failures",
        "ssh_invalid_user_24h": "Invalid SSH Users",
        "unique_attacker_ips": "Unique Attacker IPs",
        "unique_attacker_subnets": "Unique Attacker /24s",
        "f2b_banned_count": "Fail2ban Bans",
        "botnet_chain_rules": "Botnet Chain Rules",
        "martian_packets_24h": "Martian Packets",
        "new_blocked_subnets_24h": "New Blocked Subnets",
        "kernel_errors_24h": "Kernel Errors",
        "listening_ports_count": "Listening Ports",
        "established_conns": "Established Conns",
    }

    # --- 24h Metrics table ---
    lines.append("### 📊 24h Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    for key in METRIC_KEYS:
        val = metrics.get(key, 0)
        label = METRIC_LABELS.get(key, key.replace("_", " ").title())
        lines.append(f"| {label} | {val:,} |")
    lines.append("")

    # --- Baseline Comparison table ---
    lines.append("### 📈 Baseline Comparison")
    lines.append("")
    has_baseline = any(baselines.get(k) for k in METRIC_KEYS)
    if has_baseline:
        lines.append("| Metric | Today | Baseline | Δ |")
        lines.append("|--------|------:|---------:|---:|")
        for key in METRIC_KEYS:
            bl = baselines.get(key)
            cur = metrics.get(key, 0)
            label = METRIC_LABELS.get(key, key.replace("_", " ").title())
            if bl:
                mean = bl["mean"]
                delta = cur - mean
                delta_str = f"{delta:+d}"
                # Color hint via emoji for large deltas
                if delta > bl.get("stdev", 0) * 2:
                    delta_str = f"⚠️ {delta:+d}"
                elif delta < -bl.get("stdev", 0) * 2:
                    delta_str = f"✅ {delta:+d}"
                lines.append(f"| {label} | {cur:,} | {mean:.0f} | {delta_str} |")
            else:
                lines.append(f"| {label} | {cur:,} | — | — |")
    else:
        lines.append("*No baselines calibrated yet — keep recording samples.*")
    lines.append("")

    # --- Summary row ---
    total_new = sum(metrics.get(k, 0) for k in
                    ["ssh_failed_24h", "ssh_invalid_user_24h", "f2b_banned_count"])
    lines.append("### 🔍 Summary")
    lines.append("")
    lines.append(f"- **SSH failures:** {metrics.get('ssh_failed_24h', 0):,}")
    lines.append(f"- **Invalid users:** {metrics.get('ssh_invalid_user_24h', 0):,}")
    lines.append(f"- **Fail2ban bans:** {metrics.get('f2b_banned_count', 0):,}")
    lines.append(f"- **Unique attackers:** {metrics.get('unique_attacker_ips', 0):,} IPs / {metrics.get('unique_attacker_subnets', 0):,} subnets")
    lines.append(f"- **Listening ports:** {metrics.get('listening_ports_count', 0)}")
    lines.append(f"- **Established conns:** {metrics.get('established_conns', 0)}")
    lines.append(f"- **Findings:** {findings_count}")
    lines.append("")

    # --- Anomalies ---
    recent = state.get("last_anomalies", [])[-5:]
    if recent:
        lines.append("### 🚨 Recent Anomalies")
        lines.append("")
        for a in recent:
            sev = a.get("severity", "INFO")
            metric = a.get("metric", "?")
            direction = a.get("direction", "?")
            emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "ℹ️"
            lines.append(f"- {emoji} **{sev}**: {metric} {direction}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("▶ `secmon --audit` — Full forensic audit")
    return "\n".join(lines)


def format_audit_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True)
