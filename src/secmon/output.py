"""Output formatters for status, daily digest, audit."""

from __future__ import annotations

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


LAYER_NAMES: dict[int, str] = {
    1: "📁 File Integrity",
    2: "🌐 Network",
    3: "⚙️ Process",
    4: "🔑 Auth",
    5: "📝 Logs",
    6: "🛡️ Threat Intel",
    7: "📋 Compliance",
    8: "📈 Trends",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️",
}

CHECK_ID_EMOJI = {
    "proc_hollow_anon": "🕳️",
    "proc_hollow_deleted": "🕳️",
    "proc_hollow_rwx": "🕳️",
    "proc_spoof": "🎭",
    "hidden_proc": "👻",
    "proc_lineage_web_shell": "🕸️",
    "proc_lineage_inject": "💉",
    "proc_root_tmp": "📂",
    "proc_root_deleted": "🗑️",
    "bad_module": "🧩",
    "kernel_tainted": "⚠️",
    "kernel_sysctl_change": "⚙️",
    "kernel_modules_enabled": "🧩",
    "file_changed": "📝",
    "file_removed": "❌",
    "world_writable": "🌍",
    "ld_preload": "🧨",
    "hidden_tmp": "👻",
    "unexpected_suid": "🔑",
    "new_listen_port": "🚪",
    "port_changed": "🔄",
    "port_removed": "🚫",
    "fw_policy": "🧱",
    "fw_chain": "🧱",
    "webshell": "🐚",
    "secret_world_readable": "🔓",
    "secret_key_tmp": "🔑",
    "secret_pattern": "🔎",
    "secret_authkeys_perm": "🔓",
    "persist_new": "🆕",
    "persist_modified": "✏️",
    "persist_removed": "🗑️",
    "cron_suspicious": "⏰",
    "modified_bin": "💾",
    "tmp_executable": "📂",
    "sysctl": "⚙️",
    "sec_updates": "📦",
    "unattended": "🤖",
    "pass_aging": "👴",
    "sshd_config": "🔐",
    "nopasswd": "🛂",
    "systemd_failed": "💥",
    "log_stale": "⏳",
    "log_truncated": "✂️",
    "risk_increase": "📈",
    "NC-1-privileged": "🐳",
    "NC-1-sock": "🐳",
    "NC-1-hostmount": "🐳",
    "NC-2-promisc": "👂",
    "NC-2-tun": "🔌",
    "NC-2-arp": "📡",
    "NC-3-dns": "🌐",
    "NC-3-ndots": "🌐",
    "NC-3-nsswitch": "🌐",
    "NC-3-hosts": "🌐",
    "NC-4-expired": "📜",
    "NC-4-expiring": "📜",
    "NC-4-soon": "📜",
    "NC-5-uid0": "👤",
    "NC-5-newuser": "👤",
    "NC-5-emptypw": "🔓",
    "NC-5-privgroup": "👥",
    "NC-5-authkeys": "🔑",
    "NC-6-tmpfs": "💿",
    "NC-6-bind": "🔗",
    "NC-6-fakeproc": "🎭",
    "NC-6-noexec": "🚫",
    "NC-7-newtimer": "⏲️",
    "NC-7-newsvc": "⚙️",
    "NC-7-execstart": "⚠️",
    "NC-7-masked": "🙈",
    "NC-8-ntp": "🕐",
    "NC-8-drift": "🕐",
    "NC-9-nobpf": "🐝",
    "NC-9-nobpftool": "🐝",
    "NC-9-unpriv": "🐝",
    "NC-9-newprog": "🐝",
    "NC-9-newmap": "🐝",
    "NC-10-nodebsums": "📦",
    "NC-10-critical": "📦",
    "NC-10-modified": "📦",
    "NC-10-apt": "📦",
    "NC-11-storage": "💾",
    "NC-11-verify": "💾",
    "NC-11-gap": "⏳",
    "auditd": "🔍",
    "invalid_users": "👤",
    "ssh_stats": "🔐",
    "trend_new": "🆕",
    "trend_resolved": "✅",
    "trend_persistent": "🔄",
}


def _format_details(detail: dict[str, Any]) -> str:
    """Pretty-print detail fields as bullet points, no JSON."""
    if not detail:
        return ""
    lines: list[str] = []
    for key, val in detail.items():
        if key in ("pid", "parent_pid", "child_pid"):
            label = {"pid": "PID", "parent_pid": "Parent PID", "child_pid": "Child PID"}.get(
                key, "PID"
            )
            lines.append(f"     • {label}: `{val}`")
        elif key == "path":
            lines.append(f"     • Path: `{val}`")
        elif key == "exe":
            lines.append(f"     • Binary: `{val}`")
        elif key == "mode":
            lines.append(f"     • Permissions: `{val}`")
        elif key == "content":
            lines.append(f"     • Content: `{val[:120]}`")
        elif key == "expected":
            lines.append(f"     • Expected: `{val}`")
        else:
            lines.append(f"     • {key}: `{val}`")
    return "\n".join(lines)


def format_audit_markdown(result: dict[str, Any]) -> str:
    """Render audit result as readable markdown — no raw JSON."""
    lines: list[str] = []

    score = result.get("total_score", 0)
    total = result.get("finding_count", 0)
    crit = result.get("critical_count", 0)
    high = result.get("high_count", 0)
    med = sum(
        1 for f in result.get("findings", []) if f["severity"] == "MEDIUM"
    )
    low = sum(
        1 for f in result.get("findings", []) if f["severity"] in ("LOW", "INFO")
    )

    lines.append("### 📊 Audit Overview")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|------:|")
    lines.append(f"| 🔴 **CRITICAL** | {crit} |")
    lines.append(f"| 🟠 **HIGH** | {high} |")
    lines.append(f"| 🟡 **MEDIUM** | {med} |")
    lines.append(f"| 🔵 **LOW / INFO** | {low} |")
    lines.append(f"| **Total Score** | {score} |")
    lines.append("")
    lines.append(f"**Total findings: {total}**")
    lines.append("")

    findings = result.get("findings", [])
    if not findings:
        lines.append("✅ **No findings — system is clean.**")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("▶ `secmon --audit`")
        return "\n".join(lines)

    # Group by severity in order
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f["severity"] == severity]
        if not group:
            continue
        emoji = SEVERITY_EMOJI.get(severity, "•")
        lines.append(f"---")
        lines.append("")
        lines.append(f"### {emoji} {severity}")
        lines.append("")

        for idx, f in enumerate(group, 1):
            check_id = f.get("check_id", "")
            msg = f.get("message", "")
            layer = f.get("layer", 0)
            detail = f.get("detail", {}) or {}

            cid_emoji = CHECK_ID_EMOJI.get(check_id, "•")
            layer_name = LAYER_NAMES.get(layer, f"L{layer}")

            lines.append(f"**{idx}. {cid_emoji} {msg}**")
            lines.append(f"")
            lines.append(f"     • Layer: {layer_name}")
            lines.append(f"     • Check: `{check_id}`")
            detail_str = _format_details(detail)
            if detail_str:
                lines.append(detail_str)
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("▶ `secmon --audit` — Run full forensic audit")
    return "\n".join(lines)
