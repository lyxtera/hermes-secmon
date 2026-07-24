"""Output formatters for status, daily digest, audit."""

from __future__ import annotations

from typing import Any

from secmon.config import METRIC_KEYS
from secmon.utils import parse_iso, utcnow


METRIC_LABELS: dict[str, str] = {
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

METRIC_IMPACT: dict[str, str] = {
    "ssh_failed_24h": "Failed SSH logins often indicate brute-force or credential stuffing attempts",
    "ssh_invalid_user_24h": "Logins for non-existent users suggest recon and username guessing",
    "unique_attacker_ips": "Distinct sources targeting SSH indicate breadth of attack activity",
    "unique_attacker_subnets": "Attacker /24s suggest distributed scan waves",
    "f2b_banned_count": "Fail2ban bans reflect active defense response to abuse",
    "botnet_chain_rules": "BOTNET firewall rules represent blocked hostile subnets",
    "martian_packets_24h": "Impossible-source packets can reflect routing misconfig or spoofing",
    "new_blocked_subnets_24h": "New blocklist entries suggest emerging attack waves",
    "kernel_errors_24h": "Kernel errors may indicate hardware, driver, or stability issues",
    "listening_ports_count": "Open listening sockets may reveal unexpected services or backdoors",
    "established_conns": "Active sessions can show baseline drift that may indicate C2 or load changes",
}

METRIC_GUIDANCE: dict[str, str] = {
    "ssh_failed_24h": "Review recent failed SSH login attempts and identify the most active source IPs",
    "ssh_invalid_user_24h": "Review invalid-user SSH attempts to confirm whether enumeration is underway",
    "unique_attacker_ips": "Identify which IPs are driving the highest volume of SSH failures and assess whether they are likely coordinated",
    "unique_attacker_subnets": "Determine whether activity spans multiple /24 networks and consider tightening network controls",
    "f2b_banned_count": "Confirm fail2ban is actively banning abusive IPs and check whether bans are escalating",
    "botnet_chain_rules": "Inspect the BOTNET firewall chain and verify that newly detected hostile subnets are blocked",
    "martian_packets_24h": "Review kernel messages for martian packets and assess whether spoofing or routing anomalies occurred",
    "new_blocked_subnets_24h": "Inspect the botnet block log to understand which subnets were added and whether they look legitimate",
    "kernel_errors_24h": "Review recent kernel error messages and correlate them with other observed anomalies",
    "listening_ports_count": "List listening services and verify that any new ports are authorized and expected",
    "established_conns": "Review established connections and map them to processes to identify unusual peers",
}


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
    """Render daily digest as compact Telegram format."""
    lines: list[str] = []
    baselines = state.get("baselines", {})

    elevated_ctas: list[str] = []

    lines.append("**📅 Daily Security Digest**")
    lines.append("")
    lines.append("**📊 24h Activity**")
    lines.append("")
    lines.append("| Metric | Value | Baseline | Δ |")
    lines.append("| :---: | :---: | :---: | :---: |")

    for key in METRIC_KEYS:
        val = metrics.get(key, 0)
        label = METRIC_LABELS.get(key, key.replace("_", " ").title())
        impact = METRIC_IMPACT.get(key, "")
        bl = baselines.get(key)

        if bl:
            mean = bl["mean"]
            delta = val - mean
            stdev = bl.get("stdev", 0)
            if delta > stdev * 2:
                delta_str = f"⚠️ {int(delta):+d}"
                if key in METRIC_GUIDANCE:
                    elevated_ctas.append(f"**{label}** is elevated — {METRIC_GUIDANCE[key]}")
            elif delta < -stdev * 2:
                delta_str = f"✅ {int(delta):+d}"
            else:
                delta_str = f"{int(delta):+d}"
            val_str = f"`{val:,}`"
            bl_str = f"`{mean:.0f}`"
            lines.append(f"| **{label}** | {val_str} | {bl_str} | {delta_str} |")
        else:
            lines.append(f"| **{label}** | `{val:,}` | — | — |")

        lines.append("")

    lines.append("**🔍 Summary**")
    lines.append("")
    lines.append(f"• SSH failures: `{metrics.get('ssh_failed_24h', 0):,}`")
    lines.append(f"• Invalid users: `{metrics.get('ssh_invalid_user_24h', 0):,}`")
    lines.append(f"• Fail2ban bans: `{metrics.get('f2b_banned_count', 0):,}`")
    lines.append(
        f"• Unique attackers: `{metrics.get('unique_attacker_ips', 0):,}` IPs / "
        f"`{metrics.get('unique_attacker_subnets', 0):,}` subnets"
    )
    lines.append(f"• Listening ports: `{metrics.get('listening_ports_count', 0)}`")
    lines.append(f"• Established conns: `{metrics.get('established_conns', 0)}`")
    lines.append(f"• Findings: `{findings_count}`")
    lines.append("")

    recent = state.get("last_anomalies", [])[-5:]
    if recent:
        lines.append("**🚨 Recent Anomalies**")
        lines.append("")
        for a in recent:
            sev = a.get("severity", "INFO")
            metric = a.get("metric", "?")
            direction = a.get("direction", "?")
            emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "ℹ️"
            lines.append(f"• {emoji} **{sev}**: {metric} {direction}")
        lines.append("")

    if elevated_ctas:
        lines.append("**▶ What to check**")
        lines.append("")
        for cta in elevated_ctas[:5]:
            lines.append(f"• ℹ️ {cta}")
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

CHECK_ID_EXPLANATIONS: dict[str, str] = {
    "proc_hollow_anon": "Process with anonymous executable memory — potential code injection",
    "proc_hollow_deleted": "Process running from a deleted binary — classic memory-resident malware",
    "proc_hollow_rwx": "Process with read-write-execute memory pages — shellcode risk",
    "proc_spoof": "Process name doesn't match its binary — masquerading attempt",
    "hidden_proc": "Process hidden from `/proc` — rootkit behavior",
    "proc_lineage_web_shell": "Process spawned by a web server (e.g. PHP/Ruby) — potential webshell execution",
    "proc_lineage_inject": "Process spawned from an unexpected parent — injection indicator",
    "proc_root_tmp": "Root-owned process running from `/tmp` — unusual, often malware staging",
    "proc_root_deleted": "Root process with deleted binary on disk — memory-only execution",
    "bad_module": "Kernel module loaded from unexpected path — unauthorized driver",
    "kernel_tainted": "Kernel is tainted — proprietary or unsigned module loaded",
    "kernel_sysctl_change": "System configuration (sysctl) changed since baseline",
    "kernel_modules_enabled": "Kernel modules can still be loaded — disable if not needed",
    "file_changed": "Monitored file content changed since baseline",
    "file_removed": "Monitored file was deleted since baseline",
    "world_writable": "World-writable file or directory — allows any user to modify",
    "ld_preload": "LD_PRELOAD hook active — library injection vector",
    "hidden_tmp": "Hidden file in `/tmp` — often malware staging data",
    "unexpected_suid": "SUID binary not in baseline — privilege escalation risk",
    "new_listen_port": "New listening port detected — possibly a backdoor or new service",
    "port_changed": "Existing port's owning process changed — service hijack indicator",
    "port_removed": "Previously seen listening port disappeared",
    "fw_policy": "Firewall policy deficiency — inbound rules too permissive",
    "fw_chain": "Firewall chain deficiency — missing or misconfigured rules",
    "webshell": "File content matches webshell signature — remote access tool",
    "secret_world_readable": "Sensitive file readable by all users — credential exposure",
    "secret_key_tmp": "Private key or credential in `/tmp` — data leakage",
    "secret_pattern": "File containing credential-like pattern — possible exposed secret",
    "secret_authkeys_perm": "SSH authorized_keys file has unsafe permissions",
    "persist_new": "New persistence mechanism detected — autorun, cron, systemd unit",
    "persist_modified": "Existing persistence entry modified — potential hijack",
    "persist_removed": "Persistence entry removed — unusual if not intentional",
    "cron_suspicious": "Cron job runs from writable or suspicious path",
    "modified_bin": "System binary hash differs from baseline — possible tampering",
    "tmp_executable": "Executable file in world-writable `/tmp` — malware staging",
    "sysctl": "Kernel parameter setting poses security risk",
    "sec_updates": "Pending security updates — known CVEs unpatched",
    "unattended": "Unattended upgrades not running — missing auto-patching",
    "pass_aging": "Password aging policy is weak or missing",
    "sshd_config": "SSH configuration deviates from security baseline",
    "nopasswd": "User account has no password — unauthorized access risk",
    "systemd_failed": "Systemd unit in failed state — service may be down",
    "log_stale": "Log file unchanged beyond expected window — possible log tampering",
    "log_truncated": "Log file truncated or rotated — evidence gap",
    "risk_increase": "Total risk score increased significantly since last audit",
    "NC-1-privileged": "Container running privileged — full host access",
    "NC-1-sock": "Docker socket mounted in container — escape vector",
    "NC-1-hostmount": "Host filesystem mounted in container — data exposure",
    "NC-2-promisc": "Interface in promiscuous mode — packet sniffing",
    "NC-2-tun": "TUN/TAP interface active — virtual network device",
    "NC-2-arp": "ARP table anomaly — possible spoofing or scan",
    "NC-3-dns": "DNS resolver misconfiguration — potential hijack",
    "NC-3-ndots": "DNS ndots setting unusual — resolution delay or leak",
    "NC-3-nsswitch": "Name service switch order risky — credential harvesting vector",
    "NC-3-hosts": "`/etc/hosts` entry changed — potential redirection",
    "NC-4-expired": "TLS/SSL certificate expired — service may fail",
    "NC-4-expiring": "TLS/SSL certificate expiring soon",
    "NC-4-soon": "Certificates expiring within risk window",
    "NC-5-uid0": "User with UID 0 (root) — administrative access",
    "NC-5-newuser": "New user account created since baseline",
    "NC-5-emptypw": "User with empty password — authentication bypass",
    "NC-5-privgroup": "User in privileged group — elevated permissions",
    "NC-5-authkeys": "SSH authorized_keys entry changed — access review needed",
    "NC-6-tmpfs": "Tmpfs mount present — volatile in-memory filesystem",
    "NC-6-bind": "Bind mount detected — filesystem redirection",
    "NC-6-fakeproc": "Fake `/proc` mount — process hiding technique",
    "NC-6-noexec": "Filesystem mounted without noexec — allows code execution",
    "NC-7-newtimer": "New systemd timer — scheduled task added",
    "NC-7-newsvc": "New systemd service — background service added",
    "NC-7-execstart": "Systemd unit ExecStart uses writable script — injection vector",
    "NC-7-masked": "Systemd unit masked — administrator intent to disable",
    "NC-8-ntp": "NTP synchronization issue — time accuracy problem",
    "NC-8-drift": "System clock drifted beyond tolerance — timing anomaly",
    "NC-9-nobpf": "BPF (eBPF) not available — reduced monitoring capability",
    "NC-9-nobpftool": "BPF tooling not installed — can't inspect eBPF programs",
    "NC-9-unpriv": "Unprivileged BPF enabled — potential kernel exploit vector",
    "NC-9-newprog": "New BPF program loaded since baseline",
    "NC-9-newmap": "New BPF map created since baseline",
    "NC-9-bpf-surveillance-started": "Unknown BPF object entered surveillance watchlist",
    "NC-9-bpf-high-risk-program": "High-risk BPF program detected",
    "NC-9-bpf-critical-program": "Critical-risk BPF program detected",
    "NC-9-bpf-high-risk-map": "High-risk BPF map detected",
    "NC-9-bpf-map-mutated": "BPF map metadata changed during surveillance",
    "NC-9-bpf-link-updated": "BPF link attached during surveillance",
    "NC-9-bpf-pinned-persistence": "BPF object pinned to filesystem",
    "NC-9-bpf-loader-suspicious": "Suspicious BPF loader process detected",
    "NC-9-bpf-monitoring-gap": "BPF auditd monitoring gap — events may be lost",
    "NC-9-bpf-baseline-promoted": "BPF object manually promoted to baseline",
    "NC-10-nodebsums": "Debsums data unavailable — can't verify package integrity",
    "NC-10-critical": "Critical package(s) with integrity check failure",
    "NC-10-modified": "Modified debian package file — possible tampering",
    "NC-10-apt": "APT state anomaly — package database inconsistency",
    "NC-11-storage": "Storage audit issue — check disk integrity",
    "NC-11-verify": "Storage verification anomaly — possible data corruption",
    "NC-11-gap": "Storage audit gap — missing records in expected sequence",
    "auditd": "Audit daemon issue — logging subsystem concern",
    "invalid_users": "SSH login attempts using non-existent usernames — recon activity",
    "ssh_stats": "SSH connection statistics deviation from baseline",
    "trend_new": "New finding appeared since last audit cycle",
    "trend_resolved": "Previously reported finding no longer present — cleared",
    "trend_persistent": "Finding persists across multiple audit cycles — unresolved",
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
    "NC-9-bpf-surveillance-started": "🐝",
    "NC-9-bpf-high-risk-program": "🐝",
    "NC-9-bpf-critical-program": "🐝",
    "NC-9-bpf-high-risk-map": "🐝",
    "NC-9-bpf-map-mutated": "🐝",
    "NC-9-bpf-link-updated": "🐝",
    "NC-9-bpf-pinned-persistence": "🐝",
    "NC-9-bpf-loader-suspicious": "🐝",
    "NC-9-bpf-monitoring-gap": "🐝",
    "NC-9-bpf-baseline-promoted": "🐝",
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

FINDING_DIVIDER = "· · ·"


CHECK_ID_GUIDANCE: dict[str, str] = {
    # Process memory / hiding
    "proc_hollow_anon": "Inspect the memory map of process {pid} for anonymous executable segments",
    "proc_hollow_deleted": "Verify whether process {pid} is running from a deleted binary and collect its command line",
    "proc_hollow_rwx": "Check whether process {pid} has RWX memory pages that indicate potential shellcode",
    "proc_spoof": "Compare the process name for {pid} with the actual binary path to detect masquerading",
    "hidden_proc": "List processes and confirm whether process {pid} is hidden or missing from standard views",
    "proc_lineage_web_shell": "Review the parent-child process chain of {pid} to identify webserver-origin execution",
    "proc_lineage_inject": "Validate the parent process chain of {pid} to look for unexpected spawning (injection indicator)",
    "proc_root_tmp": "Investigate the suspicious file {path} executed with root privileges and tie it to process {pid}",
    "proc_root_deleted": "Confirm whether process {pid} is executing from a binary that no longer exists on disk",

    # Kernel / system integrity
    "bad_module": "Inspect loaded kernel modules and validate whether module {module} is present and unexpected",
    "kernel_tainted": "Check whether the kernel is tainted (unexpected or unsigned modules) and note details",
    "kernel_sysctl_change": "Compare current sysctl settings against the last baseline and identify what changed",
    "kernel_modules_enabled": "Verify whether kernel module loading is still allowed and whether it matches the baseline policy",

    # File integrity / secrets / permissions
    "file_changed": "Verify file {path} integrity and confirm whether it matches the baseline hash/metadata",
    "file_removed": "Confirm removal of expected file {path} and determine what replaced or re-created it",
    "world_writable": "Identify who can write to {path} and whether permissions are excessive for the risk model",
    "ld_preload": "Check for active LD_PRELOAD configuration that could be used for library injection",
    "hidden_tmp": "Examine suspicious temporary file {path} and determine its origin and purpose",
    "unexpected_suid": "Enumerate unexpected SUID binaries and assess whether they represent privilege-escalation risk",

    # Network exposure
    "new_listen_port": "Identify which process is listening on port {port} and verify it is expected",
    "port_changed": "Determine what changed for port {port} (process/ownership) and assess for service hijack",
    "port_removed": "Review the service landscape to understand why a previously seen port is no longer listening",
    "fw_policy": "Review firewall default policy and confirm inbound rules are not overly permissive",
    "fw_chain": "Review firewall chains and verify that expected drop/reject rules still exist",

    # Content / data
    "webshell": "Open {path} and determine whether it matches webshell signatures or suspicious execution patterns",
    "secret_world_readable": "Check {path} permissions and determine whether sensitive data is exposed to non-owners",
    "secret_key_tmp": "Inspect the contents and access pattern of {path} to assess credential/key leakage risk",
    "secret_pattern": "Search within {path} for credential-like patterns and capture what matched",
    "secret_authkeys_perm": "Validate permissions on SSH authorized_keys file {path} and determine if access should be restricted",

    # Persistence
    "persist_new": "Identify new persistence mechanisms that appeared since baseline (services/timers/etc.)",
    "persist_modified": "Inspect persistence entry {unit} and determine how it differs from baseline and why",
    "persist_removed": "Confirm whether persistence entry {unit} was removed intentionally and whether that affects stability",
    "cron_suspicious": "Review cron configuration and identify any entries pointing to writable or suspicious locations",

    # System updates / auth policy
    "modified_bin": "Verify whether system binaries differ from expected package-provided versions",
    "tmp_executable": "Identify executable files in world-writable {path} and assess malware staging risk",
    "sysctl": "Review sysctl key {key} and confirm it does not weaken the security baseline",
    "sec_updates": "Check whether security updates are pending and prioritize patching high-severity items",
    "unattended": "Verify whether unattended upgrades are enabled and functioning for routine patching",
    "pass_aging": "Review password aging policy and determine whether it meets your security requirements",
    "sshd_config": "Review sshd effective configuration and confirm safe authentication and login policy",
    "nopasswd": "Find accounts with empty passwords and assess whether they represent an immediate compromise risk",

    # Monitoring / evidence quality
    "systemd_failed": "Inspect failed systemd units and decide whether failures impact security visibility",
    "log_stale": "Check log {path} freshness and determine whether logging stopped unexpectedly",
    "log_truncated": "Investigate possible log truncation of {path} and ensure you preserve evidence",
    "risk_increase": "Run a full forensic audit to understand why the risk score increased",

    # Container hardening / namespace breakouts
    "NC-1-privileged": "Review containers running with elevated privileges and determine which workloads are exposed",
    "NC-1-sock": "Inspect container {container} for access to sensitive sockets and mounts that enable escape",
    "NC-1-hostmount": "Inspect container {container} for host filesystem mounts that enable data exposure or persistence",
    "NC-2-promisc": "Check whether network interfaces are in promiscuous mode and assess sniffing risk",
    "NC-2-tun": "Detect whether TUN/TAP devices are present and evaluate whether they enable unexpected network paths",
    "NC-2-arp": "Inspect ARP table anomalies (unexpected mappings) for spoofing or scan behavior",
    "NC-3-dns": "Review DNS resolver configuration and evaluate whether it matches your security expectations",
    "NC-3-ndots": "Review ndots behavior and determine if resolution quirks could enable attacker-controlled lookups",
    "NC-3-nsswitch": "Review name service switch configuration and ensure the lookup order is safe",
    "NC-3-hosts": "Review /etc/hosts changes and determine whether they could redirect critical domains",
    "NC-4-expired": "Check certificate {path} validity and confirm whether expiration impacts security services",
    "NC-4-expiring": "Check certificate {path} expiration window and schedule renewal if needed",
    "NC-4-soon": "Review certificates for {path} and plan renewal to avoid service failure",
    "NC-5-uid0": "List users with UID 0 (root-equivalent) and confirm they are expected",
    "NC-5-newuser": "Review newly created user accounts since baseline and assess legitimacy",
    "NC-5-emptypw": "Identify users with empty passwords and treat as an urgent authentication risk",
    "NC-5-privgroup": "Review users in privileged groups and assess whether membership is appropriate",
    "NC-5-authkeys": "Review SSH authorized_keys content at {path} and verify that only trusted keys exist",
    "NC-6-tmpfs": "Verify tmpfs mounts and evaluate whether they enable suspicious staging behavior",
    "NC-6-bind": "Inspect bind mounts and confirm no unsafe host paths are exposed",
    "NC-6-fakeproc": "Detect fake /proc techniques and confirm whether process hiding is possible",
    "NC-6-noexec": "Check mounts for executable permissions and determine whether noexec protections are missing",
    "NC-7-newtimer": "Identify newly created systemd timers and assess whether they introduce unexpected execution",
    "NC-7-newsvc": "Identify newly running systemd services and assess whether they are legitimate",
    "NC-7-execstart": "Inspect systemd unit {unit} and determine whether ExecStart points to writable scripts or unsafe binaries",
    "NC-7-masked": "Confirm whether systemd unit {unit} is masked and assess whether masking appears malicious or legitimate",
    "NC-8-ntp": "Check time synchronization status and assess whether time drift could affect security decisions",
    "NC-8-drift": "Review clock drift behavior and evaluate potential impacts on auditing and detection",
    "NC-9-nobpf": "Check whether BPF filesystem access is restricted and whether monitoring capability is reduced",
    "NC-9-nobpftool": "Check whether bpftool is available and whether you can inspect eBPF programs when needed",
    "NC-9-unpriv": "Verify whether unprivileged BPF is enabled/disabled and assess exploit exposure",
    "NC-9-newprog": "Check whether new BPF programs were loaded since baseline",
    "NC-9-newmap": "Check whether new BPF maps were created since baseline",
    "NC-9-bpf-surveillance-started": "Review the new BPF object in the watchlist and assess whether it is expected",
    "NC-9-bpf-high-risk-program": "Inspect the high-risk BPF program attach points and loader provenance",
    "NC-9-bpf-critical-program": "Treat as urgent — inspect critical BPF program hooks and loader chain",
    "NC-9-bpf-high-risk-map": "Inspect the high-risk BPF map type and owning programs",
    "NC-9-bpf-map-mutated": "Compare map mutations during surveillance and assess tampering",
    "NC-9-bpf-link-updated": "Review new BPF link attachments for unexpected hooking",
    "NC-9-bpf-pinned-persistence": "Check pinned BPF paths for persistence mechanisms",
    "NC-9-bpf-loader-suspicious": "Investigate the BPF loader process executable and parent chain",
    "NC-9-bpf-monitoring-gap": "Verify auditd rules and backlog; short-lived BPF loads may be missed",
    "NC-9-bpf-baseline-promoted": "Confirm the promoted BPF object is trusted and document the decision",
    "NC-10-nodebsums": "Verify whether package integrity checks were unavailable and assess detection gaps",
    "NC-10-critical": "Inspect package integrity failures for critical packages and determine what changed",
    "NC-10-modified": "Review modified package files and assess for tampering",
    "NC-10-apt": "Check the package database consistency and address any apt integrity issues",
    "NC-11-storage": "Review recent auditd/storage logs to understand if storage integrity or logging is impaired",
    "NC-11-verify": "Review authentication audit events to see whether expected records are missing",
    "NC-11-gap": "Investigate auditing gaps (missing events) since today and ensure evidence continuity",
    "auditd": "Verify that auditd is healthy and collecting events as expected",
    "invalid_users": "Review SSH invalid-user activity and identify which sources appear suspicious",
    "ssh_stats": "Review SSH authentication statistics and compare to expected baseline behavior",
    "trend_new": "Run a full forensic audit to investigate the newly appearing finding",
    "trend_resolved": "Record the resolved state and verify no related persistence remains",
    "trend_persistent": "Run a full forensic audit because the issue persists across audit cycles",
}


class _SafeDict(dict[str, str]):
    """Format helper: missing keys keep the placeholder token."""

    def __missing__(self, key: str) -> str:  # pragma: no cover (defensive)
        return "{" + key + "}"


def _render_guidance(check_id: str, detail: dict[str, Any]) -> str:
    """Render AI-agent guidance for a finding in Telegram-friendly text."""
    template = CHECK_ID_GUIDANCE.get(check_id, "Run a full forensic audit with secmon")

    pid = detail.get("pid") or detail.get("parent_pid") or detail.get("child_pid")
    path = detail.get("path") or detail.get("exe") or ""
    port = detail.get("port") or detail.get("listen_port") or ""
    unit = detail.get("unit") or detail.get("service") or ""
    container = detail.get("container") or detail.get("name") or ""
    module = detail.get("module") or detail.get("module_name") or ""
    key = detail.get("key") or detail.get("sysctl") or ""

    context = {
        "pid": str(pid) if pid else "",
        "path": str(path) if path else "",
        "port": str(port) if port else "",
        "unit": str(unit) if unit else "",
        "container": str(container) if container else "",
        "module": str(module) if module else "",
        "key": str(key) if key else "",
    }

    return template.format_map(_SafeDict(context))


def format_audit_markdown(result: dict[str, Any]) -> str:
    """Render audit result with tables for agent-delivered Telegram."""
    lines: list[str] = []

    score = result.get("total_score", 0)
    total = result.get("finding_count", 0)
    crit = result.get("critical_count", 0)
    high = result.get("high_count", 0)
    med = sum(1 for f in result.get("findings", []) if f["severity"] == "MEDIUM")
    low = sum(1 for f in result.get("findings", []) if f["severity"] == "LOW")

    all_findings = result.get("findings", [])

    lines.append("🔍 **Secmon Audit**")
    lines.append("")

    parts = []
    if crit:
        parts.append(f"🔴 **{crit} CRIT**")
    if high:
        parts.append(f"🟠 **{high} HIGH**")
    if med:
        parts.append(f"🟡 **{med} MED**")
    if low:
        parts.append(f"🔵 **{low} LOW**")
    parts.append(f"Σ **{total}** risk **{score}**")
    lines.append(" · ".join(parts))
    lines.append("")

    if not all_findings:
        lines.append("✅ **System clean** — no findings.")
        lines.append("")
        lines.append("`secmon --audit`")
        return "\n".join(lines)

    lines.append("| Finding | Check | Layer | Action |")
    lines.append("| :---: | :--- | :--- | :--- |")

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = [f for f in all_findings if f["severity"] == severity]
        if not group:
            continue
        
        emoji = SEVERITY_EMOJI.get(severity, "•")
        
        for f in group:
            check_id = f.get("check_id", "")
            msg = f.get("message", "")
            layer = f.get("layer", 0)
            detail = f.get("detail", {}) or {}
            cid_emoji = CHECK_ID_EMOJI.get(check_id, "•")
            layer_name = LAYER_NAMES.get(layer, f"L{layer}")
            
            short_msg = msg[:40] + "..." if len(msg) > 40 else msg
            
            meta = []
            path = detail.get("path") or detail.get("exe")
            pid = detail.get("pid") or detail.get("parent_pid")
            if path:
                p = path if len(path) <= 25 else "..." + path[-22:]
                meta.append(f"`{p}`")
            elif pid:
                meta.append(f"PID `{pid}`")
            
            finding_cell = f"{emoji} **{short_msg}**"
            check_cell = f"{cid_emoji} `{check_id}`"
            detail_cell = layer_name + (" · " + " · ".join(meta) if meta else "")
            
            guidance = _render_guidance(check_id, detail)
            action = ""
            if guidance and not guidance.endswith("secmon"):
                action = guidance.split(" — ")[-1] if " — " in guidance else guidance
            if not action:
                action = "`secmon --audit`"
            
            lines.append(f"| {finding_cell} | {check_cell} | {detail_cell} | {action} |")
        
        lines.append("")

    lines.append("`secmon --audit`")
    return "\n".join(lines)


def _format_details_telegram(detail: dict[str, Any]) -> list[str]:
    """Format detail fields as compact Telegram-friendly lines."""
    out: list[str] = []
    if not detail:
        return out

    # Special-case: show path + one extra field inline when possible
    path = detail.get("path")
    exe = detail.get("exe")
    pid = detail.get("pid") or detail.get("parent_pid") or detail.get("child_pid")
    mode = detail.get("mode")
    content = detail.get("content")
    expected = detail.get("expected")
    users = detail.get("top_users") or detail.get("users")

    if path:
        out.append(f"  📄 `{path}`")
    if exe and exe != path:
        out.append(f"  ⚙️  `{exe}`")
    if pid:
        out.append(f"  PID: `{pid}`")
    if mode:
        out.append(f"  Mode: `{mode}`")
    if content:
        preview = content[:100] if isinstance(content, str) else str(content)[:100]
        out.append(f"  Content: `{preview}`")
    if expected:
        out.append(f"  Expected: `{expected}`")
    if users:
        if isinstance(users, list):
            users_str = ", ".join(str(u) for u in users[:8])
        else:
            users_str = str(users)
        out.append(f"  Users: `{users_str}`")

    # Any remaining keys not handled above
    handled = {"path", "exe", "pid", "parent_pid", "child_pid", "mode", "content", "expected", "top_users", "users"}
    for key, val in detail.items():
        if key not in handled:
            out.append(f"  {key}: `{val}`")

    return out
