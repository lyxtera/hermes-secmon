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

    METRIC_IMPACT = {
        "ssh_failed_24h": "Failed SSH logins — spikes often mean brute-force or credential stuffing",
        "ssh_invalid_user_24h": "Logins for non-existent users — recon and username guessing",
        "unique_attacker_ips": "Distinct sources targeting SSH — breadth of attack surface",
        "unique_attacker_subnets": "Attacker /24 subnets seen — distributed scan activity",
        "f2b_banned_count": "IPs banned by fail2ban — active defense response to abuse",
        "botnet_chain_rules": "iptables BOTNET rules — blocked hostile subnets",
        "martian_packets_24h": "Impossible-source packets — routing misconfig or spoofing",
        "new_blocked_subnets_24h": "New subnets added to blocklist — emerging attack waves",
        "kernel_errors_24h": "Kernel log errors — hardware, driver, or stability issues",
        "listening_ports_count": "Open listening sockets — unexpected growth may mean new services or backdoors",
        "established_conns": "Active outbound/inbound sessions — baseline drift can signal C2 or load changes",
    }

    METRIC_CTA = {
        "ssh_failed_24h": "journalctl -u ssh --since '24 hours ago' | grep 'Failed password' | tail -20",
        "ssh_invalid_user_24h": "journalctl -u ssh --since '24 hours ago' | grep 'Invalid user' | tail -20",
        "unique_attacker_ips": "journalctl -u ssh --since '24 hours ago' | grep 'Failed password' | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -15",
        "unique_attacker_subnets": "secmon --detect-botnet",
        "f2b_banned_count": "fail2ban-client status sshd",
        "botnet_chain_rules": "iptables -L BOTNET -n --line-numbers",
        "martian_packets_24h": "dmesg -T | grep -i martian | tail -20",
        "new_blocked_subnets_24h": "tail -30 /var/log/secmon-botnet.log",
        "kernel_errors_24h": "journalctl -k --since '24 hours ago' -p err | tail -20",
        "listening_ports_count": "ss -tlnp",
        "established_conns": "ss -tnp state established | head -30",
    }

    elevated_ctas: list[str] = []

    lines.append("### 📅 Daily Security Digest")
    lines.append("")
    lines.append("### 📊 24h Activity")
    lines.append("")

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
                delta_str = f"⚠️ {delta:+d}"
                if key in METRIC_CTA:
                    elevated_ctas.append(
                        f"{label} above baseline — `{METRIC_CTA[key]}`"
                    )
            elif delta < -stdev * 2:
                delta_str = f"✅ {delta:+d}"
            else:
                delta_str = f"{delta:+d}"
            lines.append(f"**{label}**  `{val:,}`  baseline `{mean:.0f}`  {delta_str}")
        else:
            lines.append(f"**{label}**  `{val:,}`")

        if impact:
            lines.append(f"_{impact}_")
        lines.append("")

    # --- Summary row ---
    lines.append("### 🔍 Summary")
    lines.append("")
    lines.append(f"- **SSH failures:** {metrics.get('ssh_failed_24h', 0):,}")
    lines.append(f"- **Invalid users:** {metrics.get('ssh_invalid_user_24h', 0):,}")
    lines.append(f"- **Fail2ban bans:** {metrics.get('f2b_banned_count', 0):,}")
    lines.append(
        f"- **Unique attackers:** {metrics.get('unique_attacker_ips', 0):,} IPs / "
        f"{metrics.get('unique_attacker_subnets', 0):,} subnets"
    )
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

    if elevated_ctas:
        lines.append("### ▶ What to check")
        lines.append("")
        for cta in elevated_ctas[:5]:
            lines.append(f"- ℹ️ {cta}")
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

CHECK_ID_CTA: dict[str, str] = {
    "proc_hollow_anon": "cat /proc/<pid>/maps | grep anon",
    "proc_hollow_deleted": "ls -la /proc/<pid>/exe && cat /proc/<pid>/cmdline",
    "proc_hollow_rwx": "grep -E 'rwx' /proc/<pid>/maps",
    "proc_spoof": "cat /proc/<pid>/comm && readlink /proc/<pid>/exe",
    "hidden_proc": "ps aux && ls /proc/<pid>",
    "proc_lineage_web_shell": "pstree -p <pid> && cat /proc/<pid>/cmdline",
    "proc_lineage_inject": "pstree -p <pid> && cat /proc/<pid>/status | grep PPid",
    "proc_root_tmp": "ls -la <path> && cat /proc/<pid>/cmdline",
    "proc_root_deleted": "ls -la /proc/<pid>/exe",
    "bad_module": "lsmod && modinfo <module>",
    "kernel_tainted": "cat /proc/sys/kernel/tainted",
    "kernel_sysctl_change": "sysctl -a | diff - baseline-sysctl.txt",
    "kernel_modules_enabled": "sysctl kernel.modules_disabled",
    "file_changed": "sha256sum <path> && ls -la <path>",
    "file_removed": "ls -la <path>",
    "world_writable": "ls -la <path>",
    "ld_preload": "cat /etc/ld.so.preload",
    "hidden_tmp": "ls -la <path>",
    "unexpected_suid": "find / -perm -4000 -not -path '/proc/*' 2>/dev/null | head -30",
    "new_listen_port": "ss -tlnp | grep <port>",
    "port_changed": "ss -tlnp | grep <port>",
    "port_removed": "ss -tlnp",
    "fw_policy": "iptables -L -n -v",
    "fw_chain": "iptables -L -n -v",
    "webshell": "head -50 <path>",
    "secret_world_readable": "ls -la <path>",
    "secret_key_tmp": "ls -la <path>",
    "secret_pattern": "grep -n . <path> | head -20",
    "secret_authkeys_perm": "ls -la <path>",
    "persist_new": "systemctl list-unit-files --state=enabled | tail -20",
    "persist_modified": "systemctl cat <unit>",
    "persist_removed": "systemctl list-unit-files | grep <unit>",
    "cron_suspicious": "crontab -l && ls -la /etc/cron.*",
    "modified_bin": "debsums -c /bin /usr/bin 2>/dev/null | head -20",
    "tmp_executable": "ls -la <path>",
    "sysctl": "sysctl <key>",
    "sec_updates": "apt list --upgradable 2>/dev/null | grep -i security",
    "unattended": "systemctl status unattended-upgrades",
    "pass_aging": "chage -l root",
    "sshd_config": "sshd -T | grep -E 'permit|auth|login|password'",
    "nopasswd": "grep -v '^#' /etc/passwd | awk -F: '$2==\"\"'",
    "systemd_failed": "systemctl --failed",
    "log_stale": "ls -la <path> && stat <path>",
    "log_truncated": "ls -la <path> && tail -5 <path>",
    "risk_increase": "secmon --audit",
    "NC-1-privileged": "docker ps --format 'table {{.Names}}\t{{.Status}}'",
    "NC-1-sock": "docker inspect <container> | grep -A5 Mounts",
    "NC-1-hostmount": "docker inspect <container> | grep -A5 Mounts",
    "NC-2-promisc": "ip link show | grep PROMISC",
    "NC-2-tun": "ip link show type tun",
    "NC-2-arp": "ip neigh show",
    "NC-3-dns": "cat /etc/resolv.conf",
    "NC-3-ndots": "grep ndots /etc/resolv.conf",
    "NC-3-nsswitch": "cat /etc/nsswitch.conf",
    "NC-3-hosts": "cat /etc/hosts",
    "NC-4-expired": "openssl x509 -in <path> -noout -dates",
    "NC-4-expiring": "openssl x509 -in <path> -noout -dates",
    "NC-4-soon": "certbot certificates 2>/dev/null || openssl x509 -in <path> -noout -dates",
    "NC-5-uid0": "awk -F: '$3==0 {print}' /etc/passwd",
    "NC-5-newuser": "getent passwd",
    "NC-5-emptypw": "awk -F: '$2==\"\" {print $1}' /etc/shadow 2>/dev/null",
    "NC-5-privgroup": "getent group sudo wheel admin",
    "NC-5-authkeys": "cat <path>",
    "NC-6-tmpfs": "mount | grep tmpfs",
    "NC-6-bind": "mount | grep bind",
    "NC-6-fakeproc": "mount | grep /proc",
    "NC-6-noexec": "mount | grep -v noexec",
    "NC-7-newtimer": "systemctl list-timers --all",
    "NC-7-newsvc": "systemctl list-units --type=service --state=running",
    "NC-7-execstart": "systemctl cat <unit>",
    "NC-7-masked": "systemctl is-enabled <unit>",
    "NC-8-ntp": "timedatectl status",
    "NC-8-drift": "timedatectl status",
    "NC-9-nobpf": "ls /sys/fs/bpf",
    "NC-9-nobpftool": "which bpftool",
    "NC-9-unpriv": "sysctl kernel.unprivileged_bpf_disabled",
    "NC-9-newprog": "bpftool prog list",
    "NC-9-newmap": "bpftool map list",
    "NC-10-nodebsums": "debsums -c 2>/dev/null | head -20",
    "NC-10-critical": "debsums -c 2>/dev/null | head -20",
    "NC-10-modified": "debsums -c 2>/dev/null | head -20",
    "NC-10-apt": "apt-get check",
    "NC-11-storage": "journalctl -u auditd --since '24 hours ago' | tail -20",
    "NC-11-verify": "ausearch -m USER_AUTH 2>/dev/null | tail -10",
    "NC-11-gap": "ausearch --start today 2>/dev/null | tail -10",
    "auditd": "systemctl status auditd",
    "invalid_users": "journalctl -u ssh --since '24 hours ago' | grep 'Invalid user' | tail -20",
    "ssh_stats": "journalctl -u ssh --since '24 hours ago' | tail -30",
    "trend_new": "secmon --audit",
    "trend_resolved": "secmon --audit",
    "trend_persistent": "secmon --audit",
}


def _render_cta(check_id: str, detail: dict[str, Any]) -> str:
    """Fill CTA template placeholders from finding detail."""
    template = CHECK_ID_CTA.get(check_id, "secmon --audit")
    pid = detail.get("pid") or detail.get("parent_pid") or detail.get("child_pid")
    path = detail.get("path") or detail.get("exe") or ""
    port = detail.get("port") or detail.get("listen_port") or ""
    unit = detail.get("unit") or detail.get("service") or ""
    container = detail.get("container") or detail.get("name") or ""
    module = detail.get("module") or detail.get("module_name") or ""
    key = detail.get("key") or detail.get("sysctl") or ""

    replacements = {
        "<pid>": str(pid) if pid else "<pid>",
        "<path>": str(path) if path else "<path>",
        "<port>": str(port) if port else "<port>",
        "<unit>": str(unit) if unit else "<unit>",
        "<container>": str(container) if container else "<container>",
        "<module>": str(module) if module else "<module>",
        "<key>": str(key) if key else "<key>",
    }
    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    return result


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
    """Render audit result as clean Telegram markdown."""
    lines: list[str] = []

    score = result.get("total_score", 0)
    total = result.get("finding_count", 0)
    crit = result.get("critical_count", 0)
    high = result.get("high_count", 0)
    med = sum(1 for f in result.get("findings", []) if f["severity"] == "MEDIUM")
    low = sum(1 for f in result.get("findings", []) if f["severity"] in ("LOW", "INFO"))

    all_findings = result.get("findings", [])

    # ── Header ──────────────────────────────────────────────
    lines.append("🔍 **Secmon Audit**")
    lines.append("")

    # ── Compact severity bar ───────────────────────────────
    # Shows only non-zero severities inline with labels
    bar_parts = []
    if crit:
        bar_parts.append(f"🔴 **CRIT** {crit}")
    if high:
        bar_parts.append(f"🟠 **HIGH** {high}")
    if med:
        bar_parts.append(f"🟡 **MED** {med}")
    if low:
        bar_parts.append(f"🔵 **LOW** {low}")
    bar_parts.append(f"Σ **{total}**  risk **{score}**")
    lines.append("  ·  ".join(bar_parts))
    lines.append("")

    if not all_findings:
        lines.append("✅  System clean — no findings.")
        lines.append("")
        lines.append("`secmon --audit`")
        return "\n".join(lines)

    # ── Findings by severity ───────────────────────────────
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in all_findings if f["severity"] == severity]
        if not group:
            continue
        emoji = SEVERITY_EMOJI.get(severity, "•")
        label = severity.capitalize()
        lines.append(f"**{emoji}  {label} — {len(group)}**")
        lines.append("")

        for f in group:
            check_id = f.get("check_id", "")
            msg = f.get("message", "")
            layer = f.get("layer", 0)
            detail = f.get("detail", {}) or {}

            cid_emoji = CHECK_ID_EMOJI.get(check_id, "•")
            layer_name = LAYER_NAMES.get(layer, f"L{layer}")
            explanation = CHECK_ID_EXPLANATIONS.get(check_id, "")

            # Finding title
            lines.append(f"• {cid_emoji}  **{msg}**")
            lines.append("")

            # Short explanation as blockquote
            if explanation:
                lines.append(f"> _{explanation}_")
                lines.append("")

            # Badge line: check_id + layer
            lines.append(f"`{check_id}`  ·  {layer_name}")
            lines.append("")

            # Detail fields — compact single-line where possible
            if detail:
                detail_lines = _format_details_telegram(detail)
                lines.extend(detail_lines)
                lines.append("")

            cta = _render_cta(check_id, detail)
            lines.append(f"▶ `{cta}`")
            lines.append("")

            # Visual separator between findings
            lines.append(FINDING_DIVIDER)
            lines.append("")

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
