"""Audit layer tests."""

from unittest.mock import patch

from secmon.audit import run_audit
from secmon.audit.base import AuditFinding
from secmon.audit import trends


def test_run_audit_returns_json(cfg, state, mock_commands):
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22\n")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "Chain INPUT (policy ACCEPT)")
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "1: lo: <LOOPBACK>\n")
    mock_commands(["ip", "neigh", "show"], "")
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "Module\n")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "")
    mock_commands(["cat", "/proc/mounts"], "proc /proc proc\n")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "")
    mock_commands(["sshd", "-T"], "maxauthtries 3\npermitemptypasswords no\n")
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["systemctl", "--failed", "--no-legend"], "")
    mock_commands(["journalctl", "--list-boots"], "")
    mock_commands(["journalctl", "--verify"], "pass")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"], "2026-06-29T09:00:00\n")
    mock_commands(["systemctl", "is-active", "auditd"], "inactive")
    mock_commands(["crontab", "-l"], "")
    mock_commands(["systemctl", "list-unit-files", "--type=service", "--state=enabled"], "ssh.service enabled")
    mock_commands(["systemctl", "cat", "ssh.service"], "ExecStart=/usr/sbin/sshd\n")
    mock_commands(["systemctl", "list-unit-files", "--state=masked"], "")
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "1")
    mock_commands(["apt", "list", "--upgradable"], "")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "unattended-upgrades")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "yes")
    mock_commands(["chronyc", "tracking"], "")
    mock_commands(["which", "debsums"], "")
    result = run_audit(state, cfg)
    assert "findings" in result
    assert "total_score" in result


def test_trends_layer(cfg, state):
    current = [AuditFinding("HIGH", 1, "test_check", "test message")]
    state["last_audit_findings"] = []
    state["last_audit_score"] = 0
    findings = trends.run(state, cfg, current)
    assert any(f.check_id == "trend_new" for f in findings)
