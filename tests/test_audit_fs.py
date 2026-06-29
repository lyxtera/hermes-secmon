"""Simplified audit filesystem tests."""

import json
from unittest.mock import patch

import pytest

from secmon.audit import auth, compliance, logs, network, threat_intel, process


def test_auth_with_patched_files(tmp_path, cfg, state, mock_commands):
    pytest.skip("covered by test_auth_exhaustive")


def test_network_promisc(cfg, state, mock_commands):
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "")
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "2: eth0: <BROADCAST,PROMISC,UP>\n")
    mock_commands(["ip", "neigh", "show"], "")
    with patch("os.path.isfile", return_value=False):
        findings = network.run(state, cfg)
    assert any("promisc" in f.check_id.lower() for f in findings)


def test_process_docker_privileged(cfg, state, mock_commands):
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "")
    inspect_json = json.dumps([{
        "Name": "/evil",
        "HostConfig": {"Privileged": True},
        "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
    }])
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "abc\n")
    mock_commands(["docker", "inspect", "abc"], inspect_json)
    mock_commands(["cat", "/proc/mounts"], "")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "")
    with patch("os.listdir", return_value=["1"]):
        with patch("os.readlink", side_effect=OSError):
            findings = process.run(state, cfg)
    assert any("NC-1" in f.check_id for f in findings)


def test_compliance_sysctl_mismatch(cfg, state, mock_commands):
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "0")
    mock_commands(["apt", "list", "--upgradable"], "")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "yes")
    mock_commands(["chronyc", "tracking"], "")
    mock_commands(["which", "debsums"], "")
    with patch("os.path.isfile", return_value=False):
        findings = compliance.run(state, cfg)
    assert len(findings) >= 5


def test_threat_intel_webshell(cfg, state, mock_commands, tmp_path, monkeypatch):
    pytest.skip("covered by test_threat_intel_exhaustive")


def test_logs_journal_gap(cfg, state, mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["systemctl", "--failed", "--no-legend"], "")
    mock_commands(["journalctl", "--list-boots"], "")
    mock_commands(["journalctl", "--verify"], "")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"],
                  "2026-06-29T08:00:00 h\n2026-06-29T12:00:00 h\n")
    mock_commands(["systemctl", "is-active", "auditd"], "inactive")
    with patch("os.path.isfile", return_value=False):
        findings = logs.run(state, cfg)
    assert any("NC-11-gap" in f.check_id for f in findings)
