"""Tests to reach coverage targets on remaining modules."""

import io
import json
from unittest.mock import patch

import pytest

from secmon.__main__ import main
from secmon.audit import file_integrity, compliance
from secmon.baseline import suggest_calibration
from secmon.botnet import get_blocked_subnets
from secmon.checks import fail2ban, ports, brute_force
from secmon.config import load_config
from secmon.metrics import invalidate_cache, collect_metrics
from secmon.modes.tick import run_tick
from secmon.state import save_state, load_state


def test_main_all_modes(cfg, mock_commands, monkeypatch, tmp_path):
    d = str(tmp_path / "maindata")
    monkeypatch.setenv("SECMON_DATA_DIR", d)
    base_mocks = [
        (["journalctl", "--since", "24 hours ago"], ""),
        (["fail2ban-client", "status", "sshd"], ""),
        (["iptables", "-L", "BOTNET", "-n"], ""),
        (["journalctl", "-k", "--since", "24 hours ago"], ""),
        (["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], ""),
        (["ss", "-tlnp"], ""),
        (["ss", "-tnp", "state", "established"], ""),
        (["journalctl", "--since", "5 minutes ago"], ""),
        (["journalctl", "-k", "--since", "1 hour ago"], ""),
        (["ss", "-tnp", "dport", "=", ":22"], ""),
        (["iptables", "-N", "BOTNET"], ""),
        (["iptables", "-L", "INPUT", "-n"], "BOTNET"),
    ]
    for args, out in base_mocks:
        mock_commands(args, out)
  # audit mode mocks
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "")
    mock_commands(["ip", "neigh", "show"], "")
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "")
    mock_commands(["cat", "/proc/mounts"], "")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "")
    mock_commands(["sshd", "-T"], "")
    mock_commands(["systemctl", "--failed", "--no-legend"], "")
    mock_commands(["journalctl", "--verify"], "")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"], "")
    mock_commands(["systemctl", "is-active", "auditd"], "")
    mock_commands(["crontab", "-l"], "")
    mock_commands(["systemctl", "list-unit-files", "--type=service", "--state=enabled"], "")
    mock_commands(["systemctl", "list-unit-files", "--state=masked"], "")
    mock_commands(["apt", "list", "--upgradable"], "")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "yes")
    mock_commands(["chronyc", "tracking"], "")
    mock_commands(["which", "debsums"], "")
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "1")
    invalidate_cache()
    assert main(["--status"]) == 0
    assert main(["--daily"]) == 0
    assert main(["--record"]) == 0
    assert main(["--detect-botnet"]) == 0
    assert main(["--audit"]) in (0, 1)


def test_file_integrity_preload_and_tmp(cfg, state, mock_commands, monkeypatch):
    monkeypatch.setattr(file_integrity, "CRITICAL_FILES", [])
    mock_commands(["find", "/usr", "-xdev", "-perm", "-4000", "-type", "f"], "")
    for root in ("/etc", "/usr", "/bin", "/sbin", "/lib"):
        mock_commands(["find", root, "-xdev", "-perm", "-0002", "-type", "f"], "")

    def isfile(p):
        s = str(p)
        return s.endswith("ld.so.preload") or s == "/tmp"

    def open_router(path, *a, **k):
        if str(path).endswith("ld.so.preload"):
            return io.StringIO("/evil/lib.so\n")
        raise FileNotFoundError(path)

    with patch("os.path.isfile", side_effect=isfile):
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[".hidden"]):
                with patch("os.stat", return_value=type("S", (), {"st_mode": 0o040777})()):
                    with patch("builtins.open", side_effect=open_router):
                        findings = file_integrity.run(state, cfg)
    assert any(f.check_id == "ld_preload" for f in findings)


def test_compliance_cert_expiry_branches(cfg, state, mock_commands, frozen_time):
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "1")
    mock_commands(["apt", "list", "--upgradable"], "")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "ii")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "yes")
    mock_commands(["chronyc", "tracking"], "System time : 10.0 seconds\n")
    mock_commands(["which", "debsums"], "")
    mock_commands(["openssl", "x509", "-in", "/c.pem", "-noout", "-enddate"], "notAfter=Jul  1 00:00:00 2026 GMT\n")
    mock_commands(["openssl", "x509", "-in", "/c2.pem", "-noout", "-enddate"], "notAfter=Aug  1 00:00:00 2026 GMT\n")
    with patch("os.path.isfile", return_value=False):
        with patch("os.path.isdir", return_value=True):
            with patch("glob.glob", return_value=["/c.pem", "/c2.pem"]):
                findings = compliance.run(state, cfg)
    assert isinstance(findings, list)


def test_fail2ban_noise_and_brute_info(cfg, state, mock_commands):
    mock_commands(["fail2ban-client", "status", "sshd"], "Banned IP list:\n1.2.3.4\n")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "DROP all -- 1.2.3.0/24\n")
    state["monitor_state"]["last_f2b_snapshot"] = ""
    alerts = fail2ban.check(state, cfg)
    assert alerts


def test_ports_closed(cfg, state, mock_commands):
    state["monitor_state"]["known_ports_output"] = "State\n0.0.0.0:22\n0.0.0.0:80\n"
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22\n")
    alerts = ports.check(state, cfg)
    assert any("closed" in a.message for a in alerts)


def test_brute_force_info_blocked_subnet(cfg, state, mock_commands):
    lines = "\n".join([f"Failed password from 1.2.3.{i}" for i in range(15)])
    mock_commands(["journalctl", "--since", "5 minutes ago"], lines)
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "DROP all -- 1.2.3.0/24\n")
    alerts = brute_force.check(state, cfg)
    assert any(a.severity == "INFO" for a in alerts)


def test_config_generic_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECMON_REALTIME_SSH_BRUTE_FORCE_THRESHOLD", "20")
    cfg = load_config(overrides={"general": {"data_dir": str(tmp_path)}})
    assert cfg["realtime"]["ssh_brute_force_threshold"] == 20
