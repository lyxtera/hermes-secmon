"""Additional tests for coverage."""

import json
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from secmon.__main__ import main
from secmon.alerts import Alert, _log_alert
from secmon.audit import process as audit_process
from secmon.audit import file_integrity, network, auth, logs, threat_intel, compliance
from secmon.baseline import check_baseline_staleness, suggest_calibration
from secmon.botnet import list_blocked, unblock_subnet, flush_botnet_chain, ensure_botnet_chain
from secmon.config import default_config, state_file_path
from secmon.metrics import collect_metrics_from_state, invalidate_cache
from secmon.modes.tick import run_tick
from secmon.modes.audit_mode import run_audit_mode
from secmon.modes.detect_botnet import run_detect_botnet
from secmon.shell import run_cmd, run_cmd_safe, set_runner
from secmon.state import load_state, save_state, trim_daily_stats
from secmon.utils import ip_in_prefixes, parse_iso


def test_tick_mode(cfg, state, mock_commands, frozen_time, monkeypatch):
    monkeypatch.setenv("SECMON_DATA_DIR", cfg["general"]["data_dir"])
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["fail2ban-client", "status", "sshd"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "")
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    mock_commands(["journalctl", "-k", "--since", "1 hour ago"], "")
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "")
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    invalidate_cache()
    rc = run_tick(state, cfg)
    assert rc in (0, 1)
    save_state(cfg, state)


def test_audit_mode(cfg, state, mock_commands, capsys):
    from secmon.audit import run_audit
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "")
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "")
    mock_commands(["ip", "neigh", "show"], "")
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "")
    mock_commands(["cat", "/proc/mounts"], "proc /proc proc\n")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "")
    mock_commands(["sshd", "-T"], "")
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
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
    result = run_audit(state, cfg)
    assert "findings" in result
    rc = run_audit_mode(state, cfg)
    assert rc in (0, 1)


def test_detect_botnet_mode(cfg, state, mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    rc = run_detect_botnet(state, cfg)
    assert rc == 0


def test_shell_timeout():
    def slow(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 30)
    set_runner(slow)
    assert run_cmd_safe(["sleep", "99"], default="x") == "x"
    set_runner(None)


def test_shell_not_found():
    def missing(args, **kwargs):
        raise FileNotFoundError(args[0])
    set_runner(missing)
    with pytest.raises(FileNotFoundError):
        run_cmd(["nonexistent-cmd-xyz"])
    set_runner(None)


def test_baseline_staleness(cfg, state, frozen_time):
    from secmon.config import METRIC_KEYS
    state["daily_stats"] = [
        {"timestamp": "2026-06-20T00:00:00Z", **{k: 1 for k in METRIC_KEYS}}
    ]
    state["baselines"] = {"ssh_failed_24h": {"mean": 1}}
    assert check_baseline_staleness(state)
    assert state["baselines"] == {}


def test_trim_daily_stats():
    from secmon.config import METRIC_KEYS
    old = {"timestamp": "2020-01-01T00:00:00Z", **{k: 1 for k in METRIC_KEYS}}
    new = {"timestamp": "2026-06-29T00:00:00Z", **{k: 1 for k in METRIC_KEYS}}
    result = trim_daily_stats([old, new], 30)
    assert len(result) == 1


def test_ip_in_prefixes():
    assert ip_in_prefixes("10.1.2.3", ["10.0.0.0/8"])


def test_parse_iso_invalid():
    assert parse_iso("bad") is None


def test_main_no_mode():
    with pytest.raises(SystemExit):
        main([])


def test_main_tick(cfg, mock_commands, monkeypatch, tmp_path):
    d = str(tmp_path / "d")
    monkeypatch.setenv("SECMON_DATA_DIR", d)
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["fail2ban-client", "status", "sshd"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "")
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    mock_commands(["journalctl", "-k", "--since", "1 hour ago"], "")
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "")
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    invalidate_cache()
    rc = main(["--tick"])
    assert rc in (0, 1)


@patch("secmon.audit.process.os.listdir")
@patch("secmon.audit.process.os.readlink")
@patch("secmon.audit.process.os.stat")
def test_process_layer(mock_stat, mock_readlink, mock_listdir, cfg, state, mock_commands, mock_bpf_empty):
    mock_listdir.return_value = ["1", "2", "self"]
    mock_readlink.side_effect = OSError("no exe")
    mock_stat.side_effect = OSError("no stat")
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "Module\n")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "")
    mock_commands(["cat", "/proc/mounts"], "proc /proc proc defaults 0 0\n")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "/usr/bin/bpftool")
    findings = audit_process.run(state, cfg)
    assert isinstance(findings, list)


def test_file_integrity_missing_file(cfg, state, tmp_path, monkeypatch):
    monkeypatch.setattr(file_integrity, "CRITICAL_FILES", [str(tmp_path / "missing")])
    state["audit_baseline"]["file_hashes"] = {str(tmp_path / "missing"): "abc"}
    findings = file_integrity.run(state, cfg)
    assert any(f.check_id == "file_removed" for f in findings)


def test_collect_metrics_from_state_cache(cfg, state, frozen_time):
    from secmon.config import METRIC_KEYS
    from secmon.metrics import invalidate_cache
    invalidate_cache()
    state["metric_cache"] = {
        "timestamp": "2026-06-29T09:59:00Z",
        "values": {k: 42 for k in METRIC_KEYS},
    }
    m = collect_metrics_from_state(cfg, state)
    assert m["ssh_failed_24h"] == 42


def test_botnet_utilities(cfg, mock_commands):
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "1 DROP all -- 1.2.3.0/24\n")
    assert list_blocked()
    mock_commands(["iptables", "-L", "BOTNET", "-n", "--line-numbers"], "1 DROP all -- 1.2.3.0/24\n")
    mock_commands(["iptables", "-D", "BOTNET", "1"], "")
    unblock_subnet("1.2.3.0/24")
    mock_commands(["iptables", "-F", "BOTNET"], "")
    flush_botnet_chain()
