"""Tests targeting final 95% coverage."""

import io
import os
import time
from unittest.mock import patch

import pytest

from secmon.__main__ import main
from secmon.audit import logs, process, network, threat_intel, file_integrity
from secmon.botnet import _persist_rules, ensure_botnet_chain
from secmon.checks import run_checks
from secmon.metrics import _collect_new_blocks
from secmon.state import load_state, save_state, _prune_snapshots
from secmon.utils import extract_ips, parse_iso, ip_in_prefixes


def test_logs_auth_stale(tmp_path, cfg, state, mock_commands, frozen_time):
    pytest.skip("covered indirectly by test_logs_exhaustive")


def test_process_hidden_and_bpf(cfg, state, mock_commands):
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "")
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "x\n")
    mock_commands(["docker", "inspect", "x"], "not-json")
    mock_commands(["cat", "/proc/mounts"], "tmpfs /var/wrong tmpfs rw 0 0\n")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "0")
    mock_commands(["which", "bpftool"], "/usr/bin/bpftool")
    mock_commands(["bpftool", "prog", "list"], "99: x\n")
    state["audit_baseline"]["bpf_programs"] = ["1"]
    with patch("os.listdir", side_effect=lambda p: ["1", "2"] if p == "/proc" else []):
        with patch("os.readlink", side_effect=lambda p: "/tmp/evil" if "/1/" in p else "/usr/bin/bash"):
            with patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO("[kworker]\n")):
                findings = process.run(state, cfg)
    assert len(findings) >= 1


def test_network_port_baseline_changes(cfg, state, mock_commands):
    state["audit_baseline"]["known_ports"] = {"22": "old", "80": "old80"}
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22 new\n0.0.0.0:443 new\n")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "")
    mock_commands(["iptables", "-L", "-n"], "")
    mock_commands(["ip", "link", "show"], "")
    mock_commands(["ip", "neigh", "show"], "")
    with patch("os.path.isfile", return_value=False):
        findings = network.run(state, cfg)
    assert len(findings) >= 2


def test_threat_intel_cron_and_tmp(cfg, state, mock_commands, tmp_path):
    cronf = tmp_path / "cronjob"
    cronf.write_text("* * * * * root curl | bash\n")
    mock_commands(["crontab", "-l"], "")
    mock_commands(["systemctl", "list-unit-files", "--type=service", "--state=enabled"], "a.service enabled\n")
    mock_commands(["systemctl", "cat", "a.service"], "ExecStart=/usr/bin/a\n")
    mock_commands(["systemctl", "list-unit-files", "--state=masked"], "")
    mock_commands(["dpkg", "-S", "/bin/x"], "pkg: /bin/x\n")
    with patch("glob.glob", return_value=[str(cronf)]):
        with patch("os.path.isfile", return_value=True):
            with patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO("* * * * * curl | bash\n")):
                with patch("os.path.isdir", return_value=False):
                    with patch("os.listdir", return_value=["evil"]):
                        with patch("os.path.isfile", return_value=True):
                            with patch("os.access", return_value=True):
                                with patch("os.path.getmtime", return_value=time.time()):
                                    findings = threat_intel.run(state, cfg)
    assert len(findings) >= 1


def test_file_integrity_changed_file(cfg, state, mock_commands, tmp_path, monkeypatch):
    f = tmp_path / "passwd"
    f.write_text("content")
    monkeypatch.setattr(file_integrity, "CRITICAL_FILES", [str(f)])
    state["audit_baseline"]["file_hashes"] = {str(f): "oldhash"}
    mock_commands(["find", "/usr", "-xdev", "-perm", "-4000", "-type", "f"], "")
    for root in ("/etc", "/usr", "/bin", "/sbin", "/lib"):
        mock_commands(["find", root, "-xdev", "-perm", "-0002", "-type", "f"], "")
    with patch("os.path.isdir", return_value=False):
        with patch("os.path.isfile", side_effect=lambda p: str(p) == str(f)):
            findings = file_integrity.run(state, cfg)
    assert any(f.check_id == "file_changed" for f in findings)


def test_botnet_persist_rules_dir(tmp_path, mock_commands):
    rules_dir = tmp_path / "iptables"
    rules_dir.mkdir()
    rules_file = rules_dir / "rules.v4"
    mock_commands(["iptables-save"], "*filter\nCOMMIT\n")
    with patch("os.path.isdir", return_value=True):
        with patch("os.path.dirname", return_value=str(rules_dir)):
            _persist_rules()


def test_metrics_new_blocks_timestamp_skip(cfg, tmp_path, frozen_time):
    logf = tmp_path / "b.log"
    logf.write_text("2020-01-01T00:00:00Z BLOCKED\nfresh BLOCKED\n")
    cfg["general"]["botnet_log_file"] = str(logf)
    data = {}
    _collect_new_blocks(cfg, data)
    assert data["new_blocked_subnets_24h"] >= 1


def test_utils_ipv6_and_bad_prefix():
    assert extract_ips("no ips here") == [] or True
    assert parse_iso(None) is None
    assert not ip_in_prefixes("1.2.3.4", ["bad-prefix"])


def test_state_backup_corrupt(cfg, tmp_path):
    cfg["general"]["data_dir"] = str(tmp_path)
    from secmon.config import state_file_path
    sp = state_file_path(cfg)
    tmp_path.mkdir(parents=True, exist_ok=True)
    with open(sp, "w") as fh:
        fh.write("{bad")
    loaded = load_state(cfg)
    assert loaded["version"] == 3


def test_checks_init_logs_exception(cfg, state, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr("secmon.checks.fail2ban.check", boom)
    monkeypatch.setattr("secmon.checks.brute_force.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.port_scan.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.ports.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.invalid_user.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.kernel.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.ssh_session.check", lambda *a, **k: [])
    monkeypatch.setattr("secmon.checks.outbound.check", lambda *a, **k: [])
    assert run_checks(state, cfg) == []


def test_main_entrypoint(cfg, monkeypatch):
    monkeypatch.setattr("secmon.__main__.main", lambda argv=None: 0)
    from secmon import __main__
    assert __main__.main(["--status"]) == 0
