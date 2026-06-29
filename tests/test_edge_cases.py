"""Botnet and metrics edge-case tests."""

import os
from unittest.mock import patch

import pytest

from secmon.botnet import detect_and_block, ensure_botnet_chain, get_blocked_subnets, _persist_rules, _log_block
from secmon.metrics import collect_metrics, invalidate_cache, _collect_ssh_metrics, _collect_f2b, _collect_kernel
from secmon.__main__ import main
from secmon.modes.tick import run_tick
from secmon.output import format_status, format_daily_digest
from secmon.state import load_state
from secmon.utils import subnet_24, is_private_or_loopback, ip_in_prefixes


def test_botnet_ensure_chain_fail(cfg, mock_commands):
    def fail_runner(args, **kwargs):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.returncode = 1
        m.stdout = ""
        if args[0] == "iptables" and args[1] == "-I":
            raise OSError("denied")
        return m
    from secmon.shell import set_runner
    set_runner(fail_runner)
    assert ensure_botnet_chain() is False
    set_runner(None)


def test_botnet_persist_and_log(cfg, tmp_path):
    cfg["general"]["botnet_log_file"] = str(tmp_path / "b.log")
    _log_block(cfg, "1.2.3.0/24", "test")
    assert os.path.isfile(tmp_path / "b.log")


def test_botnet_block_failure(cfg, state, mock_commands, monkeypatch):
    lines = ["Failed password from 185.1.2.5"] * 600
    mock_commands(["journalctl", "--since", "24 hours ago"], "\n".join(lines))
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")

    def fail_append(args, **kwargs):
        from unittest.mock import MagicMock
        if args[:3] == ["iptables", "-A", "BOTNET"]:
            raise OSError("denied")
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        return m

    from secmon.shell import set_runner
    set_runner(fail_append)
    alerts = detect_and_block(state, cfg)
    set_runner(None)
    assert alerts == []


def test_metrics_collection_errors(cfg, mock_commands):
    def err_runner(args, **kwargs):
        raise OSError("fail")
    from secmon.shell import set_runner
    set_runner(err_runner)
    m = {}
    _collect_ssh_metrics(m)
    _collect_f2b(m)
    _collect_kernel(m)
    set_runner(None)
    assert m.get("ssh_failed_24h", 0) == 0


def test_main_audit_and_check_modes(cfg, mock_commands, monkeypatch, tmp_path):
    d = str(tmp_path / "d2")
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
    invalidate_cache()
    assert main(["--check"]) == 0


def test_format_output_with_baselines(cfg, state):
    from secmon.config import METRIC_KEYS
    state["baselines"] = {
        "ssh_failed_24h": {"mean": 1, "stdev": 0, "sample_size": 4, "min": 0, "max": 2}
    }
    metrics = {k: 5 for k in METRIC_KEYS}
    assert "baseline" in format_status(state, cfg, metrics).lower()
    assert "Digest" in format_daily_digest(state, metrics)


def test_utils_edge_cases():
    assert subnet_24("not-an-ip") == "not-an-ip"
    assert is_private_or_loopback("10.0.0.1")
    assert not ip_in_prefixes("bad-ip", ["10.0.0.0/8"])
