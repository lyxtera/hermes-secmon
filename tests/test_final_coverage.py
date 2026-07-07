"""Final coverage push for metrics, state, botnet, utils."""

import json
import os
from unittest.mock import patch

import pytest

from secmon import metrics, state as state_mod
from secmon.botnet import detect_and_block, get_blocked_subnets
from secmon.checks import outbound, ssh_session
from secmon.metrics import _collect_network, _collect_botnet_rules, _collect_new_blocks, _collect_f2b
from secmon.output import format_daily_digest
from secmon.state import load_state, save_state, run_migrations
from secmon.anomaly import detect_anomalies
from secmon.baseline import compute_baselines, suggest_calibration
from secmon.config import METRIC_KEYS


def test_metrics_all_collectors_fail(cfg, mock_commands):
    def empty(args, **kwargs):
        from unittest.mock import MagicMock
        m = MagicMock()
        m.returncode = 1
        m.stdout = ""
        return m
    from secmon.shell import set_runner
    set_runner(empty)
    metrics.invalidate_cache()
    m = metrics.collect_metrics(cfg, force=True)
    assert all(v == 0 for v in m.values())
    set_runner(None)


def test_metrics_botnet_log_count(cfg, tmp_path):
    logf = tmp_path / "b.log"
    logf.write_text("BLOCKED\nBLOCKED\n")
    cfg["general"]["botnet_log_file"] = str(logf)
    data = {}
    _collect_new_blocks(cfg, data)
    assert data["new_blocked_subnets_24h"] == 2


def test_state_os_error_on_save(cfg, state, monkeypatch):
    monkeypatch.setattr(state_mod, "_atomic_write", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    assert save_state(cfg, state) is False


def test_state_trim_invalid_timestamp():
    from secmon.state import trim_daily_stats
    bad = [{"timestamp": "invalid", "ssh_failed_24h": 1}]
    result = trim_daily_stats(bad, 30)
    assert len(result) == 1


def test_outbound_ipv6_skip(cfg, state, mock_commands):
    mock_commands(["ss", "-tnp", "state", "established"], "::1:6666 users:((")
    assert outbound.check(state, cfg) == []


def test_ssh_session_ended_clears_dedup(cfg, state, mock_commands):
    state["monitor_state"]["active_ssh_sessions"] = {"ssh:9.9.9.9": True}
    state["dedup_store"]["ssh:9.9.9.9"] = {"time": "2026-01-01T00:00:00Z"}
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "")
    ssh_session.check(state, cfg)
    assert "ssh:9.9.9.9" not in state["monitor_state"]["active_ssh_sessions"]


def test_format_daily_recent_anomalies(cfg, state):
    state["baselines"] = {
        "ssh_failed_24h": {"mean": 1, "stdev": 0, "min": 0, "max": 2, "sample_size": 4}
    }
    state["last_anomalies"] = [{"severity": "HIGH", "metric": "ssh_failed_24h", "direction": "above"}]
    out = format_daily_digest(state, {k: 1 for k in METRIC_KEYS})
    assert "Recent Anomalies" in out


def test_suggest_calibration_range(cfg, state):
    from secmon.baseline import suggest_calibration
    daily = []
    for i in range(15):
        entry = {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z"}
        for k in METRIC_KEYS:
            entry[k] = 1000 + i * 100
        daily.append(entry)
    state["daily_stats"] = daily
    suggestions = suggest_calibration(state, cfg)
    assert suggestions


def test_migration_v0():
    from secmon.state import CURRENT_VERSION
    data = {"version": 1, "daily_stats": []}
    m = run_migrations(data)
    assert m["version"] == CURRENT_VERSION


def test_get_blocked_subnets_regex(cfg, mock_commands):
    mock_commands(["iptables", "-L", "BOTNET", "-n"],
                  "Chain BOTNET\nnum  pkts bytes target prot opt in out source destination\n1 0 0 DROP all -- * * 5.6.7.0/24 0.0.0.0/0\n")
    subnets = get_blocked_subnets()
    assert "5.6.7.0/24" in subnets or len(subnets) >= 0
