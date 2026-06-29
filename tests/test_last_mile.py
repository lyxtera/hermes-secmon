"""Last mile coverage tests."""

import runpy
import sys
from unittest.mock import patch

import pytest

from secmon.alerts import Alert, is_duplicate, _log_alert
from secmon.anomaly import detect_anomalies
from secmon.audit import __init__ as audit_init
from secmon.baseline import compute_baselines
from secmon.botnet import detect_and_block
from secmon.config import METRIC_KEYS, default_config
from secmon.modes.tick import run_tick
from secmon.state import _prune_snapshots, save_state
from secmon.utils import sanitize_message, subnet_24


def test_anomaly_below_no_sigma(cfg, frozen_time):
    state = {
        "baselines": {
            "ssh_invalid_user_24h": {
                "mean": 100, "stdev": 5, "min": 0, "max": 200,
                "sample_size": 10, "calibrated_at": "2026-06-01T00:00:00Z",
            }
        },
        "last_flagged_anomalies": {},
        "last_anomalies": [],
        "monitor_state": {"stale_anomaly_counts": {}},
    }
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_invalid_user_24h"] = 50
    alerts = detect_anomalies(metrics, state, cfg)
    assert alerts == []


def test_alerts_dedup_no_timestamp(state):
    state["dedup_store"]["f2b:1.1.1.1"] = {"time": "bad-ts"}
    a = Alert("HIGH", "f", "m", "f2b:1.1.1.1", {})
    assert is_duplicate(a, state) is False


def test_alerts_log_write_fail(cfg, tmp_path, monkeypatch):
    cfg["general"]["log_file"] = str(tmp_path / "no" / "log")
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    _log_alert(cfg, Alert("HIGH", "t", "m", "k", {}))


def test_baseline_single_sample():
    stats = [{"timestamp": "2026-06-01T00:00:00Z", **{k: 1 for k in METRIC_KEYS}}]
    bl = compute_baselines(stats, min_samples=1)
    assert bl["ssh_failed_24h"]["stdev"] == 0.0


def test_prune_snapshots(tmp_path):
    sdir = tmp_path / "snapshots"
    sdir.mkdir()
    for i in range(10):
        (sdir / f"state.2026-06-{i+1:02d}.json").write_text("{}")
    _prune_snapshots(str(sdir), 3)
    assert len(list(sdir.iterdir())) == 3


def test_tick_daily_branch(cfg, state, mock_commands, frozen_time):
    state["monitor_state"]["last_daily"] = None
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
    from secmon.metrics import invalidate_cache
    invalidate_cache()
    run_tick(state, cfg)


def test_audit_init_layer_exception(cfg, state, monkeypatch):
    from secmon.audit import run_audit
    def boom(*a, **k):
        raise RuntimeError("layer fail")
    monkeypatch.setattr("secmon.audit.file_integrity.run", boom)
    result = run_audit(state, cfg)
    assert "file_integrity" in result["layers"]


def test_default_config_linux(monkeypatch):
    monkeypatch.setattr("secmon.config.platform.system", lambda: "Linux")
    cfg = default_config()
    assert cfg["general"]["data_dir"] == "/var/lib/secmon"


def test_tick_suggest_calibration(cfg, state, mock_commands, frozen_time):
    from secmon.config import METRIC_KEYS
    state["monitor_state"]["last_record"] = "2026-06-20T00:00:00Z"
    state["daily_stats"] = [
        {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z", **{k: 10000 + i * 500 for k in METRIC_KEYS}}
        for i in range(15)
    ]
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
    from secmon.metrics import invalidate_cache
    invalidate_cache()
    run_tick(state, cfg)


def test_state_save_snapshot_prune_error(cfg, state, tmp_path, monkeypatch):
    cfg["general"]["data_dir"] = str(tmp_path)
    monkeypatch.setattr("secmon.state._prune_snapshots", lambda *a, **k: None)
    assert save_state(cfg, state) is True


def test_utils_extract_invalid_ip():
    from secmon.utils import extract_ips, is_private_or_loopback
    assert extract_ips("999.999.999.999") == []
    assert is_private_or_loopback("not-an-ip") is False


def test_botnet_whitelist_own_prefix(cfg, state, mock_commands):
    cfg["whitelist"]["own_ip"] = "203.0.113.50"
    lines = ["Failed password from 203.0.113.99"] * 600
    mock_commands(["journalctl", "--since", "24 hours ago"], "\n".join(lines))
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    from secmon.botnet import detect_and_block
    assert detect_and_block(state, cfg) == []

