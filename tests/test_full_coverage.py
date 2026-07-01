"""Targeted tests for remaining uncovered branches."""

import json
import os
from unittest.mock import patch

import pytest

from secmon.alerts import Alert, dispatch, is_duplicate
from secmon.anomaly import detect_anomalies, _severity_from_deviation
from secmon.audit import file_integrity
from secmon.baseline import record_sample, suggest_calibration
from secmon.botnet import ensure_botnet_chain, _persist_rules
from secmon.checks import run_checks
from secmon.checks import fail2ban, outbound, ssh_session
from secmon.config import _coerce, _deep_merge, load_config, get_threshold
from secmon.metrics import collect_metrics, invalidate_cache, _collect_new_blocks
from secmon.shell import run_cmd
from secmon.state import save_state
from secmon.utils import extract_ips, sanitize_message, subnet_24


def test_coerce_types():
    assert _coerce("true") is True
    assert _coerce("42") == 42
    assert _coerce("3.14") == 3.14
    assert _coerce("hello") == "hello"


def test_deep_merge():
    base = {"a": {"b": 1}}
    assert _deep_merge(base, {"a": {"c": 2}})["a"]["b"] == 1


def test_severity_from_deviation():
    assert _severity_from_deviation(5, 2) == "CRITICAL"
    assert _severity_from_deviation(3.5, 2) == "HIGH"
    assert _severity_from_deviation(2.5, 2) == "MEDIUM"
    assert _severity_from_deviation(1.5, 2) is None


def test_anomaly_below_direction(cfg, frozen_time):
    from secmon.config import METRIC_KEYS
    state = {
        "baselines": {
            "ssh_failed_24h": {
                "mean": 10000, "stdev": 100, "min": 0, "max": 20000,
                "sample_size": 10, "calibrated_at": "2026-06-01T00:00:00Z",
            }
        },
        "last_flagged_anomalies": {},
        "last_anomalies": [],
        "monitor_state": {"stale_anomaly_counts": {}},
    }
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 100
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 1


def test_record_sample_dedup_slot(cfg, state, frozen_time):
    from secmon.config import METRIC_KEYS
    cfg["anomaly"]["dedup_slot_hours"] = 6
    state["monitor_state"]["last_record"] = "2026-06-29T09:00:00Z"
    metrics = {k: 1 for k in METRIC_KEYS}
    assert record_sample(state, cfg, metrics) is False


def test_collect_new_blocks_log(cfg, tmp_path):
    logf = tmp_path / "botnet.log"
    logf.write_text("2026-06-29T09:00:00Z BLOCKED 1.2.3.0/24\n")
    cfg["general"]["botnet_log_file"] = str(logf)
    metrics = {}
    _collect_new_blocks(cfg, metrics)
    assert metrics["new_blocked_subnets_24h"] == 1


def test_file_integrity_find(cfg, state, mock_commands):
    mock_commands(["find", "/usr", "-xdev", "-perm", "-4000", "-type", "f"], "/usr/bin/evil\n")
    for root in ("/etc", "/usr", "/bin", "/sbin", "/lib"):
        mock_commands(["find", root, "-xdev", "-perm", "-0002", "-type", "f"], "")
    findings = file_integrity.run(state, cfg)
    assert any(f.check_id == "unexpected_suid" for f in findings)


def test_fail2ban_in_list_parsing(cfg, state, mock_commands):
    mock_commands(
        ["fail2ban-client", "status", "sshd"],
        "Status for the jail: sshd\n|- Filter\n|- Currently banned:\t2\n|- Banned IP list:\t9.9.9.9 8.8.8.8\n",
    )
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    state["monitor_state"]["last_f2b_snapshot"] = ""
    alerts = fail2ban.check(state, cfg)
    assert len(alerts) >= 1


def test_outbound_port_range(cfg, state, mock_commands):
    mock_commands(["ss", "-tnp", "state", "established"], "1.2.3.4:6666 users:((")
    alerts = outbound.check(state, cfg)
    assert len(alerts) == 1


def test_ssh_whitelisted(cfg, state, mock_commands):
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "peer 203.0.113.1:5555\n")
    alerts = ssh_session.check(state, cfg)
    assert alerts == []


def test_check_registry_exception(cfg, state, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("fail")
    monkeypatch.setattr("secmon.checks.fail2ban.check", boom)
    findings = run_checks(state, cfg)
    assert findings == []


def test_save_state_disk_error(cfg, state, monkeypatch):
    monkeypatch.setattr("secmon.state._atomic_write", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    assert save_state(cfg, state) is False


def test_env_override_sigma_below(monkeypatch, tmp_path):
    monkeypatch.setenv("SECMON_OVERRIDE_SSH_FAILED_24H_SIGMA_BELOW", "1.5")
    cfg = load_config(overrides={"general": {"data_dir": str(tmp_path)}})
    th = get_threshold(cfg, "ssh_failed_24h")
    assert th.get("sigma_below") == 1.5


def test_extract_ipv6():
    ips = extract_ips("from 2001:db8::1 port")
    assert any(":" in ip for ip in ips)


def test_sanitize_truncation():
    assert len(sanitize_message("a" * 1000)) <= 503
