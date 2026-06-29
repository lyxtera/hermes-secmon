"""Micro tests for remaining lines."""

import io
import json
from unittest.mock import patch

import secmon.checks as checks_mod
from secmon.anomaly import detect_anomalies
from secmon.checks import invalid_user, outbound
from secmon.config import METRIC_KEYS
from secmon.metrics import _collect_new_blocks


def test_anomaly_equal_mean_no_alert(cfg, frozen_time):
    state = {
        "baselines": {
            "ssh_failed_24h": {
                "mean": 100, "stdev": 10, "min": 0, "max": 200,
                "sample_size": 10, "calibrated_at": "2026-06-01T00:00:00Z",
            }
        },
        "last_flagged_anomalies": {},
        "last_anomalies": [],
        "monitor_state": {"stale_anomaly_counts": {}},
    }
    metrics = {k: 100 for k in METRIC_KEYS}
    assert detect_anomalies(metrics, state, cfg) == []


def test_invalid_user_skip_blocked_subnet(cfg, state, mock_commands):
    lines = [f"Invalid user u{i} from 10.0.0.1" for i in range(10)]
    mock_commands(["journalctl", "--since", "5 minutes ago"], "\n".join(lines))
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "DROP all -- 10.0.0.0/24\n")
    assert invalid_user.check(state, cfg) == []


def test_outbound_no_match(cfg, state, mock_commands):
    mock_commands(["ss", "-tnp", "state", "established"], "1.2.3.4:443 users:((")
    assert outbound.check(state, cfg) == []


def test_checks_all_fail(cfg, state):
    def boom(*a, **k):
        raise RuntimeError("x")
    orig = list(checks_mod.CHECKS)
    checks_mod.CHECKS.clear()
    checks_mod.CHECKS.extend([("a", boom), ("b", boom)])
    try:
        assert checks_mod.run_checks(state, cfg) == []
    finally:
        checks_mod.CHECKS.clear()
        checks_mod.CHECKS.extend(orig)


def test_process_host_mount(cfg, state, mock_commands):
    mock_commands(["ps", "-eo", "pid="], "1\n")
    mock_commands(["lsmod"], "")
    data = [{"Name": "/c", "HostConfig": {}, "Mounts": [{"Source": "/etc", "Destination": "/etc"}]}]
    mock_commands(["docker", "ps", "--format", "{{.ID}}"], "id1\n")
    mock_commands(["docker", "inspect", "id1"], json.dumps(data))
    mock_commands(["cat", "/proc/mounts"], "")
    mock_commands(["sysctl", "-n", "kernel.unprivileged_bpf_disabled"], "1")
    mock_commands(["which", "bpftool"], "")
    with patch("os.listdir", return_value=["1"]):
        with patch("os.readlink", side_effect=OSError):
            from secmon.audit import process
            findings = process.run(state, cfg)
    assert any("NC-1-hostmount" in f.check_id for f in findings)


def test_metrics_new_blocks_open_fail(cfg, monkeypatch):
    monkeypatch.setattr("os.path.isfile", lambda p: True)
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    data = {}
    _collect_new_blocks(cfg, data)
    assert data.get("new_blocked_subnets_24h", 0) == 0
