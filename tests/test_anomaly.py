"""Anomaly detection tests."""

from secmon.anomaly import detect_anomalies
from secmon.config import METRIC_KEYS


def _baseline_state(mean=100, stdev=10):
    return {
        "baselines": {
            "ssh_failed_24h": {
                "mean": mean,
                "stdev": stdev,
                "min": mean - stdev,
                "max": mean + stdev,
                "sample_size": 10,
                "calibrated_at": "2026-06-01T00:00:00Z",
            }
        },
        "last_flagged_anomalies": {},
        "last_anomalies": [],
        "monitor_state": {"stale_anomaly_counts": {}},
    }


def test_both_gates_pass(cfg, frozen_time):
    state = _baseline_state(100, 10)
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 10000
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 1
    assert alerts[0].severity in ("MEDIUM", "HIGH", "CRITICAL")


def test_sigma_pass_delta_fail(cfg, frozen_time):
    state = _baseline_state(100, 10)
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 150  # high sigma but low delta
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 0


def test_zero_stdev(cfg, frozen_time):
    state = _baseline_state(100, 0)
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 6000
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 1


def test_cooldown_suppresses(cfg, frozen_time):
    state = _baseline_state(100, 10)
    state["last_flagged_anomalies"]["anomaly:ssh_failed_24h+above"] = {
        "time": "2026-06-29T09:30:00Z",
        "value": 10000,
    }
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 10000
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 0


def test_stale_baseline(cfg, frozen_time):
    state = _baseline_state(100, 10)
    state["monitor_state"]["stale_anomaly_counts"]["ssh_failed_24h"] = {"count": 3, "value": 10000}
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 10000
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 0
