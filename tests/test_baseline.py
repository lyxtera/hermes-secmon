"""Baseline tests."""

from secmon.baseline import compute_baselines, record_sample, suggest_calibration
from secmon.config import METRIC_KEYS


def _samples(n, value=100):
    return [
        {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z", **{k: value for k in METRIC_KEYS}}
        for i in range(n)
    ]


def test_compute_baselines_bessel():
    stats = _samples(5, 100)
    stats[1]["ssh_failed_24h"] = 200
    bl = compute_baselines(stats, min_samples=4)
    assert "ssh_failed_24h" in bl
    assert bl["ssh_failed_24h"]["sample_size"] == 5
    assert bl["ssh_failed_24h"]["stdev"] > 0


def test_insufficient_samples():
    bl = compute_baselines(_samples(2), min_samples=4)
    assert bl == {}


def test_record_sample(cfg, state, frozen_time):
    state["daily_stats"] = []
    metrics = {k: 50 for k in METRIC_KEYS}
    assert record_sample(state, cfg, metrics)
    assert len(state["daily_stats"]) == 1
    assert state["monitor_state"]["last_record"] is not None


def test_suggest_calibration(cfg, state):
    state["daily_stats"] = _samples(15, 10000)
    suggestions = suggest_calibration(state, cfg)
    assert isinstance(suggestions, list)
