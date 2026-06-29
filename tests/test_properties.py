"""Property-based tests for statistical invariants."""

import math

import pytest
from hypothesis import given, strategies as st

from secmon.baseline import compute_baselines
from secmon.config import METRIC_KEYS


@given(st.lists(st.integers(min_value=0, max_value=100000), min_size=4, max_size=30))
def test_variance_non_negative(values):
    stats = [
        {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z", **{k: values[i] for k in METRIC_KEYS}}
        for i in range(len(values))
    ]
    bl = compute_baselines(stats, min_samples=4)
    for key, b in bl.items():
        assert b["stdev"] >= 0
        assert b["min"] <= b["mean"] <= b["max"]


@given(st.lists(st.integers(min_value=1, max_value=1000), min_size=4, max_size=20))
def test_identical_values_zero_stdev(values):
    v = values[0]
    stats = [
        {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z", **{k: v for k in METRIC_KEYS}}
        for i in range(len(values))
    ]
    bl = compute_baselines(stats, min_samples=4)
    assert bl["ssh_failed_24h"]["stdev"] == 0.0


def test_bessel_manual():
    values = [2, 4, 4, 4, 5, 5, 7, 9]
    n = len(values)
    mean = sum(values) / n
    stdev = math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1))
    stats = [
        {"timestamp": f"2026-06-{i+1:02d}T00:00:00Z", **{k: values[i] for k in METRIC_KEYS}}
        for i in range(n)
    ]
    bl = compute_baselines(stats, min_samples=4)
    assert abs(bl["ssh_failed_24h"]["stdev"] - stdev) < 0.001
