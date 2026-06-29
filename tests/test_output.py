"""Output formatter tests."""

from secmon.output import format_status, format_daily_digest


def test_format_status(cfg, state):
    metrics = {k: 0 for k in __import__("secmon.config", fromlist=["METRIC_KEYS"]).METRIC_KEYS}
    out = format_status(state, cfg, metrics)
    assert "Security Monitor Status" in out


def test_format_daily(cfg, state):
    metrics = {k: 5 for k in __import__("secmon.config", fromlist=["METRIC_KEYS"]).METRIC_KEYS}
    out = format_daily_digest(state, metrics)
    assert "Daily Security Digest" in out
