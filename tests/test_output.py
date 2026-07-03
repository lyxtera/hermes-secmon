"""Output formatter tests."""

from secmon.config import METRIC_KEYS
from secmon.output import (
    FINDING_DIVIDER,
    _render_cta,
    format_audit_markdown,
    format_daily_digest,
    format_status,
)


def test_format_status(cfg, state):
    metrics = {k: 0 for k in METRIC_KEYS}
    out = format_status(state, cfg, metrics)
    assert "Security Monitor Status" in out


def test_format_daily(cfg, state):
    metrics = {k: 5 for k in METRIC_KEYS}
    out = format_daily_digest(state, metrics)
    assert "Daily Security Digest" in out


def test_format_daily_elevated_ctas():
    state = {
        "baselines": {
            "ssh_failed_24h": {"mean": 100, "stdev": 10, "sample_size": 7, "min": 80, "max": 120},
        },
        "last_anomalies": [],
    }
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 500
    out = format_daily_digest(state, metrics)
    assert "What to check" in out
    assert "journalctl -u ssh" in out
    assert "| Metric |" not in out


def test_format_audit_markdown_cta_and_divider():
    result = {
        "total_score": 10,
        "finding_count": 1,
        "critical_count": 0,
        "high_count": 1,
        "findings": [
            {
                "severity": "HIGH",
                "check_id": "proc_hollow_anon",
                "message": "Anonymous executable memory",
                "layer": 3,
                "detail": {"pid": 1234, "path": "/proc/1234/exe"},
            }
        ],
    }
    out = format_audit_markdown(result)
    assert FINDING_DIVIDER in out
    assert "▶ `cat /proc/1234/maps | grep anon`" in out
    assert "---" not in out.split("▶")[0]  # no markdown hr between findings


def test_render_cta_substitutes_placeholders():
    cta = _render_cta(
        "new_listen_port",
        {"port": 4444, "path": "/ignored"},
    )
    assert cta == "ss -tlnp | grep 4444"
