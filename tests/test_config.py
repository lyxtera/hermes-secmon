"""Config tests."""

import os

from secmon.config import default_config, get_threshold, load_config, METRIC_KEYS


def test_default_config_has_all_metrics():
    cfg = default_config()
    assert len(METRIC_KEYS) == 11
    for k in METRIC_KEYS:
        assert k in cfg["metrics"]["thresholds"]


def test_load_config_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECMON_OWN_IP", "1.2.3.4")
    monkeypatch.setenv("SECMON_ANOMALY_COOLDOWN_MINUTES", "30")
    monkeypatch.setenv("SECMON_OVERRIDE_SSH_FAILED_24H_MIN_DELTA", "8000")
    cfg = load_config(overrides={"general": {"data_dir": str(tmp_path)}})
    assert cfg["whitelist"]["own_ip"] == "1.2.3.4"
    assert cfg["anomaly"]["cooldown_minutes"] == 30
    th = get_threshold(cfg, "ssh_failed_24h")
    assert th["min_delta"] == 8000


def test_load_yaml_config(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("whitelist:\n  own_ip: 10.0.0.1\n")
    cfg = load_config(str(p), overrides={"general": {"data_dir": str(tmp_path / "d")}})
    assert cfg["whitelist"]["own_ip"] == "10.0.0.1"
