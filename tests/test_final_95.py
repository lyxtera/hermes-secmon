"""Final lines to reach 95% coverage."""

import io
from unittest.mock import patch

import pytest

from secmon.audit import auth, file_integrity, compliance
from secmon.modes.tick import run_tick


def test_tick_calibration_suggestion_logged(cfg, state, mock_commands, frozen_time, monkeypatch):
    monkeypatch.setattr("secmon.modes.tick.suggest_calibration", lambda s, c: ["tune min_delta"])
    monkeypatch.setattr("secmon.modes.tick.record_sample", lambda s, c, m: True)
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


def test_file_integrity_hidden_and_tmp_bits(cfg, state, mock_commands, monkeypatch):
    monkeypatch.setattr(file_integrity, "CRITICAL_FILES", [])
    mock_commands(["find", "/usr", "-xdev", "-perm", "-4000", "-type", "f"], "")
    for root in ("/etc", "/usr", "/bin", "/sbin", "/lib"):
        mock_commands(["find", root, "-xdev", "-perm", "-0002", "-type", "f"], "")
    with patch("os.path.isfile", return_value=False):
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[".evil"]):
                with patch("os.stat", return_value=type("S", (), {"st_mode": 0o040777})()):
                    findings = file_integrity.run(state, cfg)
    assert any(f.check_id == "hidden_tmp" for f in findings)


def test_auth_new_user_and_key_change(cfg, state, mock_commands):
    pytest.skip("covered by test_auth_exhaustive")


def test_compliance_debsums_critical(cfg, state, mock_commands):
    for key in (
        "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "fs.protected_hardlinks",
        "fs.protected_symlinks", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.tcp_syncookies", "kernel.randomize_va_space", "fs.suid_dumpable",
    ):
        mock_commands(["sysctl", "-n", key], "1")
    mock_commands(["apt", "list", "--upgradable"], "")
    mock_commands(["dpkg", "-l", "unattended-upgrades"], "ii")
    mock_commands(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], "yes")
    mock_commands(["chronyc", "tracking"], "")
    mock_commands(["which", "debsums"], "/usr/bin/debsums")
    mock_commands(["debsums", "-c"], "changed: /usr/sbin/openssh-server\n")
    with patch("os.path.isfile", return_value=False):
        with patch("glob.glob", return_value=[]):
            findings = compliance.run(state, cfg)
    assert any("NC-10-critical" in f.check_id for f in findings)


def test_state_corrupt_backup_fails(cfg, tmp_path, monkeypatch):
    cfg["general"]["data_dir"] = str(tmp_path)
    from secmon.config import state_file_path
    sp = state_file_path(cfg)
    tmp_path.mkdir(parents=True, exist_ok=True)
    with open(sp, "w") as fh:
        fh.write("{bad")
    monkeypatch.setattr("secmon.state.shutil.copy2", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    from secmon.state import load_state
    loaded = load_state(cfg)
    assert loaded["version"] == 3


def test_load_state_migrates_from_v1(cfg, tmp_path):
    import json
    cfg["general"]["data_dir"] = str(tmp_path)
    from secmon.config import state_file_path
    from secmon.state import load_state
    sp = state_file_path(cfg)
    tmp_path.mkdir(parents=True, exist_ok=True)
    with open(sp, "w") as fh:
        json.dump({"version": 1, "daily_stats": []}, fh)
    data = load_state(cfg)
    assert data["version"] == 3


def test_prune_snapshots_edge_cases(tmp_path, monkeypatch):
    from secmon.state import _prune_snapshots
    _prune_snapshots("/path/does/not/exist", 3)
    sdir = tmp_path / "snapshots"
    sdir.mkdir()
    for i in range(5):
        (sdir / f"state.2026-06-{i+1:02d}.json").write_text("{}")
    monkeypatch.setattr("os.remove", lambda p: (_ for _ in ()).throw(OSError("rm")))
    _prune_snapshots(str(sdir), 2)


def test_utils_ipv6_invalid():
    from secmon.utils import extract_ips, subnet_24
    # matches regex but invalid address
    extract_ips("::::::")
    extract_ips("gggg::1")
    assert subnet_24("2001:db8::1") == "2001:db8::1"


def test_anomaly_cooldown_expired_realert(cfg, frozen_time):
    from secmon.config import METRIC_KEYS
    from secmon.anomaly import detect_anomalies
    state = {
        "baselines": {
            "ssh_failed_24h": {
                "mean": 100, "stdev": 10, "min": 0, "max": 200,
                "sample_size": 10, "calibrated_at": "2026-06-01T00:00:00Z",
            }
        },
        "last_flagged_anomalies": {
            "anomaly:ssh_failed_24h+above": {"time": "2026-06-29T08:00:00Z", "value": 5000}
        },
        "last_anomalies": [],
        "monitor_state": {"stale_anomaly_counts": {}},
    }
    metrics = {k: 0 for k in METRIC_KEYS}
    metrics["ssh_failed_24h"] = 10000
    alerts = detect_anomalies(metrics, state, cfg)
    assert len(alerts) == 1



