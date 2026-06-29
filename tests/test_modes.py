"""Mode integration tests."""

from secmon.__main__ import main
from secmon.state import load_state, save_state
from secmon.metrics import invalidate_cache


def _mock_all(mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["fail2ban-client", "status", "sshd"], "Currently banned: 0\n")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "")
    mock_commands(["ss", "-tlnp"], "State\n0.0.0.0:22\n")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    mock_commands(["journalctl", "--since", "5 minutes ago"], "")
    mock_commands(["journalctl", "-k", "--since", "1 hour ago"], "")
    mock_commands(["ss", "-tnp", "dport", "=", ":22"], "")
    mock_commands(["iptables", "-N", "BOTNET"], "")
    mock_commands(["iptables", "-L", "INPUT", "-n"], "BOTNET")


def test_status_mode(cfg, mock_commands, tmp_path, monkeypatch):
    monkeypatch.setenv("SECMON_DATA_DIR", cfg["general"]["data_dir"])
    _mock_all(mock_commands)
    invalidate_cache()
    rc = main(["--status", "--config", "/nonexistent"])
    assert rc == 0


def test_record_mode(cfg, mock_commands, monkeypatch):
    monkeypatch.setenv("SECMON_DATA_DIR", cfg["general"]["data_dir"])
    cfg_path = cfg["general"]["data_dir"]
    _mock_all(mock_commands)
    invalidate_cache()
    rc = main(["--record"])
    assert rc == 0
    state = load_state(cfg)
    assert len(state["daily_stats"]) >= 1


def test_check_mode_silent(cfg, mock_commands, monkeypatch, capsys):
    monkeypatch.setenv("SECMON_DATA_DIR", cfg["general"]["data_dir"])
    _mock_all(mock_commands)
    invalidate_cache()
    rc = main(["--check"])
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_daily_mode(cfg, mock_commands, monkeypatch, capsys):
    monkeypatch.setenv("SECMON_DATA_DIR", cfg["general"]["data_dir"])
    _mock_all(mock_commands)
    invalidate_cache()
    rc = main(["--daily"])
    assert rc == 0
    assert "Daily Security Digest" in capsys.readouterr().out
