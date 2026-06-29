"""Metrics tests."""

from secmon.metrics import collect_metrics, invalidate_cache
from secmon.config import METRIC_KEYS as KEYS


def test_collect_metrics_all_keys(cfg, mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "Failed password\nInvalid user\nfrom 1.2.3.4\n")
    mock_commands(["fail2ban-client", "status", "sshd"], "Currently banned: 2\n")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "DROP all -- 1.0.0.0/24\n")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "martian source\n")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "error line\n")
    mock_commands(["ss", "-tlnp"], "State Recv-Q\n0.0.0.0:22\n")
    mock_commands(["ss", "-tnp", "state", "established"], "State Recv-Q\n1.2.3.4:22\n")
    invalidate_cache()
    m = collect_metrics(cfg, force=True)
    assert set(m.keys()) == set(KEYS)
    assert m["ssh_failed_24h"] == 1
    assert m["f2b_banned_count"] == 2


def test_metrics_cache(cfg, mock_commands):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["fail2ban-client", "status", "sshd"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "")
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    invalidate_cache()
    m1 = collect_metrics(cfg, force=True)
    m2 = collect_metrics(cfg)
    assert m1 == m2
