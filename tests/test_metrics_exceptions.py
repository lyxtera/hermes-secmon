"""Trigger metrics exception handlers."""

import pytest

from secmon.metrics import (
    _collect_ssh_metrics,
    _collect_f2b,
    _collect_botnet_rules,
    _collect_kernel,
    _collect_network,
    _collect_new_blocks,
    collect_metrics_from_state,
)
from secmon.shell import set_runner


def test_metrics_exception_handlers(cfg, monkeypatch):
    def boom(args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr("secmon.metrics.run_cmd_safe", boom)
    m = {}
    _collect_ssh_metrics(m)
    _collect_f2b(m)
    _collect_botnet_rules(m)
    _collect_kernel(m)
    _collect_network(m)
    _collect_new_blocks(cfg, m)
    assert m.get("ssh_failed_24h", 0) == 0


def test_collect_metrics_force_path(cfg, state, mock_commands, frozen_time):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["fail2ban-client", "status", "sshd"], "")
    mock_commands(["iptables", "-L", "BOTNET", "-n"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago"], "")
    mock_commands(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], "")
    mock_commands(["ss", "-tlnp"], "")
    mock_commands(["ss", "-tnp", "state", "established"], "")
    from secmon.metrics import invalidate_cache
    invalidate_cache()
    collect_metrics_from_state(cfg, state, force=True)
