"""Logs layer coverage."""

import time
from unittest.mock import patch

import pytest

from secmon.audit import logs


def test_logs_file_checks(cfg, state, mock_commands, frozen_time):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["systemctl", "--failed", "--no-legend"], "")
    mock_commands(["journalctl", "--list-boots"], "0\n")
    mock_commands(["journalctl", "--verify"], "FAIL corrupt\n")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"], "")
    mock_commands(["systemctl", "is-active", "auditd"], "active\n")
    with patch("os.path.isfile", return_value=False):
        findings = logs.run(state, cfg)
    assert any(f.check_id == "NC-11-verify" for f in findings)


def test_logs_stale_auth_syslog(cfg, state, mock_commands, frozen_time):
    mock_commands(["journalctl", "--since", "24 hours ago"], "")
    mock_commands(["systemctl", "--failed", "--no-legend"], "")
    mock_commands(["journalctl", "--list-boots"], "")
    mock_commands(["journalctl", "--verify"], "")
    mock_commands(["journalctl", "--since", "48 hours ago", "-o", "short-iso"], "")
    mock_commands(["systemctl", "is-active", "auditd"], "inactive")
    from datetime import datetime, timezone
    stale = datetime(2026, 6, 29, 6, 0, 0, tzinfo=timezone.utc).timestamp()

    def isfile(p):
        return str(p) in ("/var/log/auth.log", "/var/log/syslog")

    with patch("os.path.isfile", side_effect=isfile):
        with patch("os.path.getmtime", return_value=stale):
            with patch("os.path.getsize", return_value=500):
                findings = logs.run(state, cfg)
    assert any(f.check_id == "log_stale" for f in findings)

