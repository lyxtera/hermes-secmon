"""Test fixtures."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from secmon.config import default_config, load_config
from secmon.shell import set_runner
from secmon.state import default_state, load_state, save_state


@pytest.fixture
def tmp_data_dir(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture
def cfg(tmp_data_dir, tmp_path):
    return load_config(
        overrides={
            "general": {
                "data_dir": tmp_data_dir,
                "log_file": str(tmp_path / "secmon.log"),
                "botnet_log_file": str(tmp_path / "botnet.log"),
            },
            "whitelist": {
                "own_ip": "203.0.113.1",
                "known_ssh_ips": ["203.0.113.1"],
            },
            "anomaly": {
                "baseline_min_samples": 4,
                "dedup_slot_hours": 0,
                "cache_ttl_seconds": 300,
                "cooldown_minutes": 60,
            },
            "dns": {"expected_nameservers": ["8.8.8.8"]},
            "realtime": {"fail2ban_min_new_bans": 1},
            "suspicious_ports": {
                "ranges": [[6660, 6700]],
                "specific": [4444, 5555, 8080, 9090, 2222],
            },
        }
    )


@pytest.fixture
def state(cfg):
    return default_state()


@pytest.fixture
def state_path(cfg):
    from secmon.config import state_file_path
    return state_file_path(cfg)


@pytest.fixture
def mock_commands():
    responses: dict[tuple, str] = {}

    def _key(args):
        return tuple(args[:3]) if len(args) >= 3 else tuple(args)

    def runner(args, **kwargs):
        result = MagicMock()
        result.returncode = 0
        key = tuple(args)
        stdout = responses.get(key, "")
        if not stdout:
            # match by command prefix
            for k, v in responses.items():
                if list(args[: len(k)]) == list(k):
                    stdout = v
                    break
        result.stdout = stdout
        result.stderr = ""
        return result

    def set_response(args, output: str):
        responses[tuple(args)] = output

    set_runner(runner)
    yield set_response
    set_runner(None)


@pytest.fixture
def mock_bpf_empty(mock_commands):
    """Stub bpftool JSON pipeline with no programs/maps."""

    def _apply():
        mock_commands(["which", "bpftool"], "/usr/sbin/bpftool")
        mock_commands(["cat", "/proc/sys/kernel/random/boot_id"], "boot-test\n")
        mock_commands(["bpftool", "-j", "prog", "show"], "[]")
        mock_commands(["bpftool", "-j", "map", "show"], "[]")
        mock_commands(["bpftool", "-j", "link", "show"], "[]")
        mock_commands(["bpftool", "-j", "cgroup", "show", "/"], "{}")
        mock_commands(["bpftool", "-j", "net", "show"], "{}")
        mock_commands(["auditctl", "-s"], "lost 0\nbacklog 0\n")

    _apply()
    return _apply


@pytest.fixture
def frozen_time(monkeypatch):
    fixed = datetime(2026, 6, 29, 10, 0, 0, tzinfo=timezone.utc)

    class FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz:
                return fixed.astimezone(tz)
            return fixed.replace(tzinfo=None)

    monkeypatch.setattr("secmon.utils.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.anomaly.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.alerts.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.baseline.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.metrics.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.metrics.utcnow", lambda: fixed)
    monkeypatch.setattr("secmon.utils.utcnow_iso", lambda: "2026-06-29T10:00:00Z")
    return fixed
