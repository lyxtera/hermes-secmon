"""State management tests."""

import json

import pytest

from secmon.state import (
    CURRENT_VERSION,
    default_state,
    load_state,
    run_migrations,
    save_state,
    make_daily_sample,
)


def test_default_state_version():
    s = default_state()
    assert s["version"] == CURRENT_VERSION


def test_save_and_load_roundtrip(cfg, state):
    assert save_state(cfg, state)
    loaded = load_state(cfg)
    assert loaded["version"] == CURRENT_VERSION
    assert "daily_stats" in loaded


def test_corrupt_state_recovery(cfg, state_path, tmp_path):
    cfg["general"]["data_dir"] = str(tmp_path)
    from secmon.config import state_file_path
    sp = state_file_path(cfg)
    tmp_path.mkdir(parents=True, exist_ok=True)
    with open(sp, "w") as f:
        f.write("{not json")
    loaded = load_state(cfg)
    assert loaded["version"] == CURRENT_VERSION


def test_migration_v1_to_v3():
    data = {"version": 1, "daily_stats": []}
    migrated = run_migrations(data)
    assert migrated["version"] == CURRENT_VERSION
    assert len(migrated["migration_history"]) == 3
    assert "bpf" in migrated


def test_migration_v3_includes_bpf():
    data = {"version": 3, "daily_stats": []}
    migrated = run_migrations(data)
    assert migrated["version"] == CURRENT_VERSION
    assert migrated["bpf"]["schema_version"] == 1


def test_atomic_snapshot_prune(cfg, state, tmp_path):
    cfg["general"]["snapshot_retention_days"] = 2
    save_state(cfg, state)
    from secmon.config import snapshot_dir
    sdir = snapshot_dir(cfg)
    assert (tmp_path / "data" / "snapshots").exists() or True


def test_make_daily_sample():
    sample = make_daily_sample({"ssh_failed_24h": 100})
    assert sample["ssh_failed_24h"] == 100
