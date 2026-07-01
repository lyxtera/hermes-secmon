"""Persistent state: atomic writes, migration, snapshots."""

from __future__ import annotations

import json
import logging
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from secmon.config import METRIC_KEYS, snapshot_dir, state_file_path
from secmon.utils import utcnow, utcnow_iso

logger = logging.getLogger("secmon.state")

CURRENT_VERSION = 3


def default_state() -> dict[str, Any]:
    now = utcnow_iso()
    return {
        "version": CURRENT_VERSION,
        "created_at": now,
        "updated_at": now,
        "daily_stats": [],
        "baselines": {},
        "audit_baseline": {
            "file_hashes": {},
            "suid_cache": [],
            "known_ports": {},
            "users": {},
            "groups": {},
            "services": [],
            "authorized_keys_hashes": {},
            "persistence": {},
            "timers": [],
            "bpf_programs": [],
            "bpf_maps": [],
            "sysctl": {},
            "self_protection": {},
        },
        "last_flagged_anomalies": {},
        "last_anomalies": [],
        "last_anomaly_check": None,
        "dedup_store": {},
        "monitor_state": {
            "last_f2b_snapshot": "",
            "known_ports_output": "",
            "last_record": None,
            "last_daily": None,
            "last_botnet_check": None,
            "active_ssh_sessions": {},
            "stale_anomaly_counts": {},
        },
        "migration_history": [],
        "metric_cache": {"timestamp": None, "values": {}},
        "last_audit_findings": [],
        "last_audit_score": 0,
    }


def _migrate_v1_to_v2(data: dict) -> dict:
    data.setdefault("dedup_store", {})
    data.setdefault("last_audit_findings", [])
    data.setdefault("last_audit_score", 0)
    ab = data.setdefault("audit_baseline", {})
    ab.setdefault("users", {})
    ab.setdefault("groups", {})
    ab.setdefault("services", [])
    ab.setdefault("authorized_keys_hashes", {})
    ms = data.setdefault("monitor_state", {})
    ms.setdefault("active_ssh_sessions", {})
    ms.setdefault("stale_anomaly_counts", {})
    data["version"] = 2
    data.setdefault("migration_history", []).append(
        {"from_version": 1, "to_version": 2, "at": utcnow_iso()}
    )
    return data


def _migrate_v2_to_v3(data: dict) -> dict:
    data.setdefault("metric_cache", {"timestamp": None, "values": {}})
    data["version"] = 3
    data.setdefault("migration_history", []).append(
        {"from_version": 2, "to_version": 3, "at": utcnow_iso()}
    )
    return data


def run_migrations(data: dict) -> dict:
    version = data.get("version", 1)
    if version < 2:
        data = _migrate_v1_to_v2(data)
    if data.get("version", 2) < 3:
        data = _migrate_v2_to_v3(data)
    return data


def load_state(cfg: dict, path: str | None = None) -> dict:
    spath = path or state_file_path(cfg)
    if not os.path.isfile(spath):
        return default_state()
    try:
        with open(spath, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError:
        logger.error("state file corrupt, using defaults: %s", spath)
        backup = f"{spath}.corrupt.{int(utcnow().timestamp())}"
        try:
            shutil.copy2(spath, backup)
        except OSError:
            pass
        return default_state()
    if data.get("version", 1) < CURRENT_VERSION:
        data = run_migrations(data)
    return data


def _atomic_write(path: str, content: str) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _prune_snapshots(sdir: str, keep: int) -> None:
    if not os.path.isdir(sdir):
        return
    files = sorted(
        [f for f in os.listdir(sdir) if f.startswith("state.") and f.endswith(".json")],
        reverse=True,
    )
    for old in files[keep:]:
        try:
            os.remove(os.path.join(sdir, old))
        except OSError:
            pass


def save_state(cfg: dict, data: dict, path: str | None = None) -> bool:
    spath = path or state_file_path(cfg)
    data["updated_at"] = utcnow_iso()
    data["version"] = CURRENT_VERSION
    try:
        _atomic_write(spath, json.dumps(data, indent=2, sort_keys=True))
        sdir = snapshot_dir(cfg)
        os.makedirs(sdir, exist_ok=True)
        today = utcnow().strftime("%Y-%m-%d")
        snap = os.path.join(sdir, f"state.{today}.json")
        _atomic_write(snap, json.dumps(data, indent=2, sort_keys=True))
        keep = cfg["general"].get("snapshot_retention_days", 7)
        _prune_snapshots(sdir, keep)
        return True
    except OSError as exc:
        logger.error("failed to save state: %s", exc)
        return False


def make_daily_sample(metrics: dict[str, int]) -> dict:
    entry: dict[str, Any] = {"timestamp": utcnow_iso()}
    for key in METRIC_KEYS:
        entry[key] = int(metrics.get(key, 0))
    return entry


def trim_daily_stats(daily_stats: list, max_days: int) -> list:
    cutoff = utcnow() - timedelta(days=max_days)
    result = []
    for entry in daily_stats:
        ts = entry.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt >= cutoff:
                result.append(entry)
        except ValueError:
            result.append(entry)
    return result
