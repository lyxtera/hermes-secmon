"""Configuration: defaults → YAML file → SECMON_* env vars."""

from __future__ import annotations

import copy
import os
import platform
from pathlib import Path
from typing import Any

import yaml

METRIC_KEYS = [
    "ssh_failed_24h",
    "ssh_invalid_user_24h",
    "unique_attacker_ips",
    "unique_attacker_subnets",
    "f2b_banned_count",
    "botnet_chain_rules",
    "martian_packets_24h",
    "new_blocked_subnets_24h",
    "kernel_errors_24h",
    "listening_ports_count",
    "established_conns",
]

DEFAULT_METRIC_THRESHOLDS: dict[str, dict[str, float | int | None]] = {
    "ssh_failed_24h": {"sigma_above": 2.5, "sigma_below": 2.0, "min_delta": 5000},
    "ssh_invalid_user_24h": {"sigma_above": 2.5, "sigma_below": None, "min_delta": 2000},
    "unique_attacker_ips": {"sigma_above": 2.5, "sigma_below": None, "min_delta": 100},
    "unique_attacker_subnets": {"sigma_above": 2.5, "sigma_below": None, "min_delta": 80},
    "f2b_banned_count": {"sigma_above": 4.0, "sigma_below": None, "min_delta": 20},
    "botnet_chain_rules": {"sigma_above": 4.0, "sigma_below": None, "min_delta": 5},
    "martian_packets_24h": {"sigma_above": 3.0, "sigma_below": None, "min_delta": 10},
    "new_blocked_subnets_24h": {"sigma_above": 3.0, "sigma_below": None, "min_delta": 5},
    "kernel_errors_24h": {"sigma_above": 3.0, "sigma_below": None, "min_delta": 3},
    "listening_ports_count": {"sigma_above": 3.0, "sigma_below": None, "min_delta": 2},
    "established_conns": {"sigma_above": 4.0, "sigma_below": None, "min_delta": 8},
}


def _default_data_dir() -> str:
    if platform.system() == "Linux":
        return "/var/lib/secmon"
    return str(Path.home() / ".secmon")


def default_config() -> dict[str, Any]:
    return {
        "general": {
            "data_dir": _default_data_dir(),
            "log_file": "/var/log/security-monitor.log",
            "botnet_log_file": "/var/log/secmon-botnet.log",
            "snapshot_retention_days": 7,
            "config_path": os.environ.get("SECMON_CONFIG_PATH", ""),
        },
        "whitelist": {
            "own_ip": "",
            "known_ssh_ips": [],
            "network_prefixes": [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
            ],
            "docker_container_whitelist": [],
            "hidden_tmp_entries": [],
            "tmpfs_mounts": [],
            "secret_exclude_paths": [],
            "proc_hollow_exclude_pids": [],
            "persist_exclude_prefixes": [],
        },
        "anomaly": {
            "baseline_min_samples": 4,
            "max_baseline_days": 30,
            "dedup_slot_hours": 6,
            "cache_ttl_seconds": 300,
            "cooldown_minutes": 60,
        },
        "realtime": {
            "ssh_brute_force_threshold": 10,
            "invalid_user_threshold": 5,
            "kernel_error_threshold": 3,
        },
        "botnet": {
            "lookback_hours": 24,
            "min_ips_per_subnet": 3,
            "min_hits_per_subnet": 100,
            "solo_min_hits": 500,
            "bulletproof_prefixes": [],
        },
        "hermes": {
            "deliver_target": "",
            "min_severity": "HIGH",
        },
        "suspicious_ports": {
            "ranges": [[6660, 6700]],
            "specific": [4444, 5555, 8080, 9090, 2222],
        },
        "dns": {
            "expected_nameservers": [],
        },
        "installation": {
            "source_dir": "/opt/secmon",
            "cli_path": "/usr/local/bin/secmon",
            "cron_marker": "secmon --tick",
            "hermes_cron_job": "secmon-tick",
            "venv_dir": "/opt/secmon/venv",
        },
        "metrics": {
            "thresholds": copy.deepcopy(DEFAULT_METRIC_THRESHOLDS),
            "overrides": {},
        },
        "hardening": {
            "ssh_tier": 1,
            "skip_root_login_check": False,
            "skip_password_auth_check": False,
            "skip_fw_policy_check": False,
            "skip_kernel_modules_check": False,
        },
        "sysctl": {
            "expected_values": {},
        },
    }


def _deep_merge(base: dict, overlay: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _set_nested(cfg: dict, keys: list[str], value: Any) -> None:
    cur = cfg
    for k in keys[:-1]:
        cur = cur.setdefault(k, {})
    cur[keys[-1]] = value


def _apply_env(cfg: dict) -> None:
    prefix = "SECMON_"
    for env_key, raw in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        key = env_key[len(prefix) :].lower()
        if key.startswith("override_"):
            # SECMON_OVERRIDE_SSH_FAILED_24H_MIN_DELTA
            rest = key[len("override_") :]
            if rest.endswith("_min_delta"):
                metric = rest[: -len("_min_delta")]
                cfg.setdefault("metrics", {}).setdefault("overrides", {}).setdefault(
                    metric, {}
                )["min_delta"] = int(raw)
            elif rest.endswith("_sigma_above"):
                metric = rest[: -len("_sigma_above")]
                cfg.setdefault("metrics", {}).setdefault("overrides", {}).setdefault(
                    metric, {}
                )["sigma_above"] = float(raw)
            elif rest.endswith("_sigma_below"):
                metric = rest[: -len("_sigma_below")]
                cfg.setdefault("metrics", {}).setdefault("overrides", {}).setdefault(
                    metric, {}
                )["sigma_below"] = float(raw)
            continue
        parts = key.split("_")
        # Map simple top-level groups
        mapping = {
            "own_ip": ["whitelist", "own_ip"],
            "data_dir": ["general", "data_dir"],
            "log_file": ["general", "log_file"],
            "deliver_target": ["hermes", "deliver_target"],
            "anomaly_cooldown_minutes": ["anomaly", "cooldown_minutes"],
            "baseline_min_samples": ["anomaly", "baseline_min_samples"],
            "cache_ttl_seconds": ["anomaly", "cache_ttl_seconds"],
        }
        if key in mapping:
            val: Any = raw
            if key in ("anomaly_cooldown_minutes", "baseline_min_samples", "cache_ttl_seconds"):
                val = int(raw)
            _set_nested(cfg, mapping[key], val)
            continue
        # generic nested: group_param (e.g. realtime_ssh_brute_force_threshold)
        if len(parts) >= 2:
            group, param = parts[0], "_".join(parts[1:])
            if group in cfg and isinstance(cfg[group], dict):
                _set_nested(cfg, [group, param], _coerce(raw))


def _coerce(value: str) -> Any:
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def load_config(config_path: str | None = None, overrides: dict | None = None) -> dict:
    cfg = default_config()
    path = config_path or os.environ.get("SECMON_CONFIG_PATH", "")
    if not path:
        for candidate in ("/etc/secmon/config.yaml", "config.yaml"):
            if os.path.isfile(candidate):
                path = candidate
                break
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            file_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(cfg, file_cfg)
        cfg["general"]["config_path"] = path
    _apply_env(cfg)
    if overrides:
        cfg = _deep_merge(cfg, overrides)
    # own_ip defaults known_ssh_ips
    own = cfg["whitelist"].get("own_ip", "")
    if own and own not in cfg["whitelist"].get("known_ssh_ips", []):
        cfg["whitelist"].setdefault("known_ssh_ips", []).append(own)
    # Apply metric overrides into thresholds
    for metric, ovr in cfg.get("metrics", {}).get("overrides", {}).items():
        th = cfg["metrics"]["thresholds"].setdefault(metric, {})
        th.update(ovr)
    return cfg


def get_threshold(cfg: dict, metric: str) -> dict:
    return cfg["metrics"]["thresholds"].get(metric, DEFAULT_METRIC_THRESHOLDS.get(metric, {}))


def state_file_path(cfg: dict) -> str:
    return str(Path(cfg["general"]["data_dir"]) / "state.json")


def snapshot_dir(cfg: dict) -> str:
    return str(Path(cfg["general"]["data_dir"]) / "snapshots")
