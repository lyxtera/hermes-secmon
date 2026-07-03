"""Secmon self-protection and tamper detection."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
from pathlib import Path

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe
from secmon.utils import parse_iso, utcnow, utcnow_iso


def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _hermes_cron_registered(job_name: str) -> bool:
    if not job_name:
        return False
    listing = run_cmd_safe(["hermes", "cron", "list"])
    if job_name in listing:
        return True
    jobs_path = os.path.expanduser("~/.hermes/cron/jobs.json")
    if os.path.isfile(jobs_path):
        try:
            with open(jobs_path, encoding="utf-8") as fh:
                data = json.load(fh)
            jobs = data if isinstance(data, list) else data.get("jobs", [])
            for job in jobs:
                if isinstance(job, dict) and job.get("name") == job_name:
                    return True
                if isinstance(job, str) and job == job_name:
                    return True
        except (OSError, ValueError, TypeError):
            pass
    return False


def _cron_interval_minutes(job_name: str, default: int = 15) -> int:
    """Read the cron schedule for *job_name* and return its interval in minutes.

    Parses common cron(5) expression shapes:
      ``*/N * * * *``       → N minutes
      ``M * * * *``          → 60 minutes
      ``0 */N * * *``        → N hours → N×60 minutes
      ``0 0 ...``            → 24 hours → 1440 minutes

    If the job can't be read or the expression is unrecognised, return
    *default*.
    """
    jobs_path = os.path.expanduser("~/.hermes/cron/jobs.json")
    if not os.path.isfile(jobs_path):
        return default
    try:
        with open(jobs_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, TypeError):
        return default
    jobs = data if isinstance(data, list) else data.get("jobs", [])
    if not isinstance(jobs, list):
        return default

    expr = ""
    for job in jobs:
        if isinstance(job, dict) and job.get("name") == job_name:
            raw = job.get("schedule", {})
            if isinstance(raw, dict):
                expr = raw.get("expr", "")
                if not expr:
                    expr = raw.get("display", "")
            elif isinstance(raw, str):
                expr = raw
            if not expr:
                expr = job.get("schedule_display", "")
            break

    if not expr or not isinstance(expr, str):
        return default

    expr = expr.strip()

    # */N * * * *  → every N minutes
    m = re.fullmatch(r"\*/(\d+)\s+\*\s+\*\s+\*\s+\*", expr)
    if m:
        return int(m.group(1))

    # M * * * *  → once per hour (at minute M)
    m = re.fullmatch(r"\d+\s+\*\s+\*\s+\*\s+\*", expr)
    if m:
        return 60

    # 0 */N ...  → every N hours
    m = re.fullmatch(r"\d+\s+\*/(\d+)\s+\*\s+\*\s+\*", expr)
    if m:
        return int(m.group(1)) * 60

    # 0 0 ...  → daily
    m = re.fullmatch(r"\d+\s+\d+\s+\*\s+\*\s+\*", expr)
    if m:
        return 1440

    return default


def _collect_secmon_files(root: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    base = Path(root)
    if not base.is_dir():
        return hashes
    for pattern in ("src/secmon/**/*.py", "pyproject.toml", "config.yaml.example"):
        for fp in base.glob(pattern):
            if fp.is_file():
                digest = _sha256_file(str(fp))
                if digest:
                    hashes[str(fp)] = digest
    return hashes


def _check_permissions(path: str, max_mode: int, label: str) -> Alert | None:
    if not os.path.exists(path):
        return Alert(
            severity="CRITICAL",
            source="self_protection",
            message=f"Secmon {label} missing: {path}",
            dedup_key=f"self_prot:missing:{path}",
            structured={"path": path, "kind": label},
        )
    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        if mode > max_mode:
            return Alert(
                severity="HIGH",
                source="self_protection",
                message=f"Secmon {label} permissions too open: {path} ({oct(mode)})",
                dedup_key=f"self_prot:perm:{path}",
                structured={"path": path, "mode": oct(mode), "expected": oct(max_mode)},
            )
    except OSError:
        pass
    return None


def check(state: dict, cfg: dict) -> list[Alert]:
    if platform.system() != "Linux":
        return []

    alerts: list[Alert] = []
    install = cfg.get("installation", {})
    source_dir = install.get("source_dir", "/opt/secmon")
    cli_path = install.get("cli_path", "/usr/local/bin/secmon")
    cron_marker = install.get("cron_marker", "secmon --tick")
    hermes_cron_job = install.get("hermes_cron_job", "secmon-tick")
    data_dir = cfg["general"]["data_dir"]
    log_file = cfg["general"]["log_file"]
    config_path = cfg["general"].get("config_path") or "/etc/secmon/config.yaml"

    ms = state.setdefault("monitor_state", {})
    ab = state.setdefault("audit_baseline", {})
    prot = ab.setdefault("self_protection", {})
    initialized = bool(prot.get("initialized"))

    # Missed tick detection — threshold is 2× the cron interval so normal
    # schedule jitter never triggers, but a genuinely missed tick will.
    now = utcnow()
    last_tick = parse_iso(ms.get("last_tick"))
    cron_interval = _cron_interval_minutes(hermes_cron_job, default=15)
    tick_threshold = max(cron_interval * 120, 600)  # 2× interval (in seconds), min 10 min
    if initialized and last_tick and (now - last_tick).total_seconds() > tick_threshold:
        alerts.append(
            Alert(
                severity="CRITICAL",
                source="self_protection",
                message=f"Secmon tick gap detected: last run {(now - last_tick).total_seconds() / 60:.0f}m ago",
                dedup_key="self_prot:missed_tick",
                structured={"last_tick": ms.get("last_tick")},
            )
        )
    ms["last_tick"] = utcnow_iso()

    # Cron / schedule integrity (after baseline established)
    if initialized:
        hermes_ok = _hermes_cron_registered(hermes_cron_job)
        crontab = run_cmd_safe(["crontab", "-l"])
        legacy_ok = bool(cron_marker and cron_marker in crontab)
        if not hermes_ok and not legacy_ok:
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="self_protection",
                    message="Secmon scheduler missing (Hermes cron or legacy crontab)",
                    dedup_key="self_prot:cron_missing",
                )
            )

    # Symlink / install path integrity
    if initialized and os.path.lexists(source_dir):
        if os.path.islink(source_dir):
            target = os.path.realpath(source_dir)
            expected = prot.get("source_realpath")
            if expected and target != expected:
                alerts.append(
                    Alert(
                        severity="CRITICAL",
                        source="self_protection",
                        message=f"Secmon install symlink retargeted: {source_dir} -> {target}",
                        dedup_key=f"self_prot:symlink:{source_dir}",
                        structured={"expected": expected, "actual": target},
                    )
                )
            elif not expected:
                prot["source_realpath"] = target
        else:
            if initialized:
                alerts.append(
                    Alert(
                        severity="HIGH",
                        source="self_protection",
                        message=f"Secmon source path is not a symlink: {source_dir}",
                        dedup_key=f"self_prot:not_symlink:{source_dir}",
                    )
                )

    if initialized and os.path.lexists(cli_path):
        if os.path.islink(cli_path):
            cli_target = os.path.realpath(cli_path)
            expected_cli = prot.get("cli_realpath")
            if expected_cli and cli_target != expected_cli:
                alerts.append(
                    Alert(
                        severity="CRITICAL",
                        source="self_protection",
                        message=f"Secmon CLI symlink retargeted: {cli_path} -> {cli_target}",
                        dedup_key=f"self_prot:cli_symlink",
                        structured={"expected": expected_cli, "actual": cli_target},
                    )
                )
            elif not expected_cli:
                prot["cli_realpath"] = cli_target

    # Code integrity baseline
    code_root = source_dir if os.path.isdir(source_dir) else os.getcwd()
    current_hashes = _collect_secmon_files(code_root)
    baseline_hashes: dict = prot.setdefault("code_hashes", {})
    if initialized and baseline_hashes:
        for path, digest in current_hashes.items():
            prev = baseline_hashes.get(path)
            if prev and prev != digest:
                alerts.append(
                    Alert(
                        severity="CRITICAL",
                        source="self_protection",
                        message=f"Secmon code file changed: {path}",
                        dedup_key=f"self_prot:code:{path}",
                        structured={"path": path},
                    )
                )
    prot["code_hashes"] = {**baseline_hashes, **current_hashes}

    # Config / Hermes delivery target tamper
    if os.path.isfile(config_path):
        cfg_hash = _sha256_file(config_path)
        prev_cfg = prot.get("config_hash")
        if initialized and prev_cfg and cfg_hash and prev_cfg != cfg_hash:
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="self_protection",
                    message=f"Secmon config changed: {config_path}",
                    dedup_key="self_prot:config_changed",
                )
            )
        if cfg_hash:
            prot["config_hash"] = cfg_hash
        prev_deliver = prot.get("deliver_target")
        current_deliver = cfg.get("hermes", {}).get("deliver_target", "")
        if initialized and prev_deliver is not None and prev_deliver != current_deliver:
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="self_protection",
                    message="Secmon Hermes delivery target changed",
                    dedup_key="self_prot:deliver_target_changed",
                )
            )
        prot["deliver_target"] = current_deliver

    # Permissions on sensitive paths (after baseline)
    if initialized:
        for path, max_mode, label in (
            (config_path, 0o600, "config"),
            (os.path.join(data_dir, "state.json"), 0o600, "state"),
            (log_file, 0o644, "log"),
            (data_dir, 0o700, "data_dir"),
        ):
            alert = _check_permissions(path, max_mode, label)
            if alert:
                alerts.append(alert)

    # Log truncation detection
    if os.path.isfile(log_file):
        try:
            size = os.path.getsize(log_file)
            prev_size = prot.get("log_size")
            if initialized and prev_size is not None and size < prev_size:
                alerts.append(
                    Alert(
                        severity="CRITICAL",
                        source="self_protection",
                        message=f"Secmon log truncated: {log_file}",
                        dedup_key="self_prot:log_truncated",
                        structured={"prev_size": prev_size, "size": size},
                    )
                )
            prot["log_size"] = size
        except OSError:
            pass

    # State baseline reset detection
    state_path = os.path.join(data_dir, "state.json")
    if os.path.isfile(state_path):
        st_hash = _sha256_file(state_path)
        prev_st = prot.get("state_snapshot_hash")
        baselines_empty = not state.get("baselines")
        daily_empty = not state.get("daily_stats")
        if initialized and prev_st and st_hash and prev_st != st_hash and baselines_empty and daily_empty:
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="self_protection",
                    message="Secmon state baselines appear reset",
                    dedup_key="self_prot:state_reset",
                )
            )
        if st_hash:
            prot["state_snapshot_hash"] = st_hash

    # Chained integrity record (detect manual state edits)
    chain_input = f"{prot.get('config_hash','')}:{prot.get('code_chain','')}:{utcnow_iso()}"
    chain_digest = hashlib.sha256(chain_input.encode()).hexdigest()[:16]
    prev_chain = prot.get("integrity_chain")
    if prev_chain and prot.get("code_hashes") and chain_digest != prev_chain:
        prot["integrity_chain"] = hashlib.sha256(
            f"{prev_chain}:{chain_digest}".encode()
        ).hexdigest()[:16]
    else:
        prot["integrity_chain"] = chain_digest or prev_chain

    prot["initialized"] = True
    return alerts if initialized else []
