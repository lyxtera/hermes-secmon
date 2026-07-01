"""Hermes tool handlers — delegate to secmon CLI modes."""

from __future__ import annotations

import io
import os
import json
from contextlib import redirect_stdout
from typing import Any, Callable

from secmon.config import load_config
from secmon.metrics import collect_metrics_from_state
from secmon.modes.audit_mode import run_audit_mode
from secmon.modes.check import run_check
from secmon.modes.daily import run_daily
from secmon.modes.detect_botnet import run_detect_botnet
from secmon.modes.record import run_record
from secmon.modes.status import run_status
from secmon.modes.tick import run_tick
from secmon.output import format_status
from secmon.state import load_state, save_state
from secmon_plugin.schemas import SCHEMAS

ModeRunner = Callable[[dict, dict], int]


def _run_with_capture(runner: ModeRunner, state: dict, cfg: dict) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = runner(state, cfg)
    return code, buffer.getvalue().strip()


def _session(config_path: str | None = None) -> tuple[dict, dict]:
    cfg = load_config(config_path)
    state = load_state(cfg)
    return state, cfg


def run_mode(mode: str, config_path: str | None = None) -> dict[str, Any]:
    """Execute a secmon mode and return a structured result dict."""
    runners: dict[str, ModeRunner] = {
        "status": run_status,
        "check": run_check,
        "audit": run_audit_mode,
        "record": run_record,
        "daily": run_daily,
        "detect-botnet": run_detect_botnet,
        "tick": run_tick,
    }
    runner = runners.get(mode)
    if runner is None:
        return {
            "success": False,
            "mode": mode,
            "exit_code": 1,
            "error": f"Unknown mode: {mode}",
        }

    state, cfg = _session(config_path)
    exit_code, output = _run_with_capture(runner, state, cfg)
    if mode != "status":
        save_state(cfg, state)
    return {
        "success": exit_code == 0,
        "mode": mode,
        "exit_code": exit_code,
        "output": output,
    }


def security_context_summary(config_path: str | None = None) -> str:
    """Short security summary for pre_llm_call context injection."""
    state, cfg = _session(config_path)
    metrics = collect_metrics_from_state(cfg, state, force=False)
    status = format_status(state, cfg, metrics)
    findings = state.get("last_audit_findings", [])
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    return (
        "[secmon security context]\n"
        f"Last audit score: {state.get('last_audit_score', 'n/a')}\n"
        f"Open CRITICAL/HIGH audit findings: {critical}/{high}\n"
        f"{status}"
    )


def _make_handler(mode: str) -> Callable[[dict, Any], str]:
    def handler(params: dict, **kwargs: Any) -> str:
        del kwargs
        config_path = params.get("config_path")
        result = run_mode(mode, config_path)
        return json.dumps(result)

    return handler


TOOL_DEFINITIONS: list[tuple[str, dict, Callable[[dict, Any], str], str]] = [
    (
        "secmon_status",
        SCHEMAS["secmon_status"],
        _make_handler("status"),
        "Show security monitor baselines, state, and current metrics.",
    ),
    (
        "secmon_check",
        SCHEMAS["secmon_check"],
        _make_handler("check"),
        "Run realtime threat checks and statistical anomaly detection.",
    ),
    (
        "secmon_audit",
        SCHEMAS["secmon_audit"],
        _make_handler("audit"),
        "Run a full multi-layer forensic security audit.",
    ),
    (
        "secmon_record",
        SCHEMAS["secmon_record"],
        _make_handler("record"),
        "Collect metrics and append a baseline calibration sample.",
    ),
    (
        "secmon_daily",
        SCHEMAS["secmon_daily"],
        _make_handler("daily"),
        "Produce a human-readable daily security digest.",
    ),
    (
        "secmon_detect_botnet",
        SCHEMAS["secmon_detect_botnet"],
        _make_handler("detect-botnet"),
        "Run botnet /24 subnet analysis and automatic iptables blocking.",
    ),
    (
        "secmon_remediate",
        SCHEMAS["secmon_remediate"],
        lambda params, **kwargs: json.dumps(_remediate(params, params.get("config_path"))),
        "Apply safe operator-guided remediation actions.",
    ),
]


def _remediate(params: dict, config_path: str | None) -> dict[str, Any]:
    """Run a safe remediation action (best-effort)."""
    action = (params.get("action") or "").strip()
    if not action:
        return {"success": False, "action": action, "error": "Missing action"}

    state, cfg = _session(config_path)
    del state

    if action == "self_protection_fix_permissions":
        return _fix_self_protection_permissions(cfg)

    return {"success": False, "action": action, "error": f"Unknown action: {action}"}


def remediate_action(action: str, config_path: str | None = None) -> dict[str, Any]:
    """Public helper for slash commands."""
    return _remediate({"action": action}, config_path)


def _fix_self_protection_permissions(cfg: dict) -> dict[str, Any]:
    """Fix only the known insecure-permissions cases from self_protection alerts."""
    changed: list[dict[str, Any]] = []
    errors: list[str] = []

    def _chmod(path: str, mode: int) -> None:
        try:
            if not os.path.exists(path):
                return
            st_before = os.stat(path)
            os.chmod(path, mode)
            st_after = os.stat(path)
            changed.append(
                {
                    "path": path,
                    "mode_before": oct(st_before.st_mode & 0o777),
                    "mode_after": oct(st_after.st_mode & 0o777),
                }
            )
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    install = cfg.get("installation", {})
    config_path = cfg.get("general", {}).get("config_path") or "/etc/secmon/config.yaml"

    data_dir = cfg.get("general", {}).get("data_dir") or "/var/lib/secmon"
    log_file = cfg.get("general", {}).get("log_file") or "/var/log/security-monitor.log"
    botnet_log_file = cfg.get("general", {}).get("botnet_log_file") or "/var/log/secmon-botnet.log"

    # Safe defaults aligned with self_protection enforcement.
    _chmod(config_path, 0o600)
    _chmod(os.path.join(data_dir, "state.json"), 0o600)
    _chmod(data_dir, 0o700)
    _chmod(log_file, 0o640)
    _chmod(botnet_log_file, 0o640)

    return {
        "success": len(errors) == 0,
        "action": "self_protection_fix_permissions",
        "changed": changed,
        "errors": errors,
    }
