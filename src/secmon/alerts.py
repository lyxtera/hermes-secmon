"""Alert dispatch, deduplication, structured logging."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from secmon.utils import parse_iso, sanitize_message, utcnow, utcnow_iso

logger = logging.getLogger("secmon.alerts")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Dedup windows in seconds per spec §11.2
DEDUP_WINDOWS = {
    "f2b:": 24 * 3600,
    "bf_burst:": 3600,
    "port_scan": 3600,
    "port:": 24 * 3600,
    "enum:": 3600,
    "kernel": 3600,
    "ssh:": 0,  # until session ends — handled specially
    "outbound:": 24 * 3600,
    "anomaly:": 3600,
    "botnet:": 24 * 3600,
    "audit:": 6 * 3600,
    "self_prot:": 3600,
    "c2:": 3600,
}


@dataclass
class Alert:
    severity: str
    source: str
    message: str
    dedup_key: str
    structured: dict[str, Any] = field(default_factory=dict)


def _dedup_window(key: str) -> int:
    for prefix, window in DEDUP_WINDOWS.items():
        if key.startswith(prefix) or key == prefix:
            return window
    return 3600


def is_duplicate(alert: Alert, state: dict) -> bool:
    store = state.setdefault("dedup_store", {})
    prev = store.get(alert.dedup_key)
    if not prev:
        return False
    if alert.dedup_key.startswith("ssh:"):
        # suppressed while session active — caller manages active_ssh_sessions
        return alert.dedup_key in state.get("monitor_state", {}).get("active_ssh_sessions", {})
    ts = parse_iso(prev.get("time"))
    if not ts:
        return False
    window = _dedup_window(alert.dedup_key)
    return (utcnow() - ts).total_seconds() < window


def mark_dispatched(alert: Alert, state: dict) -> None:
    store = state.setdefault("dedup_store", {})
    store[alert.dedup_key] = {"time": utcnow_iso(), "severity": alert.severity}


def _log_alert(cfg: dict, alert: Alert) -> None:
    log_path = cfg["general"]["log_file"]
    entry = {
        "ts": utcnow_iso(),
        "level": "INFO",
        "source": alert.source,
        "severity": alert.severity,
        "message": sanitize_message(alert.message),
        "structured": alert.structured,
    }
    line = json.dumps(entry, separators=(",", ":"))
    try:
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.error("failed to write log: %s", exc)
    logger.info(line)


def audit_finding_to_alert(finding: Any) -> Alert:
    """Convert an AuditFinding into an Alert for the dispatch pipeline."""
    check_id = getattr(finding, "check_id", "unknown")
    message = getattr(finding, "message", "")
    layer = getattr(finding, "layer", 0)
    detail = getattr(finding, "detail", {}) or {}
    severity = getattr(finding, "severity", "MEDIUM")
    key_suffix = sanitize_message(message)[:120]
    return Alert(
        severity=severity,
        source=f"audit:{check_id}",
        message=message,
        dedup_key=f"audit:{check_id}:{key_suffix}",
        structured={"layer": layer, "check_id": check_id, **detail},
    )


def _stdout_remediation_hint(alert: Alert) -> str:
    """Short per-alert hint for gateway/cron delivery."""
    if alert.severity == "CRITICAL":
        return " → reply /secmon audit (URGENT)"
    return " → reply /secmon audit"


def findings_to_alerts(
    findings: list[Any],
    *,
    min_severity: str = "HIGH",
) -> list[Alert]:
    """Bridge audit findings (CRITICAL/HIGH by default) into actionable alerts."""
    floor = SEVERITY_ORDER.get(min_severity, 3)
    alerts: list[Alert] = []
    for finding in findings:
        sev = getattr(finding, "severity", "INFO")
        if SEVERITY_ORDER.get(sev, 0) < floor:
            continue
        alerts.append(audit_finding_to_alert(finding))
    return alerts


def dispatch(
    alerts: list[Alert],
    state: dict,
    cfg: dict,
    *,
    stdout: bool = True,
) -> list[Alert]:
    """Dedup, log, optionally print to stdout. Returns new alerts only.

    Hermes Cron no-agent jobs capture stdout and deliver via the Gateway.
    Empty stdout on a clean tick means no notification is sent.
    """
    new_alerts: list[Alert] = []
    for alert in alerts:
        if is_duplicate(alert, state):
            continue
        mark_dispatched(alert, state)
        _log_alert(cfg, alert)
        new_alerts.append(alert)
    if stdout and new_alerts:
        for a in new_alerts:
            print(
                f"[{a.severity}] {a.source}: {sanitize_message(a.message)}"
                f"{_stdout_remediation_hint(a)}"
            )
    return new_alerts
