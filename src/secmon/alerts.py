"""Alert dispatch, deduplication, structured logging."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any

from secmon.shell import run_cmd
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


def _send_webhook(cfg: dict, alert: Alert) -> None:
    url = cfg.get("alerting", {}).get("webhook_url", "")
    if not url:
        return
    min_level = cfg.get("alerting", {}).get("webhook_min_level", "CRITICAL")
    if SEVERITY_ORDER.get(alert.severity, 0) < SEVERITY_ORDER.get(min_level, 4):
        return
    payload = {
        "severity": alert.severity,
        "source": alert.source,
        "hostname": socket.gethostname(),
        "timestamp": utcnow_iso(),
        "message": sanitize_message(alert.message),
        "structured": alert.structured,
    }
    try:
        run_cmd(
            [
                "curl",
                "-sS",
                "-m",
                "10",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                json.dumps(payload),
                url,
            ],
            timeout=12,
        )
    except Exception as exc:
        logger.error("webhook failed: %s", exc)


def dispatch(
    alerts: list[Alert],
    state: dict,
    cfg: dict,
    *,
    stdout: bool = True,
) -> list[Alert]:
    """Dedup, log, optionally print and webhook. Returns new alerts only."""
    new_alerts: list[Alert] = []
    for alert in alerts:
        if is_duplicate(alert, state):
            continue
        mark_dispatched(alert, state)
        _log_alert(cfg, alert)
        new_alerts.append(alert)
        _send_webhook(cfg, alert)
    if stdout and new_alerts:
        for a in new_alerts:
            print(f"[{a.severity}] {a.source}: {sanitize_message(a.message)}")
    return new_alerts
