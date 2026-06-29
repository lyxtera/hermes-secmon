"""Kernel error monitor — TC-6."""

from __future__ import annotations

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    threshold = cfg["realtime"]["kernel_error_threshold"]
    out = run_cmd_safe(
        ["journalctl", "-k", "--priority=err", "--since", "24 hours ago"], timeout=30
    )
    lines = [
        ln
        for ln in out.splitlines()
        if ln.strip() and "regulatory.db" not in ln and "wireless-regdb" not in ln
    ]
    if len(lines) > threshold:
        alerts.append(
            Alert(
                severity="MEDIUM",
                source="kernel",
                message=f"Kernel errors elevated: {len(lines)} in 24h",
                dedup_key="kernel",
                structured={"count": len(lines), "sample": lines[:5]},
            )
        )
    return alerts
