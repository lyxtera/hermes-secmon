"""Listening port monitor — TC-4."""

from __future__ import annotations

import re

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe


def _parse_ports(output: str) -> dict[int, str]:
    ports: dict[int, str] = {}
    for line in output.splitlines():
        if not line.strip() or line.startswith("State"):
            continue
        m = re.search(r":(\d+)(?:\s|$)", line)
        if m:
            port = int(m.group(1))
            ports[port] = line.strip()
    return ports


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    out = run_cmd_safe(["ss", "-tlnp"])
    current = _parse_ports(out)
    ms = state.setdefault("monitor_state", {})
    prev_out = ms.get("known_ports_output", "")
    prev = _parse_ports(prev_out) if prev_out else {}
    if prev_out:
        for port in set(current) - set(prev):
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="ports",
                    message=f"New listening port: {port}",
                    dedup_key=f"port:{port}",
                    structured={"port": port, "line": current[port]},
                )
            )
        for port in set(prev) - set(current):
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="ports",
                    message=f"Listening port closed: {port}",
                    dedup_key=f"port:{port}",
                    structured={"port": port, "event": "closed"},
                )
            )
    ms["known_ports_output"] = out
    return alerts
