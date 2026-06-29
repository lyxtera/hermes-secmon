"""Suspicious outbound connection monitor — TC-8."""

from __future__ import annotations

import re

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe


def _is_suspicious_port(port: int, cfg: dict) -> bool:
  sp = cfg.get("suspicious_ports", {})
  if port in sp.get("specific", []):
    return True
  for rng in sp.get("ranges", []):
    if len(rng) == 2 and rng[0] <= port <= rng[1]:
      return True
  return False


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    out = run_cmd_safe(["ss", "-tnp", "state", "established"])
    for line in out.splitlines():
        if "127.0.0.1" in line or "::1" in line:
            continue
        # remote address after last space chunk
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s", line)
        if not m:
            continue
        dest_ip, dest_port = m.group(1), int(m.group(2))
        if _is_suspicious_port(dest_port, cfg):
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="outbound",
                    message=f"Suspicious outbound connection to {dest_ip}:{dest_port}",
                    dedup_key=f"outbound:{dest_ip}:{dest_port}",
                    structured={"dest_ip": dest_ip, "dest_port": dest_port, "line": line.strip()},
                )
            )
    return alerts
