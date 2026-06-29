"""Fail2ban ban monitor — TC-1."""

from __future__ import annotations

import re

from secmon.alerts import Alert
from secmon.botnet import get_blocked_subnets
from secmon.shell import run_cmd_safe
from secmon.utils import subnet_24


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    out = run_cmd_safe(["fail2ban-client", "status", "sshd"])
    if not out:
        return alerts
    banned: list[str] = []
    in_list = False
    for line in out.splitlines():
        if "Banned IP list" in line:
            in_list = True
            rest = line.split(":", 1)[-1].strip()
            if rest:
                banned.extend(rest.split())
            continue
        if in_list and line.strip():
            banned.extend(line.strip().split())
    blocked_subnets = get_blocked_subnets()
    prev = set(
        state.get("monitor_state", {}).get("last_f2b_snapshot", "").split()
    )
    new_ips = [ip for ip in banned if ip and ip not in prev]
    novel = []
    noise = []
    for ip in new_ips:
        if subnet_24(ip) in blocked_subnets:
            noise.append(ip)
        else:
            novel.append(ip)
    for ip in novel:
        alerts.append(
            Alert(
                severity="HIGH",
                source="fail2ban",
                message=f"New SSH ban: {ip}",
                dedup_key=f"f2b:{ip}",
                structured={"new_bans": [ip], "ip": ip},
            )
        )
    if noise:
        alerts.append(
            Alert(
                severity="INFO",
                source="fail2ban",
                message=f"New bans from already-blocked subnets: {', '.join(noise[:5])}",
                dedup_key=f"f2b:noise:{subnet_24(noise[0])}",
                structured={"noise_ips": noise},
            )
        )
    state.setdefault("monitor_state", {})["last_f2b_snapshot"] = " ".join(banned)
    return alerts
