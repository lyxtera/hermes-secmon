"""Invalid user enumeration — TC-5."""

from __future__ import annotations

import re
from collections import defaultdict

from secmon.alerts import Alert
from secmon.botnet import get_blocked_subnets
from secmon.shell import run_cmd_safe
from secmon.utils import extract_ips, subnet_24


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    threshold = cfg["realtime"]["invalid_user_threshold"]
    out = run_cmd_safe(["journalctl", "--since", "5 minutes ago"], timeout=30)
    invalid_lines = [ln for ln in out.splitlines() if "Invalid user" in ln]
    usernames: set[str] = set()
    for line in invalid_lines:
        m = re.search(r"Invalid user\s+(\S+)", line)
        if m:
            usernames.add(m.group(1))
    if len(usernames) < threshold:
        return alerts
    subnet_ips: dict[str, list[str]] = defaultdict(list)
    for line in invalid_lines:
        for ip in extract_ips(line):
            subnet_ips[subnet_24(ip)].append(ip)
    blocked = get_blocked_subnets()
    for subnet, ips in subnet_ips.items():
        if subnet in blocked:
            continue
        alerts.append(
            Alert(
                severity="MEDIUM",
                source="invalid_user",
                message=f"Username enumeration from {subnet}: {len(usernames)} users",
                dedup_key=f"enum:{subnet}",
                structured={
                    "subnet": subnet,
                    "usernames": sorted(usernames)[:20],
                    "ips": list(set(ips)),
                },
            )
        )
    return alerts
