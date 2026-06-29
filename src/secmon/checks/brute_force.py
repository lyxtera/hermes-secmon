"""SSH brute-force burst detection — TC-2."""

from __future__ import annotations

import re
from collections import defaultdict

from secmon.alerts import Alert
from secmon.botnet import get_blocked_subnets
from secmon.shell import run_cmd_safe
from secmon.utils import extract_ips, subnet_24


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    threshold = cfg["realtime"]["ssh_brute_force_threshold"]
    out = run_cmd_safe(["journalctl", "--since", "5 minutes ago"], timeout=30)
    failures = [ln for ln in out.splitlines() if "Failed password" in ln]
    if len(failures) < threshold:
        return alerts
    subnet_ips: dict[str, set[str]] = defaultdict(set)
    for line in failures:
        for ip in extract_ips(line):
            subnet_ips[subnet_24(ip)].add(ip)
    blocked = get_blocked_subnets()
    for subnet, ips in subnet_ips.items():
        if subnet in blocked:
            alerts.append(
                Alert(
                    severity="INFO",
                    source="brute_force",
                    message=f"Brute-force burst from blocked subnet {subnet}",
                    dedup_key=f"bf_burst:{subnet}",
                    structured={"subnet": subnet, "ips": list(ips), "blocked": True},
                )
            )
        else:
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="brute_force",
                    message=f"SSH brute-force burst from novel subnet {subnet} ({len(ips)} IPs)",
                    dedup_key=f"bf_burst:{subnet}",
                    structured={"subnet": subnet, "ips": list(ips), "failures": len(failures)},
                )
            )
    return alerts
