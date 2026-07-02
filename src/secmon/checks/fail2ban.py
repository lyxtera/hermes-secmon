"""Fail2ban ban monitor — TC-1."""

from __future__ import annotations

import logging
import re

from secmon.alerts import Alert
from secmon.botnet import get_blocked_subnets
from secmon.shell import run_cmd_safe
from secmon.utils import subnet_24, utcnow

logger = logging.getLogger("secmon.checks.fail2ban")


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

    # Only alert on batches of new bans exceeding the threshold.
    # Individual bans are routine — anomaly detection on f2b_banned_count
    # catches statistical surges. The threshold prevents per-IP noise.
    min_new = cfg.get("realtime", {}).get("fail2ban_min_new_bans", 5)
    total_new = len(novel) + len(noise)

    if total_new >= min_new:
        alerts.append(
            Alert(
                severity="HIGH" if len(novel) > 0 else "INFO",
                source="fail2ban",
                message=f"SSH ban burst: {total_new} new bans"
                + (f" ({', '.join(novel[:5])})" if novel else ""),
                dedup_key=f"f2b:burst:{utcnow().strftime('%Y%m%d%H')}",
                structured={
                    "new_bans": len(novel),
                    "noise_bans": len(noise),
                    "novel_ips": novel[:10],
                    "total_banned": len(banned),
                },
            )
        )
    elif novel and len(novel) < min_new:
        # Quietly absorb — anomaly detector will catch surges
        logger.debug(
            "fail2ban: %d new ban(s) (below threshold %d, suppressed)",
            len(novel), min_new,
        )

    state.setdefault("monitor_state", {})["last_f2b_snapshot"] = " ".join(banned)
    return alerts
