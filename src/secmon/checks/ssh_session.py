"""Unauthorized SSH session monitor — TC-7."""

from __future__ import annotations

import re

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe


def _peer_ips(output: str) -> set[str]:
    ips: set[str] = set()
    for line in output.splitlines():
        # ss format: ... peer 1.2.3.4:port
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}):\d+\b", line)
        if m:
            ips.add(m.group(1))
    return ips


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    whitelist = set(cfg.get("whitelist", {}).get("known_ssh_ips", []))
    own = cfg.get("whitelist", {}).get("own_ip", "")
    if own:
        whitelist.add(own)
    out = run_cmd_safe(["ss", "-tnp", "dport", "=", ":22"])
    current = _peer_ips(out)
    ms = state.setdefault("monitor_state", {})
    active: dict = ms.setdefault("active_ssh_sessions", {})
    for ip in current:
        if ip in whitelist:
            active.pop(f"ssh:{ip}", None)
            continue
        key = f"ssh:{ip}"
        if key not in active:
            alerts.append(
                Alert(
                    severity="CRITICAL",
                    source="ssh_session",
                    message=f"Unauthorized SSH session from {ip}",
                    dedup_key=key,
                    structured={"peer_ip": ip},
                )
            )
        active[key] = True
    # Clear ended sessions from dedup tracking
    ended = [k for k in active if k.replace("ssh:", "") not in current]
    for k in ended:
        del active[k]
        state.setdefault("dedup_store", {}).pop(k, None)
    return alerts
