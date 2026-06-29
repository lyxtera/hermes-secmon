"""Port scan detection — TC-3."""

from __future__ import annotations

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe
from secmon.utils import extract_ips


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    own_ip = cfg.get("whitelist", {}).get("own_ip", "")
    out = run_cmd_safe(["journalctl", "-k", "--since", "1 hour ago"], timeout=30)
    sources: set[str] = set()
    keywords = ("martian", "blocked", "flood", "port scan", "PORT SCAN")
    for line in out.splitlines():
        lower = line.lower()
        if any(kw in lower for kw in keywords):
            for ip in extract_ips(line):
                if ip != own_ip:
                    sources.add(ip)
    if sources:
        alerts.append(
            Alert(
                severity="MEDIUM",
                source="port_scan",
                message=f"Port scan / flood indicators from {len(sources)} source(s)",
                dedup_key="port_scan",
                structured={"sources": sorted(sources)},
            )
        )
    return alerts
