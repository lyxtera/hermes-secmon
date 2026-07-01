"""Threat check registry."""

from __future__ import annotations

import logging
from typing import Callable

from secmon.alerts import Alert

from . import (
    brute_force,
    fail2ban,
    invalid_user,
    kernel,
    outbound,
    port_scan,
    ports,
    self_protection,
    ssh_session,
)

logger = logging.getLogger("secmon.checks")

CHECKS: list[tuple[str, Callable]] = [
    ("self_protection", self_protection.check),
    ("fail2ban", fail2ban.check),
    ("brute_force", brute_force.check),
    ("port_scan", port_scan.check),
    ("ports", ports.check),
    ("invalid_user", invalid_user.check),
    ("kernel", kernel.check),
    ("ssh_session", ssh_session.check),
    ("outbound", outbound.check),
]


def run_checks(state: dict, cfg: dict) -> list[Alert]:
    findings: list[Alert] = []
    for name, fn in CHECKS:
        try:
            result = fn(state, cfg)
            if result:
                findings.extend(result)
        except Exception as exc:
            logger.error("check %s failed: %s", name, exc)
    return findings
