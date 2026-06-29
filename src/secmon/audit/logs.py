"""Layer 5: Log correlation + NC-11."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe
from secmon.utils import utcnow


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    # Invalid user top list (INFO)
    jout = run_cmd_safe(["journalctl", "--since", "24 hours ago"], timeout=30)
    invalid_users: dict[str, int] = {}
    for line in jout.splitlines():
        m = re.search(r"Invalid user\s+(\S+)", line)
        if m:
            invalid_users[m.group(1)] = invalid_users.get(m.group(1), 0) + 1
    if len(invalid_users) > 20:
        top = sorted(invalid_users, key=invalid_users.get, reverse=True)[:5]
        findings.append(
            AuditFinding("INFO", 5, "invalid_users", f"Top invalid users: {top}")
        )

    # Systemd unit failures
    failed_units = run_cmd_safe(["systemctl", "--failed", "--no-legend"])
    if failed_units.strip():
        findings.append(
            AuditFinding("MEDIUM", 5, "systemd_failed", f"Failed units: {failed_units.strip()[:200]}")
        )

    # Log tampering — auth.log/syslog mtime
    for log_path in ("/var/log/auth.log", "/var/log/syslog"):
        if os.path.isfile(log_path):
            mtime = datetime.fromtimestamp(os.path.getmtime(log_path), tz=timezone.utc)
            if (utcnow() - mtime) > timedelta(hours=1):
                findings.append(
                    AuditFinding("MEDIUM", 5, "log_stale", f"{log_path} not written in >1h")
                )
            size = os.path.getsize(log_path)
            if size < 100:
                findings.append(
                    AuditFinding("HIGH", 5, "log_truncated", f"{log_path} suspiciously small ({size}B)")
                )

    # Journal gap detection
    boots = run_cmd_safe(["journalctl", "--list-boots"])
    if boots.strip():
        pass  # informational only

    # NC-11: Log integrity
    journald_conf = "/etc/systemd/journald.conf"
    if os.path.isfile(journald_conf):
        content = open(journald_conf, encoding="utf-8", errors="replace").read()
        if "Storage=persistent" not in content and "Storage=auto" not in content:
            findings.append(
                AuditFinding("CRITICAL", 5, "NC-11-storage", "Journal persistent storage not configured")
            )
    verify = run_cmd_safe(["journalctl", "--verify"], timeout=60)
    if verify and ("FAIL" in verify or "corrupt" in verify.lower()):
        findings.append(
            AuditFinding("CRITICAL", 5, "NC-11-verify", "Journal verification failed")
        )
    # Time gaps in journal
    since = run_cmd_safe(["journalctl", "--since", "48 hours ago", "-o", "short-iso"], timeout=30)
    prev_ts = None
    for line in since.splitlines():
        if len(line) < 19:
            continue
        try:
            ts = datetime.fromisoformat(line[:19])
            if prev_ts and (ts - prev_ts) > timedelta(hours=1):
                findings.append(
                    AuditFinding("HIGH", 5, "NC-11-gap", f"Journal gap >1h before {ts}")
                )
            prev_ts = ts
        except ValueError:
            continue

    auditd = run_cmd_safe(["systemctl", "is-active", "auditd"])
    if auditd.strip() == "inactive" and os.path.exists("/etc/audit/auditd.conf"):
        findings.append(AuditFinding("LOW", 5, "auditd", "auditd installed but inactive"))

    return findings
