"""Layer 6: Threat intelligence + NC-7."""

from __future__ import annotations

import glob
import os
import re
from datetime import datetime, timedelta

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe


WEBSHELL_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        r"eval\s*\(\s*base64_decode",
        r"system\s*\(",
        r"passthru\s*\(",
        r"shell_exec\s*\(",
    )
]

BACKDOOR_NAMES = {"c99.php", "r57.php", "shell.php", "cmd.php", "backdoor.php"}

WEB_ROOTS = ["/var/www", "/srv/www", "/usr/share/nginx/html"]


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    ab = state.setdefault("audit_baseline", {})
    services_baseline: list = ab.setdefault("services", [])

    # Backdoor signature scan
    for root in WEB_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for fname in files:
                if fname in BACKDOOR_NAMES or fname.endswith(".php"):
                    fp = os.path.join(dirpath, fname)
                    try:
                        content = open(fp, encoding="utf-8", errors="replace").read(50000)
                        for pat in WEBSHELL_PATTERNS:
                            if pat.search(content):
                                findings.append(
                                    AuditFinding("CRITICAL", 6, "webshell", f"Webshell pattern in {fp}")
                                )
                                break
                    except OSError:
                        continue

    # Persistence: cron
    cron_sources = run_cmd_safe(["crontab", "-l"])
    for path in glob.glob("/etc/cron.*/*") + glob.glob("/var/spool/cron/crontabs/*"):
        if os.path.isfile(path):
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
                if "/tmp" in content or "curl | bash" in content:
                    findings.append(
                        AuditFinding("HIGH", 6, "cron_suspicious", f"Suspicious cron: {path}")
                    )
            except OSError:
                continue

    # Recently modified binaries
    cutoff = datetime.now() - timedelta(days=7)
    for scan in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        if not os.path.isdir(scan):
            continue
        for fname in os.listdir(scan)[:100]:
            fp = os.path.join(scan, fname)
            try:
                if os.path.isfile(fp) and datetime.fromtimestamp(os.path.getmtime(fp)) > cutoff:
                    dpkg = run_cmd_safe(["dpkg", "-S", fp])
                    if not dpkg:
                        findings.append(
                            AuditFinding("HIGH", 6, "modified_bin", f"Recent binary not in dpkg: {fp}")
                        )
            except OSError:
                continue

    # Suspicious downloads in tmp
    for tmp in ("/tmp", "/var/tmp", "/dev/shm"):
        if not os.path.isdir(tmp):
            continue
        for entry in os.listdir(tmp):
            fp = os.path.join(tmp, entry)
            try:
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    mtime = datetime.fromtimestamp(os.path.getmtime(fp))
                    if mtime > cutoff:
                        findings.append(
                            AuditFinding("HIGH", 6, "tmp_executable", f"Recent executable: {fp}")
                        )
            except OSError:
                continue

    # NC-7: Systemd service integrity
    enabled = run_cmd_safe(["systemctl", "list-unit-files", "--type=service", "--state=enabled"])
    current_services = [ln.split()[0] for ln in enabled.splitlines() if ln.endswith("enabled")]
    for svc in current_services:
        if svc not in services_baseline and services_baseline:
            findings.append(
                AuditFinding("HIGH", 6, "NC-7-newsvc", f"New enabled service: {svc}")
            )
        cat = run_cmd_safe(["systemctl", "cat", svc])
        for line in cat.splitlines():
            if line.startswith("ExecStart="):
                val = line.split("=", 1)[1]
                if val.startswith(("/tmp", "/dev/shm", "/var/tmp")):
                    findings.append(
                        AuditFinding("CRITICAL", 6, "NC-7-execstart", f"ExecStart in tmp: {svc}")
                    )
    ab["services"] = current_services

    # Masked services
    masked = run_cmd_safe(["systemctl", "list-unit-files", "--state=masked"])
    for line in masked.splitlines():
        if any(s in line for s in ("fail2ban", "ssh", "auditd", "ufw")):
            findings.append(
                AuditFinding("MEDIUM", 6, "NC-7-masked", f"Security service masked: {line.strip()}")
            )

    return findings
