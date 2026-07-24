"""Layer 7: Compliance + NC-4, NC-8, NC-10."""

from __future__ import annotations

import glob
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe


SYSCTL_EXPECTED = {
    "kernel.kptr_restrict": "1",
    "kernel.yama.ptrace_scope": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.tcp_syncookies": "1",
    "kernel.randomize_va_space": "2",
    "fs.suid_dumpable": "0",
}


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    for key, expected in SYSCTL_EXPECTED.items():
        val = run_cmd_safe(["sysctl", "-n", key]).strip()
        if not val:
            continue
        if val != expected:
            # Check if config allows multiple acceptable values for this key
            expected_overrides = cfg.get("sysctl", {}).get("expected_values", {})
            if key in expected_overrides:
                acceptable = expected_overrides[key]
                if isinstance(acceptable, list) and val in acceptable:
                    continue
                if val == acceptable:
                    continue
            findings.append(
                AuditFinding("MEDIUM", 7, "sysctl", f"{key}={val} (expected {expected})")
            )

    # Security updates
    upgrades = run_cmd_safe(["apt", "list", "--upgradable"])
    sec_count = sum(1 for ln in upgrades.splitlines() if "security" in ln.lower())
    if sec_count > 0:
        findings.append(
            AuditFinding("MEDIUM", 7, "sec_updates", f"{sec_count} security upgrades pending")
        )
    ua = run_cmd_safe(["dpkg", "-l", "unattended-upgrades"])
    if "unattended-upgrades" not in ua:
        findings.append(
            AuditFinding("MEDIUM", 7, "unattended", "unattended-upgrades not installed")
        )

    # Password aging
    if os.path.isfile("/etc/login.defs"):
        for line in open("/etc/login.defs", encoding="utf-8", errors="replace"):
            if line.startswith("PASS_MAX_DAYS") and not line.strip().startswith("#"):
                parts = line.split()
                if len(parts) >= 2 and int(parts[1]) > 365:
                    findings.append(
                        AuditFinding("LOW", 7, "pass_aging", f"PASS_MAX_DAYS={parts[1]}")
                    )

    # NC-4: TLS certificate hygiene
    cert_dirs = ["/etc/ssl/certs", "/etc/letsencrypt/live"]
    now = datetime.now(timezone.utc)
    cert_exclude = set(cfg.get("hardening", {}).get("cert_exclude_paths", []))
    for cert_dir in cert_dirs:
        if not os.path.isdir(cert_dir):
            continue
        for path in glob.glob(f"{cert_dir}/**/*.pem", recursive=True) + glob.glob(
            f"{cert_dir}/**/cert.pem", recursive=True
        ):
            if "privkey" in path:
                continue
            text = run_cmd_safe(["openssl", "x509", "-in", path, "-noout", "-enddate"])
            m = re.search(r"notAfter=(.+)", text)
            if m:
                try:
                    exp = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days = (exp - now).days
                    if path in cert_exclude:
                        continue
                    if days < 0:
                        findings.append(
                            AuditFinding("HIGH", 7, "NC-4-expired", f"Expired cert: {path}")
                        )
                    elif days < 7:
                        findings.append(
                            AuditFinding("HIGH", 7, "NC-4-expiring", f"Cert expires in {days}d: {path}")
                        )
                    elif days < 30:
                        findings.append(
                            AuditFinding("MEDIUM", 7, "NC-4-soon", f"Cert expires in {days}d: {path}")
                        )
                except ValueError:
                    pass

    # NC-8: Time sync
    timedate = run_cmd_safe(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip()
    if timedate == "no":
        findings.append(AuditFinding("MEDIUM", 7, "NC-8-ntp", "NTP not synchronized"))
    chrony = run_cmd_safe(["chronyc", "tracking"])
    if chrony:
        m = re.search(r"System time\s*:\s*([0-9.]+)\s*seconds", chrony)
        if m:
            drift = float(m.group(1))
            if drift > 60:
                findings.append(
                    AuditFinding("HIGH", 7, "NC-8-drift", f"Time drift {drift}s")
                )
            elif drift > 5:
                findings.append(
                    AuditFinding("LOW", 7, "NC-8-drift", f"Time drift {drift}s")
                )

    # NC-10: Supply chain
    debsums = run_cmd_safe(["which", "debsums"])
    if not debsums.strip():
        findings.append(
            AuditFinding("LOW", 7, "NC-10-nodebsums", "debsums not installed (recommended)")
        )
    elif not cfg.get("hardening", {}).get("skip_debsums_check", False):
        bad = run_cmd_safe(["debsums", "-c"], timeout=60)
        if bad.strip():
            critical_pkgs = ("openssh", "sudo", "libc", "systemd")
            for line in bad.splitlines()[:20]:
                if any(p in line for p in critical_pkgs):
                    findings.append(
                        AuditFinding("HIGH", 7, "NC-10-critical", f"Modified critical file: {line[:120]}")
                    )
                else:
                    findings.append(
                        AuditFinding("MEDIUM", 7, "NC-10-modified", f"Modified package file: {line[:120]}")
                    )

    for sl in ("/etc/apt/sources.list",) + tuple(glob.glob("/etc/apt/sources.list.d/*")):
        if os.path.isfile(sl):
            content = open(sl, encoding="utf-8", errors="replace").read()
            if "deb http://" in content and "debian.org" not in content:
                findings.append(
                    AuditFinding("MEDIUM", 7, "NC-10-apt", f"Non-standard apt source in {sl}")
                )

    return findings
