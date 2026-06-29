"""Layer 4: Authentication audit + NC-5."""

from __future__ import annotations

import glob
import hashlib
import os
import re

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    ab = state.setdefault("audit_baseline", {})
    users_baseline: dict = ab.setdefault("users", {})
    groups_baseline: dict = ab.setdefault("groups", {})

    # Parse passwd
    current_users: dict[str, dict] = {}
    if os.path.isfile("/etc/passwd"):
        for line in open("/etc/passwd", encoding="utf-8", errors="replace"):
            parts = line.strip().split(":")
            if len(parts) >= 7:
                current_users[parts[0]] = {
                    "uid": int(parts[2]),
                    "shell": parts[6],
                }

    # NC-5: User account integrity
    for user, info in current_users.items():
        if info["uid"] == 0 and user != "root":
            findings.append(
                AuditFinding("CRITICAL", 4, "NC-5-uid0", f"Non-root UID 0 account: {user}")
            )
        if user not in users_baseline and user not in ("nobody",):
            findings.append(
                AuditFinding("MEDIUM", 4, "NC-5-newuser", f"New user account: {user}")
            )
    users_baseline.update({u: v for u, v in current_users.items()})

    # Empty passwords in shadow
    if os.path.isfile("/etc/shadow"):
        for line in open("/etc/shadow", encoding="utf-8", errors="replace"):
            parts = line.strip().split(":")
            if len(parts) >= 2:
                user, pw = parts[0], parts[1]
                shell = current_users.get(user, {}).get("shell", "")
                if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                    if pw in ("", "!", "*", ""):
                        if pw == "":
                            findings.append(
                                AuditFinding("CRITICAL", 4, "NC-5-emptypw", f"Empty password: {user}")
                            )

    # Group membership changes
    priv_groups = ("sudo", "wheel", "admin", "docker")
    if os.path.isfile("/etc/group"):
        for line in open("/etc/group", encoding="utf-8", errors="replace"):
            parts = line.strip().split(":")
            if len(parts) >= 4:
                gname, members = parts[0], parts[3]
                if gname in priv_groups:
                    prev = set(groups_baseline.get(gname, []))
                    cur = set(members.split(",")) if members else set()
                    cur.discard("")
                    new_members = cur - prev
                    for m in new_members:
                        if m:
                            findings.append(
                                AuditFinding(
                                    "HIGH", 4, "NC-5-privgroup",
                                    f"New member {m} in group {gname}",
                                )
                            )
                    groups_baseline[gname] = sorted(cur)

    # SSH config audit
    sshd_cfg = run_cmd_safe(["sshd", "-T"])
    checks = {
        "maxauthtries": ("3", "MEDIUM"),
        "permitemptypasswords": ("no", "HIGH"),
        "x11forwarding": ("no", "LOW"),
    }
    skip_root = cfg.get("hardening", {}).get("skip_root_login_check", False)
    skip_pw = cfg.get("hardening", {}).get("skip_password_auth_check", False)
    if not skip_root:
        checks["permitrootlogin"] = ("no", "HIGH")
    if not skip_pw:
        checks["passwordauthentication"] = ("no", "HIGH")
    for key, (expected, sev) in checks.items():
        m = re.search(rf"^{key}\s+(\S+)", sshd_cfg, re.MULTILINE | re.IGNORECASE)
        if m and m.group(1).lower() != expected:
            findings.append(
                AuditFinding(sev, 4, "sshd_config", f"sshd {key}={m.group(1)} (expected {expected})")
            )

    # NOPASSWD
    for path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
        if not os.path.isfile(path):
            continue
        try:
            for i, line in enumerate(open(path, encoding="utf-8", errors="replace")):
                if "NOPASSWD" in line and not line.strip().startswith("#"):
                    findings.append(
                        AuditFinding("MEDIUM", 4, "nopasswd", f"NOPASSWD in {path}:{i+1}")
                    )
        except OSError:
            continue

    # Authorized keys
    key_hashes: dict = ab.setdefault("authorized_keys_hashes", {})
    for path in glob.glob("/root/.ssh/authorized_keys") + glob.glob("/home/*/.ssh/authorized_keys"):
        try:
            content = open(path, "rb").read()
            h = hashlib.sha256(content).hexdigest()
            if path in key_hashes and key_hashes[path] != h:
                findings.append(
                    AuditFinding("HIGH", 4, "NC-5-authkeys", f"authorized_keys changed: {path}")
                )
            key_hashes[path] = h
        except OSError:
            continue

    # Brute-force stats
    jout = run_cmd_safe(["journalctl", "--since", "24 hours ago"], timeout=30)
    failed = jout.count("Failed password")
    accepted = jout.count("Accepted")
    if failed > 100:
        findings.append(
            AuditFinding("INFO", 4, "ssh_stats", f"SSH failed={failed} accepted={accepted} in 24h")
        )

    return findings
