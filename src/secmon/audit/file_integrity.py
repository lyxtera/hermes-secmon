"""Layer 1: File integrity."""

from __future__ import annotations

import hashlib
import os

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe

CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/resolv.conf",
]

DEBIAN_SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/bin/mount",
    "/bin/umount",
    "/bin/su",
}


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    ab = state.setdefault("audit_baseline", {})
    hashes: dict = ab.setdefault("file_hashes", {})

    for path in CRITICAL_FILES:
        if not os.path.isfile(path):
            if path in hashes:
                findings.append(
                    AuditFinding("CRITICAL", 1, "file_removed", f"Critical file removed: {path}")
                )
            continue
        current = _sha256(path)
        if current is None:
            continue
        if path in hashes and hashes[path] != current:
            findings.append(
                AuditFinding(
                    "CRITICAL", 1, "file_changed", f"Critical file changed: {path}",
                    {"path": path},
                )
            )
        elif path not in hashes:
            findings.append(
                AuditFinding("INFO", 1, "file_baseline", f"Baselined: {path}")
            )
        hashes[path] = current

    # SUID audit via find (mockable, no full /usr walk)
    suid_out = run_cmd_safe(["find", "/usr", "-xdev", "-perm", "-4000", "-type", "f"], timeout=60)
    suid_found = [ln.strip() for ln in suid_out.splitlines() if ln.strip()]
    for fp in suid_found:
        if fp not in DEBIAN_SUID_WHITELIST and fp not in ab.get("suid_cache", []):
            findings.append(
                AuditFinding("HIGH", 1, "unexpected_suid", f"Unexpected SUID: {fp}")
            )
    ab["suid_cache"] = suid_found

    # World-writable via find on system dirs
    for scan_root in ("/etc", "/usr", "/bin", "/sbin", "/lib"):
        ww_out = run_cmd_safe(
            ["find", scan_root, "-xdev", "-perm", "-0002", "-type", "f"], timeout=30
        )
        for fp in ww_out.splitlines():
            fp = fp.strip()
            if fp:
                findings.append(
                    AuditFinding("CRITICAL", 1, "world_writable", f"World-writable: {fp}")
                )

    # Hidden files in tmp areas
    hidden_whitelist = set(cfg.get("whitelist", {}).get("hidden_tmp_entries", []))
    for tmp_dir in ("/tmp", "/var/tmp", "/dev/shm"):
        if not os.path.isdir(tmp_dir):
            continue
        try:
            entries = os.listdir(tmp_dir)
        except OSError:
            continue
        for entry in entries:
            if entry.startswith(".") and "systemd-private" not in entry and "X11" not in entry:
                if entry in hidden_whitelist:
                    continue
                findings.append(
                    AuditFinding("MEDIUM", 1, "hidden_tmp", f"Hidden entry in {tmp_dir}: {entry}")
                )

    # ld.so.preload
    preload = "/etc/ld.so.preload"
    if os.path.isfile(preload):
        try:
            content = open(preload, encoding="utf-8").read().strip()
            if content:
                findings.append(
                    AuditFinding(
                        "CRITICAL", 1, "ld_preload", "/etc/ld.so.preload has content",
                        {"content": content[:200]},
                    )
                )
        except OSError:
            pass

    # /tmp sticky bit
    if os.path.isdir("/tmp"):
        import stat
        st = os.stat("/tmp")
        if not (st.st_mode & stat.S_ISVTX):
            findings.append(AuditFinding("HIGH", 1, "tmp_sticky", "/tmp missing sticky bit"))
        if not (st.st_mode & stat.S_IWOTH):
            findings.append(AuditFinding("MEDIUM", 1, "tmp_writable", "/tmp not world-writable"))

    return findings
