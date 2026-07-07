"""Layer 6: Threat intelligence + NC-7 + persistence baseline + secrets."""

from __future__ import annotations

import glob
import hashlib
import os
import pwd
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

PERSISTENCE_PATHS = [
    "/etc/rc.local",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/root/.bashrc",
    "/root/.profile",
]

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*="),
    re.compile(r"api[_-]?key\s*[:=]", re.I),
]

SECRET_FILENAMES = {"id_rsa", "id_ecdsa", "id_ed25519", ".env", "credentials", "secrets.json"}


def _file_hash(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                h.update(chunk)
        return h.hexdigest()
    except (OSError, TypeError):
        return None


def _collect_persistence_entries() -> dict[str, str]:
    entries: dict[str, str] = {}
    for path in PERSISTENCE_PATHS:
        if os.path.isfile(path):
            digest = _file_hash(path)
            if digest:
                entries[path] = digest
    for path in glob.glob("/etc/cron.*/*") + glob.glob("/var/spool/cron/crontabs/*"):
        if os.path.isfile(path):
            digest = _file_hash(path)
            if digest:
                entries[path] = digest
    crontab = run_cmd_safe(["crontab", "-l"])
    if crontab.strip() and "no crontab" not in crontab.lower():
        entries["crontab:root"] = hashlib.sha256(crontab.encode()).hexdigest()
    atq = run_cmd_safe(["atq"])
    if atq.strip():
        entries["atq"] = hashlib.sha256(atq.encode()).hexdigest()
    timers = run_cmd_safe(["systemctl", "list-timers", "--all", "--no-pager"])
    if timers.strip():
        # Strip dynamic columns (NEXT, LEFT, LAST, PASSED) — only hash stable UNIT + ACTIVATES
        stable = set()
        for line in timers.splitlines():
            if line.strip() and not line.startswith("NEXT"):
                parts = line.rsplit(None, 2)  # split from right: UNIT | ACTIVATES
                if len(parts) >= 2:
                    stable.add(f"{parts[-2]} {parts[-1]}")
        hash_input = "\n".join(sorted(stable))
        entries["systemd_timers"] = hashlib.sha256(hash_input.encode()).hexdigest()
    for override in glob.glob("/etc/systemd/system/**/*.d/*.conf", recursive=True):
        if os.path.isfile(override):
            digest = _file_hash(override)
            if digest:
                entries[override] = digest
    for unit in glob.glob("/etc/systemd/system/*.service"):
        if os.path.isfile(unit):
            digest = _file_hash(unit)
            if digest:
                entries[unit] = digest
    for home in glob.glob("/home/*/.config/systemd/user/*.service"):
        if os.path.isfile(home):
            digest = _file_hash(home)
            if digest:
                entries[home] = digest
    return entries


def _persistence_severity(path: str, content_hint: str = "") -> str:
    if any(p in path for p in ("/tmp", "/var/tmp", "/dev/shm")):
        return "CRITICAL"
    if "curl | bash" in content_hint or "wget -" in content_hint:
        return "CRITICAL"
    if path.startswith("/etc/systemd") or "crontab" in path or "cron" in path:
        return "HIGH"
    return "MEDIUM"


def _is_excluded(fp: str, exclude_paths: set[str]) -> bool:
    """Check if fp matches any exclude path exactly or as a directory prefix."""
    if fp in exclude_paths:
        return True
    for ex in exclude_paths:
        if fp.startswith(ex + "/") or fp.startswith(ex + os.sep):
            return True
    return False


def _scan_secrets(cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    exclude_paths = set(cfg.get("whitelist", {}).get("secret_exclude_paths", []))
    scan_roots = ["/tmp", "/var/tmp", "/dev/shm", "/root"]
    for web in WEB_ROOTS:
        if os.path.isdir(web):
            scan_roots.append(web)
    for root in scan_roots:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, files in os.walk(root):
                depth = dirpath[len(root) :].count(os.sep)
                if depth > 3:
                    continue
                for fname in files:
                    fp = os.path.join(dirpath, fname)
                    if _is_excluded(fp, exclude_paths):
                        continue
                    if fname in SECRET_FILENAMES or fname.endswith((".pem", ".key", ".env")):
                        try:
                            st = os.stat(fp)
                            mode = st.st_mode & 0o777
                            if mode & 0o004:
                                findings.append(
                                    AuditFinding(
                                        "CRITICAL", 6, "secret_world_readable",
                                        f"World-readable secret file: {fp}",
                                        {"path": fp, "mode": oct(mode)},
                                    )
                                )
                            elif fname in ("id_rsa", "id_ecdsa", "id_ed25519") and root in (
                                "/tmp", "/var/tmp", "/dev/shm"
                            ):
                                findings.append(
                                    AuditFinding(
                                        "CRITICAL", 6, "secret_key_tmp",
                                        f"Private key in temp directory: {fp}",
                                    )
                                )
                        except OSError:
                            continue
                    try:
                        if os.path.getsize(fp) > 500_000:
                            continue
                        if _is_excluded(fp, exclude_paths):
                            continue
                        sample = open(fp, encoding="utf-8", errors="replace").read(8000)
                        for pat in SECRET_PATTERNS:
                            if pat.search(sample):
                                findings.append(
                                    AuditFinding(
                                        "HIGH", 6, "secret_pattern",
                                        f"Secret material pattern in {fp}",
                                    )
                                )
                                break
                    except OSError:
                        continue
        except OSError:
            continue
    # SSH authorized_keys world-readable
    try:
        for user in pwd.getpwall():
            ak = os.path.join(user.pw_dir, ".ssh", "authorized_keys")
            if os.path.isfile(ak):
                try:
                    mode = os.stat(ak).st_mode & 0o777
                    if mode & 0o044:
                        findings.append(
                            AuditFinding(
                                "HIGH", 6, "secret_authkeys_perm",
                                f"World/group-readable authorized_keys: {user.pw_name}",
                            )
                        )
                except OSError:
                    continue
    except (OSError, KeyError):
        pass
    return findings


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
                    real_fp = os.path.realpath(fp)
                    dpkg = run_cmd_safe(["dpkg", "-S", real_fp])
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

    # Persistence baseline diff
    current_persist = _collect_persistence_entries()
    persist_baseline: dict = ab.setdefault("persistence", {})
    exclude_prefixes = tuple(cfg.get("whitelist", {}).get("persist_exclude_prefixes", []))
    if persist_baseline:
        for path, digest in current_persist.items():
            if exclude_prefixes and path.startswith(exclude_prefixes):
                continue
            prev = persist_baseline.get(path)
            if prev is None:
                sev = _persistence_severity(path)
                findings.append(
                    AuditFinding(
                        sev, 6, "persist_new",
                        f"New persistence entry: {path}",
                        {"path": path},
                    )
                )
            elif prev != digest:
                try:
                    hint = open(path, encoding="utf-8", errors="replace").read(500)
                except OSError:
                    hint = ""
                sev = _persistence_severity(path, hint)
                findings.append(
                    AuditFinding(
                        sev, 6, "persist_modified",
                        f"Modified persistence entry: {path}",
                        {"path": path},
                    )
                )
        for path in persist_baseline:
            if path not in current_persist:
                findings.append(
                    AuditFinding(
                        "MEDIUM", 6, "persist_removed",
                        f"Persistence entry removed: {path}",
                    )
                )
    ab["persistence"] = current_persist

    # systemd timers (NC-7 extension)
    timer_units = run_cmd_safe(
        ["systemctl", "list-unit-files", "--type=timer", "--state=enabled"]
    )
    timer_list = [ln.split()[0] for ln in timer_units.splitlines() if ln.endswith("enabled")]
    timer_baseline: list = ab.setdefault("timers", [])
    for timer in timer_list:
        if timer_baseline and timer not in timer_baseline:
            cat = run_cmd_safe(["systemctl", "cat", timer])
            sev = "HIGH"
            if any(p in cat for p in ("/tmp", "/var/tmp", "/dev/shm", "curl", "wget")):
                sev = "CRITICAL"
            findings.append(
                AuditFinding(sev, 6, "NC-7-newtimer", f"New enabled timer: {timer}")
            )
    ab["timers"] = timer_list

    findings.extend(_scan_secrets(cfg))

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
