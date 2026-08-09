"""Auto-remediation for safe, deterministic audit findings.

Each handler function takes (finding: dict, cfg: dict) and returns
a RemediationResult.  Handlers are only called when the finding's
check_id appears in the config's ``auto_remediate.whitelist``.

Only findings that are safe to fix without human judgment are included.
"""
from __future__ import annotations

import logging
import os
import stat
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

logger = logging.getLogger("secmon.remediate")

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class RemediationResult:
    """Outcome of a single remediation attempt."""

    success: bool
    message: str          # e.g. "Removed /tmp/foo.html" or "chmod 600 /path"
    detail: str = ""      # extended explanation for the audit log

# ---------------------------------------------------------------------------
# Handler registry: check_id -> handler function
# ---------------------------------------------------------------------------

# Each handler follows the same signature:
#   handler(finding: dict, cfg: dict) -> RemediationResult | None
# Return None if the finding doesn't match this handler's criteria (skip).
# Return RemediationResult(success=True, ...) when fixed.
# Return RemediationResult(success=False, ...) when the fix failed.

_HANDLERS: dict[str, Callable[[dict, dict], RemediationResult | None]] = {}


def _register(check_id: str):
    """Decorator to register a handler for a given check_id."""
    def wrapper(fn):
        _HANDLERS[check_id] = fn
        return fn
    return wrapper


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

@_register("secret_pattern")
def _handle_secret_pattern(finding: dict, cfg: dict) -> RemediationResult | None:
    """Remove files in /tmp/ that matched a secret pattern.

    These are almost always transient artifacts from web scraping, research,
    or temp downloads — never legitimate secrets.
    """
    detail = finding.get("detail", {}) or {}
    path = detail.get("path", "")
    # Fallback: extract path from message "Secret material pattern in /tmp/..."
    if not path:
        msg = finding.get("message", "")
        for prefix in ("/tmp/", "/var/tmp/"):
            idx = msg.find(prefix)
            if idx != -1:
                path = msg[idx:].split(" - ")[0].split(":")[0].strip()
                break
    if not path or not path.startswith("/tmp/"):
        return None
    try:
        os.remove(path)
        return RemediationResult(True, f"Removed temp file `{path}`", "Scraped page with credential pattern - deleted")
    except OSError as exc:
        return RemediationResult(False, f"Failed to remove `{path}`: {exc}")


@_register("secret_key_tmp")
def _handle_secret_key_tmp(finding: dict, cfg: dict) -> RemediationResult | None:
    """Remove private keys or credentials found in /tmp/."""
    path = finding.get("detail", {}).get("path", "")
    if not path or not path.startswith("/tmp/"):
        return None
    try:
        os.remove(path)
        return RemediationResult(True, f"Removed temp credential `{path}`", "Credential in temp - deleted")
    except OSError as exc:
        return RemediationResult(False, f"Failed to remove `{path}`: {exc}")


@_register("world_writable")
def _handle_world_writable(finding: dict, cfg: dict) -> RemediationResult | None:
    """Remove world-writable permission from files/dirs owned by root.

    World-writable files owned by non-root users are intentionally shared
    resources (e.g. /tmp) and should not be auto-fixed.
    """
    path = finding.get("detail", {}).get("path", "")
    if not path:
        return None
    try:
        st = os.stat(path)
        # Only auto-fix root-owned world-writable items
        if st.st_uid != 0:
            return None
        # Remove 'other' write bit
        current_mode = stat.S_IMODE(st.st_mode)
        new_mode = current_mode & ~stat.S_IWOTH
        os.chmod(path, new_mode)
        return RemediationResult(True, f"Fixed permissions on `{path}` ({oct(current_mode)} → {oct(new_mode)})")
    except OSError as exc:
        return RemediationResult(False, f"Failed to fix `{path}`: {exc}")


@_register("secret_world_readable")
def _handle_secret_world_readable(finding: dict, cfg: dict) -> RemediationResult | None:
    """Restrict sensitive files to owner-only (chmod 600)."""
    path = finding.get("detail", {}).get("path", "")
    if not path:
        return None
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return RemediationResult(True, f"Restricted `{path}` to owner-only (600)", "Secret world-readable - fixed")
    except OSError as exc:
        return RemediationResult(False, f"Failed to restrict `{path}`: {exc}")


@_register("secret_authkeys_perm")
def _handle_authkeys_perm(finding: dict, cfg: dict) -> RemediationResult | None:
    """Fix SSH authorized_keys permissions (600)."""
    path = finding.get("detail", {}).get("path", "")
    if not path or "authorized_keys" not in path:
        return None
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return RemediationResult(True, f"Fixed authorized_keys permissions on `{path}`")
    except OSError as exc:
        return RemediationResult(False, f"Failed to fix `{path}`: {exc}")


@_register("hidden_tmp")
def _handle_hidden_tmp(finding: dict, cfg: dict) -> RemediationResult | None:
    """Remove hidden executable files in /tmp/ that are not whitelisted."""
    path = finding.get("detail", {}).get("path", "")
    if not path or not path.startswith("/tmp/"):
        return None
    # Skip known X11 / font sockets
    whitelisted = cfg.get("whitelist", {}).get("hidden_tmp_entries", [])
    basename = os.path.basename(path) if path else ""
    if basename in whitelisted:
        return None
    try:
        os.remove(path)
        return RemediationResult(True, f"Removed hidden temp file `{path}`")
    except OSError as exc:
        return RemediationResult(False, f"Failed to remove `{path}`: {exc}")


@_register("tmp_executable")
def _handle_tmp_executable(finding: dict, cfg: dict) -> RemediationResult | None:
    """Remove executable bit from files in temp directories."""
    path = finding.get("detail", {}).get("path", "")
    if not path:
        return None
    try:
        st = os.stat(path)
        current_mode = stat.S_IMODE(st.st_mode)
        new_mode = current_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if new_mode != current_mode:
            os.chmod(path, new_mode)
            return RemediationResult(True, f"Removed executable bit from `{path}`")
        return None  # already not executable — skip
    except OSError as exc:
        return RemediationResult(False, f"Failed to fix `{path}`: {exc}")


@_register("unattended")
def _handle_unattended(finding: dict, cfg: dict) -> RemediationResult | None:
    """Enable unattended-upgrades for automatic security patching."""
    try:
        # Check if already installed
        result = subprocess.run(
            ["dpkg", "-l", "unattended-upgrades"],
            capture_output=True, text=True, timeout=15,
        )
        if "ii" not in result.stdout:
            subprocess.run(
                ["apt-get", "install", "-y", "unattended-upgrades"],
                capture_output=True, text=True, timeout=120,
                check=True,
            )
            # Small delay so dpkg finishes
            time.sleep(0.5)

        subprocess.run(
            ["dpkg-reconfigure", "--frontend=noninteractive", "unattended-upgrades"],
            capture_output=True, text=True, timeout=30,
            check=True,
        )
        return RemediationResult(True, "Enabled unattended-upgrades", "auto-security-patching enabled")
    except subprocess.CalledProcessError as exc:
        return RemediationResult(False, f"Failed to enable unattended-upgrades: {exc.stderr[:200]}")
    except FileNotFoundError:
        return RemediationResult(False, "apt-get not found on this system")


@_register("nopasswd")
def _handle_nopasswd(finding: dict, cfg: dict) -> RemediationResult | None:
    """Fix NOPASSWD sudo entries — replace with password-required.

    Only fixes entries in /etc/sudoers.d/ (not the main sudoers file).
    """
    path = finding.get("detail", {}).get("path", "")
    if not path or not path.startswith("/etc/sudoers.d/"):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if "NOPASSWD" not in content:
            return None
        new_content = content.replace("NOPASSWD:", "")
        # If the entry becomes ALL:ALL with no password skip, replace with ALL
        new_content = new_content.replace("NOPASSWD", "")
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return RemediationResult(True, f"Removed NOPASSWD from `{path}`", "Sudo now requires password")
    except (OSError, PermissionError) as exc:
        return RemediationResult(False, f"Failed to fix `{path}`: {exc}")


@_register("systemd_failed")
def _handle_systemd_failed(finding: dict, cfg: dict) -> RemediationResult | None:
    """Restart failed systemd units (non-critical ones only).

    Does NOT restart units matching known critical infrastructure patterns.
    """
    unit = finding.get("detail", {}).get("unit", "")
    if not unit:
        return None
    # Skip critical system units
    skip_prefixes = ("systemd-", "network-", "sshd", "cron", "getty", "serial-")
    if any(unit.startswith(p) for p in skip_prefixes):
        return None
    try:
        result = subprocess.run(
            ["systemctl", "is-failed", unit],
            capture_output=True, text=True, timeout=15,
        )
        if result.stdout.strip() != "failed":
            return None
        subprocess.run(
            ["systemctl", "reset-failed", unit],
            capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["systemctl", "restart", unit],
            capture_output=True, text=True, timeout=30,
        )
        return RemediationResult(True, f"Restarted failed unit `{unit}`")
    except subprocess.TimeoutExpired:
        return RemediationResult(False, f"Timeout restarting `{unit}`")
    except FileNotFoundError:
        return RemediationResult(False, "systemctl not found")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def remediate(findings: list[dict], cfg: dict) -> list[dict]:
    """Run auto-remediation on findings that have registered handlers.

    Returns a copy of the findings list with successfully auto-remediated
    findings modified: severity → "INFO", message prefixed with "🟢 Auto-resolved:",
    and a new key ``auto_resolved`` = True.

    The original list is not mutated.
    """
    enabled = cfg.get("auto_remediate", {}).get("enabled", False)
    if not enabled:
        return findings

    whitelist = set(cfg.get("auto_remediate", {}).get("whitelist", []))
    if not whitelist:
        return findings

    updated = []
    for finding in findings:
        check_id = finding.get("check_id", "")
        if check_id not in whitelist or check_id not in _HANDLERS:
            updated.append(finding)
            continue

        handler = _HANDLERS[check_id]
        try:
            result = handler(finding, cfg)
            if result is None:
                updated.append(finding)
                continue
        except Exception as exc:
            logger.warning("remediation handler %s raised: %s", check_id, exc)
            updated.append(finding)
            continue

        if result.success:
            resolved = dict(finding)
            resolved["severity"] = "INFO"
            resolved["message"] = f"🟢 Auto-resolved: {result.message}"
            resolved["auto_resolved"] = True
            resolved["detail"] = dict(finding.get("detail", {}))
            resolved["detail"]["remediation"] = result.detail
            logger.info("Auto-resolved %s: %s", check_id, result.message)
            updated.append(resolved)
        else:
            # Failed — keep the original finding with a note
            failed = dict(finding)
            failed["message"] = f"{finding['message']} (auto-fix failed: {result.message})"
            updated.append(failed)

    return updated


def list_available_handlers() -> list[str]:
    """Return sorted list of check_ids that have registered handlers."""
    return sorted(_HANDLERS.keys())