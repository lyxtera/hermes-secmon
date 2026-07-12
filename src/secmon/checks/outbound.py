"""Suspicious outbound connection monitor — TC-8 + C2 behavior."""

from __future__ import annotations

import os
import re

from secmon.alerts import Alert
from secmon.shell import run_cmd_safe
from secmon.utils import is_private_or_loopback, ip_in_prefixes, parse_iso, utcnow

C2_PORTS = {443, 8443, 853, 4443, 4444, 5555, 9001, 9050, 9150}
DOH_HOST_PATTERNS = ("dns.google", "cloudflare-dns.com", "dns.quad9.net")


def _is_suspicious_port(port: int, cfg: dict) -> bool:
    sp = cfg.get("suspicious_ports", {})
    if port in sp.get("specific", []):
        return True
    for rng in sp.get("ranges", []):
        if len(rng) == 2 and rng[0] <= port <= rng[1]:
            return True
    return False


def _get_pid(line: str) -> int:
    """Extract PID from an ss -tnp line.

    ss output:  users:((\"processname\",pid=1234,fd=N))
    """
    m = re.search(r'pid=(\d+)', line)
    return int(m.group(1)) if m else 0


def _process_owner(line: str) -> str:
    m = re.search(r'users:\(\("([^"]+)"', line)
    return m.group(1) if m else ""


def _is_direct_ip_https(dest_ip: str, port: int) -> bool:
    return port in (443, 8443) and not is_private_or_loopback(dest_ip)


def _get_comm(pid: int) -> str:
    """Read the process command name from /proc/pid/comm."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except (OSError, IOError):
        return ""


def _get_ppid(pid: int) -> int:
    """Read the parent PID from /proc/pid/status."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, IOError, ValueError):
        pass
    return 0


def _ancestor_has(pid: int, target: str) -> bool:
    """Walk the process tree upward checking if any ancestor's comm matches target.

    Returns True if target is found in the ancestor chain (excluding the process
    itself).  Maximum depth 32 to prevent infinite loops from kernel pid
    namespace cycles.
    """
    depth = 0
    ppid = _get_ppid(pid)
    while ppid > 0 and depth < 32:
        comm = _get_comm(ppid)
        if comm == target:
            return True
        ppid = _get_ppid(ppid)
        depth += 1
    return False


def _is_whitelisted(dest_ip: str, dest_port: int, owner: str, pid: int, cfg: dict) -> bool:
    """Check if a connection matches a whitelisted outbound destination.

    Supports three constraint patterns in the whitelist entry:
      - ``process`` only              — whitelist ALL from this process (legacy)
      - ``process`` + ``cidr``/``ip``  — whitelist process connections to that
                                         destination
      - ``process`` + ``parent_process`` — whitelist process connections whose
                                         ancestor chain includes the named
                                         parent (e.g. ``hermes`` → legitimate
                                         git clone/pull)
    """
    entries = cfg.get("whitelist", {}).get("outbound_destinations", [])
    for entry in entries:
        proc = entry.get("process", "")
        if proc and owner != proc:
            continue

        # Parent-process constraint: walk the tree
        parent_proc = entry.get("parent_process", "")
        if parent_proc:
            if not pid or not _ancestor_has(pid, parent_proc):
                continue  # parent not in chain — don't whitelist

        # IP/CIDR constraint
        cidr = entry.get("cidr", "")
        ip = entry.get("ip", "")
        if cidr:
            if ip_in_prefixes(dest_ip, [cidr]):
                return True
            continue
        if ip:
            if dest_ip == ip:
                return True
            continue

        # Process-only entry (no IP/CIDR) — whitelist all from this process
        if proc:
            return True
        continue
    return False


def check(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    ms = state.setdefault("monitor_state", {})
    conn_tracker: dict = ms.setdefault("outbound_connections", {})
    now = utcnow()
    seen_keys: set[str] = set()

    out = run_cmd_safe(["ss", "-tnp", "state", "established"])
    for line in out.splitlines():
        if "127.0.0.1" in line or "::1" in line:
            continue
        pairs = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if len(pairs) < 2:
            continue
        local_ip, local_port = pairs[0]
        dest_ip, dest_port = pairs[1]
        dest_port = int(dest_port)
        if is_private_or_loopback(dest_ip):
            continue
        owner = _process_owner(line)
        pid = _get_pid(line)
        conn_key = f"{dest_ip}:{dest_port}:{owner}"
        seen_keys.add(conn_key)

        # Skip whitelisted destinations (Telegram, Hermes, git-from-Hermes, etc.)
        if _is_whitelisted(dest_ip, dest_port, owner, pid, cfg):
            continue

        first_seen = conn_tracker.get(conn_key)
        if not first_seen:
            conn_tracker[conn_key] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            if owner in ("root", "www-data", "nginx", "apache"):
                alerts.append(
                    Alert(
                        severity="HIGH",
                        source="outbound",
                        message=f"New outbound from privileged process {owner} to {dest_ip}:{dest_port}",
                        dedup_key=f"c2:new_priv:{dest_ip}:{dest_port}:{owner}",
                        structured={
                            "dest_ip": dest_ip,
                            "dest_port": dest_port,
                            "owner": owner,
                        },
                    )
                )
        else:
            started = parse_iso(first_seen)
            if started and (now - started).total_seconds() > 3600:
                alerts.append(
                    Alert(
                        severity="HIGH",
                        source="outbound",
                        message=f"Long-lived outbound connection to {dest_ip}:{dest_port} ({owner})",
                        dedup_key=f"c2:long:{dest_ip}:{dest_port}",
                        structured={"age_seconds": int((now - started).total_seconds())},
                    )
                )

        if _is_suspicious_port(dest_port, cfg):
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="outbound",
                    message=f"Suspicious outbound connection to {dest_ip}:{dest_port}",
                    dedup_key=f"outbound:{dest_ip}:{dest_port}",
                    structured={"dest_ip": dest_ip, "dest_port": dest_port, "line": line.strip()},
                )
            )

        if _is_direct_ip_https(dest_ip, dest_port) and owner not in ("", "systemd-resolve"):
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="outbound",
                    message=f"Direct-IP HTTPS session to {dest_ip}:{dest_port} ({owner})",
                    dedup_key=f"c2:direct_https:{dest_ip}:{dest_port}",
                    structured={"owner": owner},
                )
            )

        if dest_port in C2_PORTS and owner in ("root", "www-data", "nobody"):
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="outbound",
                    message=f"Privileged outbound to common C2 port {dest_ip}:{dest_port}",
                    dedup_key=f"c2:port:{dest_ip}:{dest_port}",
                )
            )

    # Prune stale connection tracker entries (>48h)
    cutoff = now.timestamp() - 48 * 3600
    for key, ts in list(conn_tracker.items()):
        if key not in seen_keys:
            parsed = parse_iso(ts)
            if parsed and parsed.timestamp() < cutoff:
                del conn_tracker[key]

    return alerts