"""Shared utilities."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def extract_ips(text: str) -> list[str]:
    ips: list[str] = []
    for match in IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            ips.append(match)
        except ValueError:
            continue
    for match in IPV6_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            ips.append(match)
        except ValueError:
            continue
    return ips


def subnet_24(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = str(addr).split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return str(addr)
    except ValueError:
        return ip


def sanitize_message(msg: str, max_len: int = 500) -> str:
    """Remove control chars to prevent log injection."""
    cleaned = "".join(c for c in msg if c == "\t" or (ord(c) >= 32 and ord(c) != 127))
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "..."
    return cleaned


def is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def ip_in_prefixes(ip: str, prefixes: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for prefix in prefixes:
            try:
                if addr in ipaddress.ip_network(prefix, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False
