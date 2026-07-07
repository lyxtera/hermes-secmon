"""auditd bridge for short-lived BPF syscall monitoring."""

from __future__ import annotations

import re
from typing import Any

from secmon.bpf.watchlist import ensure_bpf_state
from secmon.shell import run_cmd_safe


def read_audit_status() -> dict[str, int | None]:
    """Parse auditctl -s for lost and backlog counters."""
    out = run_cmd_safe(["auditctl", "-s"], timeout=10)
    result: dict[str, int | None] = {"lost": None, "backlog": None}
    if not out:
        return result
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("lost"):
            m = re.search(r"(\d+)", line)
            if m:
                result["lost"] = int(m.group(1))
        if "backlog" in line.lower():
            m = re.search(r"(\d+)", line)
            if m:
                result["backlog"] = int(m.group(1))
    return result


def check_audit_gap(state: dict) -> tuple[bool, dict[str, Any]]:
    """Return (gap_detected, detail) when audit lost/backlog increased."""
    bpf = ensure_bpf_state(state)
    last = bpf.setdefault("last_scan", {})
    status = read_audit_status()
    detail: dict[str, Any] = {
        "audit_lost": status.get("lost"),
        "audit_backlog": status.get("backlog"),
        "prev_lost": last.get("audit_lost"),
        "prev_backlog": last.get("audit_backlog"),
    }
    gap = False
    for key in ("lost", "backlog"):
        cur = status.get(key)
        prev = last.get(f"audit_{key}")
        if cur is not None and prev is not None and cur > prev:
            gap = True
    last["audit_lost"] = status.get("lost")
    last["audit_backlog"] = status.get("backlog")
    return gap, detail


def rules_file_installed() -> bool:
    return bool(run_cmd_safe(["test", "-f", "/etc/audit/rules.d/secmon-bpf.rules"]))


def recent_bpf_syscall_pids() -> list[int]:
    """Best-effort tail of bpf() syscall events via ausearch."""
    out = run_cmd_safe(
        ["ausearch", "-k", "secmon-bpf", "--start", "recent", "-i", "--raw"],
        timeout=15,
    )
    pids: set[int] = set()
    for line in out.splitlines():
        m = re.search(r"pid=(\d+)", line)
        if m:
            pids.add(int(m.group(1)))
    return sorted(pids)
