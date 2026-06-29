"""Metric collection with TTL cache."""

from __future__ import annotations

import logging
import os
import re
from datetime import timedelta

from secmon.config import METRIC_KEYS
from secmon.shell import run_cmd_safe
from secmon.utils import extract_ips, subnet_24, utcnow, parse_iso

logger = logging.getLogger("secmon.metrics")

# In-process cache (per spec §5.3)
_cache: dict | None = None
_cache_ts = None


def invalidate_cache() -> None:
    global _cache, _cache_ts
    _cache = None
    _cache_ts = None


def _cache_fresh(cfg: dict) -> bool:
    global _cache, _cache_ts
    if _cache is None or _cache_ts is None:
        return False
    ttl = cfg["anomaly"]["cache_ttl_seconds"]
    return (utcnow() - _cache_ts).total_seconds() < ttl


def collect_metrics(cfg: dict, *, force: bool = False) -> dict[str, int]:
    global _cache, _cache_ts
    if not force and _cache_fresh(cfg):
        return dict(_cache)

    metrics = {k: 0 for k in METRIC_KEYS}
    _collect_ssh_metrics(metrics)
    _collect_f2b(metrics)
    _collect_botnet_rules(metrics)
    _collect_kernel(metrics)
    _collect_network(metrics)
    _collect_new_blocks(cfg, metrics)

    _cache = dict(metrics)
    _cache_ts = utcnow()
    return metrics


def collect_metrics_from_state(cfg: dict, state: dict, *, force: bool = False) -> dict[str, int]:
    """Use persisted metric_cache in state when process cache cold."""
    if not force and _cache_fresh(cfg):
        return dict(_cache)
    mc = state.get("metric_cache", {})
    ts = parse_iso(mc.get("timestamp"))
    ttl = cfg["anomaly"]["cache_ttl_seconds"]
    if not force and ts and mc.get("values") and (utcnow() - ts).total_seconds() < ttl:
        return {k: int(mc["values"].get(k, 0)) for k in METRIC_KEYS}
    metrics = collect_metrics(cfg, force=force)
    state["metric_cache"] = {"timestamp": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "values": metrics}
    return metrics


def _collect_ssh_metrics(metrics: dict) -> None:
    try:
        out = run_cmd_safe(["journalctl", "--since", "24 hours ago"], timeout=60)
        metrics["ssh_failed_24h"] = out.count("Failed password")
        metrics["ssh_invalid_user_24h"] = out.count("Invalid user")
        ips = extract_ips(out)
        # Filter to lines that look like auth failures
        auth_ips = []
        for line in out.splitlines():
            if "Failed password" in line or "Invalid user" in line:
                auth_ips.extend(extract_ips(line))
        if not auth_ips:
            auth_ips = ips
        unique = set(auth_ips)
        metrics["unique_attacker_ips"] = len(unique)
        subnets = {subnet_24(ip) for ip in unique}
        metrics["unique_attacker_subnets"] = len(subnets)
    except Exception as exc:
        logger.error("ssh metrics failed: %s", exc)


def _collect_f2b(metrics: dict) -> None:
    try:
        out = run_cmd_safe(["fail2ban-client", "status", "sshd"])
        m = re.search(r"Currently banned:\s*(\d+)", out)
        metrics["f2b_banned_count"] = int(m.group(1)) if m else 0
    except Exception as exc:
        logger.error("fail2ban metric failed: %s", exc)


def _collect_botnet_rules(metrics: dict) -> None:
    try:
        out = run_cmd_safe(["iptables", "-L", "BOTNET", "-n"])
        metrics["botnet_chain_rules"] = sum(1 for line in out.splitlines() if "DROP" in line)
    except Exception as exc:
        logger.error("botnet rules metric failed: %s", exc)


def _collect_kernel(metrics: dict) -> None:
    try:
        kout = run_cmd_safe(["journalctl", "-k", "--since", "24 hours ago"], timeout=60)
        metrics["martian_packets_24h"] = kout.lower().count("martian")
        err_out = run_cmd_safe(
            ["journalctl", "-k", "--since", "24 hours ago", "--priority=err"], timeout=60
        )
        lines = [
            ln
            for ln in err_out.splitlines()
            if ln.strip() and "regulatory.db" not in ln and "wireless-regdb" not in ln
        ]
        metrics["kernel_errors_24h"] = len(lines)
    except Exception as exc:
        logger.error("kernel metrics failed: %s", exc)


def _collect_network(metrics: dict) -> None:
    try:
        listen = run_cmd_safe(["ss", "-tlnp"])
        listen_lines = [ln for ln in listen.splitlines() if ln.strip() and not ln.startswith("State")]
        metrics["listening_ports_count"] = len(listen_lines)
        estab = run_cmd_safe(["ss", "-tnp", "state", "established"])
        estab_lines = [
            ln
            for ln in estab.splitlines()
            if ln.strip()
            and not ln.startswith("State")
            and "127.0.0.1" not in ln
            and "::1" not in ln
        ]
        metrics["established_conns"] = len(estab_lines)
    except Exception as exc:
        logger.error("network metrics failed: %s", exc)


def _collect_new_blocks(cfg: dict, metrics: dict) -> None:
    try:
        log_path = cfg["general"].get("botnet_log_file", "/var/log/secmon-botnet.log")
        if not os.path.isfile(log_path):
            metrics["new_blocked_subnets_24h"] = 0
            return
        cutoff = utcnow() - timedelta(hours=24)
        count = 0
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "BLOCKED" not in line:
                    continue
                # optional ISO timestamp prefix
                if len(line) >= 20:
                    try:
                        ts = parse_iso(line[:20] + "Z" if "T" in line[:20] else None)
                        if ts and ts < cutoff:
                            continue
                    except Exception:
                        pass
                count += 1
        metrics["new_blocked_subnets_24h"] = count
    except Exception as exc:
        logger.error("new blocks metric failed: %s", exc)
