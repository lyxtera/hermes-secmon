"""Botnet /24 detection and iptables blocking."""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict

from secmon.alerts import Alert
from secmon.shell import run_cmd, run_cmd_safe
from secmon.utils import extract_ips, ip_in_prefixes, subnet_24, utcnow_iso

logger = logging.getLogger("secmon.botnet")


def get_blocked_subnets() -> set[str]:
    out = run_cmd_safe(["iptables", "-L", "BOTNET", "-n"])
    subnets: set[str] = set()
    for line in out.splitlines():
        m = re.search(r"DROP\s+all\s+--\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            subnets.add(f"{m.group(1)}/{m.group(2)}")
        else:
            m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m2 and "DROP" in line:
                subnets.add(subnet_24(m2.group(1)))
    return subnets


def ensure_botnet_chain() -> bool:
    run_cmd_safe(["iptables", "-N", "BOTNET"])
    # Check if jump exists
    input_rules = run_cmd_safe(["iptables", "-L", "INPUT", "-n"])
    if "BOTNET" not in input_rules:
        try:
            run_cmd(["iptables", "-I", "INPUT", "-j", "BOTNET"], timeout=10)
        except Exception as exc:
            logger.error("failed to insert BOTNET jump: %s", exc)
            return False
    return True


def _is_whitelisted(subnet: str, cfg: dict) -> bool:
    prefixes = list(cfg.get("whitelist", {}).get("network_prefixes", []))
    own = cfg.get("whitelist", {}).get("own_ip", "")
    if own:
        prefixes.append(subnet_24(own))
    for bp in cfg.get("botnet", {}).get("bulletproof_prefixes", []):
        prefixes.append(bp)
    # test representative IP from subnet
    base = subnet.split("/")[0]
    parts = base.split(".")
    test_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return ip_in_prefixes(test_ip, prefixes)


def _log_block(cfg: dict, subnet: str, reason: str) -> None:
    log_path = cfg["general"].get("botnet_log_file", "/var/log/secmon-botnet.log")
    line = f"{utcnow_iso()} BLOCKED {subnet} reason={reason}\n"
    try:
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        logger.error("botnet log write failed: %s", exc)


def _persist_rules() -> None:
    rules_path = "/etc/iptables/rules.v4"
    if os.path.isdir(os.path.dirname(rules_path)):
        out = run_cmd_safe(["iptables-save"])
        if out:
            try:
                with open(rules_path, "w", encoding="utf-8") as fh:
                    fh.write(out)
            except OSError as exc:
                logger.error("iptables-save persist failed: %s", exc)
        run_cmd_safe(["netfilter-persistent", "save"])


def detect_and_block(state: dict, cfg: dict) -> list[Alert]:
    alerts: list[Alert] = []
    if not ensure_botnet_chain():
        return alerts
    lookback = cfg["botnet"]["lookback_hours"]
    out = run_cmd_safe(["journalctl", "--since", f"{lookback} hours ago"], timeout=60)
    ip_hits: dict[str, int] = defaultdict(int)
    for line in out.splitlines():
        if "Failed password" in line or "Invalid user" in line:
            for ip in extract_ips(line):
                ip_hits[ip] += 1
    subnet_data: dict[str, dict] = defaultdict(lambda: {"ips": set(), "hits": 0})
    for ip, hits in ip_hits.items():
        sn = subnet_24(ip)
        subnet_data[sn]["ips"].add(ip)
        subnet_data[sn]["hits"] += hits
    blocked = get_blocked_subnets()
    min_ips = cfg["botnet"]["min_ips_per_subnet"]
    min_hits = cfg["botnet"]["min_hits_per_subnet"]
    solo_min = cfg["botnet"]["solo_min_hits"]
    for subnet, data in subnet_data.items():
        unique_ips = len(data["ips"])
        total_hits = data["hits"]
        trigger = (unique_ips >= min_ips and total_hits >= min_hits) or total_hits >= solo_min
        if not trigger:
            continue
        if _is_whitelisted(subnet, cfg):
            continue
        if subnet in blocked:
            continue
        try:
            run_cmd(["iptables", "-A", "BOTNET", "-s", subnet, "-j", "DROP"], timeout=10)
            reason = f"ips={unique_ips} hits={total_hits}"
            _log_block(cfg, subnet, reason)
            _persist_rules()
            blocked.add(subnet)
            alerts.append(
                Alert(
                    severity="HIGH",
                    source="botnet",
                    message=f"Blocked botnet subnet {subnet} ({reason})",
                    dedup_key=f"botnet:{subnet}",
                    structured={"subnet": subnet, "unique_ips": unique_ips, "hits": total_hits},
                )
            )
        except Exception as exc:
            logger.error("failed to block %s: %s", subnet, exc)
    state.setdefault("monitor_state", {})["last_botnet_check"] = utcnow_iso()
    return alerts


def list_blocked() -> list[str]:
    return sorted(get_blocked_subnets())


def unblock_subnet(subnet: str) -> bool:
    out = run_cmd_safe(["iptables", "-L", "BOTNET", "-n", "--line-numbers"])
    for line in out.splitlines():
        if subnet.split("/")[0] in line and "DROP" in line:
            m = re.match(r"(\d+)", line.strip())
            if m:
                run_cmd_safe(["iptables", "-D", "BOTNET", m.group(1)])
                _persist_rules()
                return True
    return False


def flush_botnet_chain() -> None:
    run_cmd_safe(["iptables", "-F", "BOTNET"])
    _persist_rules()
