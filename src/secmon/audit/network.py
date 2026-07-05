"""Layer 2: Network forensics + NC-2, NC-3."""

from __future__ import annotations

import os
import re

from secmon.audit.base import AuditFinding
from secmon.shell import run_cmd_safe


def run(state: dict, cfg: dict) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    ab = state.setdefault("audit_baseline", {})
    known_ports: dict = ab.setdefault("known_ports", {})

    # Listening ports
    listen = run_cmd_safe(["ss", "-tlnp"])
    current_ports: dict[int, str] = {}
    for line in listen.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m:
            current_ports[int(m.group(1))] = line.strip()
    for port, line in current_ports.items():
        if str(port) in known_ports and known_ports[str(port)] != line:
            findings.append(
                AuditFinding("MEDIUM", 2, "port_changed", f"Listening port {port} changed")
            )
        elif str(port) not in known_ports:
            findings.append(
                AuditFinding("HIGH", 2, "new_listen_port", f"New listening port: {port}")
            )
    # Check if the known process was a transient browser/agent (ephemeral ports)
    import re as _re
    transients = cfg.get("whitelist", {}).get("port_removed_processes", [])
    port_removed_ignore = set(cfg.get("whitelist", {}).get("port_removed", []))
    for port in set(map(int, known_ports)) - set(current_ports):
        if port in port_removed_ignore:
            continue
        # Skip if the original process was a known transient
        if transients:
            line = known_ports.get(str(port), "")
            m = _re.search(r'"([^"]+)"', line)
            if m and m.group(1) in transients:
                continue
        findings.append(
            AuditFinding("HIGH", 2, "port_removed", f"Listening port removed: {port}")
        )
    known_ports.update({str(k): v for k, v in current_ports.items()})

    # Firewall status
    skip_fw_policy = cfg.get("hardening", {}).get("skip_fw_policy_check", False)
    ipt = run_cmd_safe(["iptables", "-L", "INPUT", "-n"])
    if "Chain INPUT" in ipt and "policy DROP" not in ipt:
        if not skip_fw_policy:
            findings.append(
                AuditFinding("MEDIUM", 2, "fw_policy", "INPUT chain default policy is not DROP")
            )
    for chain in ("SCANS", "BOTNET", "PORT_SCAN", "ANTI_SCAN", "BAD_FLAGS"):
        if chain not in run_cmd_safe(["iptables", "-L", "-n"]):
            findings.append(
                AuditFinding("LOW", 2, "fw_chain", f"Missing protection chain: {chain}")
            )

    # NC-2: Interface anomaly
    link = run_cmd_safe(["ip", "link", "show"])
    for line in link.splitlines():
        if "PROMISC" in line and "lo:" not in line:
            findings.append(
                AuditFinding("CRITICAL", 2, "NC-2-promisc", f"Promiscuous interface: {line.strip()}")
            )
        if re.search(r"\b(tun|tap)\d", line):
            findings.append(
                AuditFinding("HIGH", 2, "NC-2-tun", f"Unexpected tun/tap: {line.strip()}")
            )

    # ARP anomalies
    arp = run_cmd_safe(["ip", "neigh", "show"])
    macs: dict[str, list[str]] = {}
    for line in arp.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            ip, mac = parts[0], parts[4]
            macs.setdefault(mac, []).append(ip)
    for mac, ips in macs.items():
        if len(ips) > 1:
            findings.append(
                AuditFinding("MEDIUM", 2, "NC-2-arp", f"Duplicate MAC {mac}: {ips}")
            )

    # NC-3: DNS integrity
    expected = cfg.get("dns", {}).get("expected_nameservers", [])
    resolv_path = "/etc/resolv.conf"
    if os.path.isfile(resolv_path):
        content = open(resolv_path, encoding="utf-8", errors="replace").read()
        ns = re.findall(r"nameserver\s+(\S+)", content)
        if expected and ns and not any(n in expected for n in ns):
            findings.append(
                AuditFinding("CRITICAL", 2, "NC-3-dns", f"Unexpected nameservers: {ns}")
            )
        if "options ndots:0" in content:
            findings.append(
                AuditFinding("MEDIUM", 2, "NC-3-ndots", "Weak DNS options: ndots:0")
            )
    nsswitch = "/etc/nsswitch.conf"
    if os.path.isfile(nsswitch):
        for line in open(nsswitch, encoding="utf-8", errors="replace"):
            if line.startswith("hosts:") and "dns" not in line:
                findings.append(
                    AuditFinding("MEDIUM", 2, "NC-3-nsswitch", f"Unusual nsswitch hosts: {line.strip()}")
                )
    hosts = "/etc/hosts"
    if os.path.isfile(hosts):
        for line in open(hosts, encoding="utf-8", errors="replace"):
            if any(d in line for d in ("security.debian.org", "github.com", "update")):
                findings.append(
                    AuditFinding("HIGH", 2, "NC-3-hosts", f"Suspicious hosts entry: {line.strip()}")
                )

    return findings
