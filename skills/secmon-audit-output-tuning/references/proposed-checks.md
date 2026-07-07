# Proposed New Audit Checks & Coverage Gaps

From a 2026-07-07 gap analysis across secmon's 7 audit layers.

## Coverage Map

| Layer | Files | Currently monitored | Gaps |
|-------|-------|--------------------|------|
| **1 - File Integrity** | `file_integrity.py` | SUID, world-writable, hidden tmp, ld.so.preload, critical file hashes | File capabilities, Unix socket drift |
| **2 - Network** | `network.py` | Ports, promiscuous, tun/tap, ARP, DNS, firewall chains | Routing table drift, netns anomalies, IPv6 checks |
| **3 - Process** | `process.py` | BPF (now watcher-based), hollowing, lineage, kthreads, kernel modules | Namespace drift, OOM score anomalies, Seccomp tracking |
| **4 - Auth** | `auth.py` | User accounts, groups, SSH config, sudoers, authorized_keys | PAM drift, login geo/timing anomalies |
| **5 - Logs** | `logs.py` | Auth log parsing | — |
| **6 - Threat Intel** | `threat_intel.py` | Secrets, webshells, persistence, systemd services/timers, binaries | APT source drift tracking |
| **7 - Compliance** | `compliance.py` | Sysctl, security updates, certs, NTP, debsums, apt sources | AppArmor/SELinux, kernel cmdline drift |

## Proposed New Checks

### 🔴 CRITICAL — Active Compromise

| Check ID | Layer | What it does |
|----------|-------|-------------|
| NC-11 | Process | Container escape indicators — `/var/run/docker.sock` existence, `/proc/1/cgroup` showing container contexts |
| NC-12 | Compliance | AppArmor/SELinux disabled — `aa-status`, `getenforce` not enforcing |
| kernel_cmdline_drift | Compliance | Hash `/proc/cmdline` vs baseline — modules/tuning injected via boot |

### 🟠 HIGH — Significant Exposure

| Check ID | Layer | What it does |
|----------|-------|-------------|
| routing_table_drift | Network | Track `ip route show` baseline, flag new default gateways or tunnel routes |
| routing_policy_drift | Network | Track `ip rule show` baseline, flag policy routing changes |
| pam_drift | Auth | Hash `/etc/pam.d/` files vs baseline — backdoor auth modules |
| file_cap_drift | File Integrity | Track `getcap -r /usr/bin /usr/sbin` baseline — privilege escalation via capabilities |
| unix_socket_drift | File Integrity | Track `ss -xln` baseline — hidden backdoor IPC |
| netns_anomaly | Network | Check `ip netns list` for unexpected namespaces — container escape residue |
| oom_score_anomaly | Process | Detect processes with `oom_score_adj` < -500 (hard to kill) — rootkit behavior |

### 🟡 MEDIUM — Configuration Weakness

| Check ID | Layer | What it does |
|----------|-------|-------------|
| ipv6_ra | Network | Check `accept_ra=1` — IPv6 MITM vector |
| ipv6_privacy | Network | Check `use_tempaddr=0` — reduced outbound privacy |
| apt_source_drift | Compliance | Hash apt sources vs baseline — repo hijacking |
| last_login_anomaly | Auth | Track `last -10` baseline — new login geo/timing patterns |
| journal_size | Compliance | Check `journalctl --disk-usage` — log exhaustion attack |
| kernel_cmdline_params | Compliance | Check `mitigations=off`, `nosmt`, `module.sig_enforce=0` |

## Remediation Steps Per Severity

### CRITICAL
- **AppArmor/SELinux** — Install and enforce MAC
- **World-writable files** — `chmod o-w <file>`, investigate origin
- **ld.so.preload** — Clear file, find the malicious library, trace source

### HIGH
- **New listening ports** — Identify with `ss -tlnp`, decide if expected. Ephemeral browser ports → add to `port_removed_processes` whitelist
- **Port removed** — Expected service stopped? Run `journalctl -u <service>` to verify
- **BPF programs** — If systemd (`sd_fw_*`, `sd_devices`), promote to baseline. If unknown, investigate via `bpftool prog show id <id>`
- **SSH config drift** — Lock down: `PermitRootLogin without-password`, `PasswordAuthentication no`, `MaxAuthTries 3`

### MEDIUM
- **Security updates pending** — `apt upgrade` or enable `unattended-upgrades`
- **Missing protection chains** — Install firewall with `SCANS`, `BOTNET`, `PORT_SCAN` chains
- **sysctl deviations** — Apply hardening via `/etc/sysctl.d/99-hardening.conf`
- **NOPASSWD sudo** — Audit sudoers, remove NOPASSWD where possible