---
name: hermes-secmon
description: "Advanced multi-layer security audit and hardening system for Linux servers — file integrity, network forensics, process analysis, auth auditing, log correlation, threat intel IOC hunting, compliance checks, trend comparison, botnet detection & subnet blocking, statistical anomaly detection (rolling baseline), and automated hardening playbook (fail2ban, iptables, sysctrace). Use when the user wants to audit, harden, or set up periodic security monitoring on a server."
version: 3.3.1
author: Hermes Agent
platforms: [linux]
metadata:
  hermes:
    tags: [security, audit, intrusion-prevention, hardening, compliance, forensics]
    related_skills: []
---

# Hermes SecMon

## Overview

This skill covers building, deploying, and operating a production-grade multi-layer security monitoring system for Debian 12 cloud VPS environments. It combines deep forensic audits, statistical anomaly detection, realtime threat monitoring, botnet detection, and automated hardening.

**System is live and deployed** at `/opt/secmon/` with CLI at `/usr/local/bin/secmon`. Cron wrappers at `/opt/secmon/scripts/`. Config at `/etc/secmon/config.yaml`. See reference files for full architecture.

## Skill Owns

| Artifact | Path | Behavior |
|----------|------|----------|
| Source | `/opt/secmon/` (→ `~/.hermes/plugins/secmon/`) | Python CLI + cron scripts |
| CLI | `/usr/local/bin/secmon` | Run with `--audit` or `--tick` |
| Config | `/etc/secmon/config.yaml` | Runtime configuration |
| Data | `/var/lib/secmon/` | State, baselines, trends |
| Logs | `/var/log/secmon/` | Tick/audit logs |
| Scripts (canonical) | `/opt/secmon/scripts/` | tick.sh, audit.sh, daily.sh — all emit **Markdown** |
| Scripts (cron runtime) | `~/.hermes/scripts/secmon/*.py` with corresponding `.sh` copies in plugin dir | **Python scripts** — Hermes cron runs `.py` as Python scripts. Scripts send directly via Telegram API (`deliver: local`, bypassing Hermes adapter). Run `scripts/sync-cron.sh` after `git pull` to sync `.sh` copies |

## Layers

| Layer | Checks |
|-------|--------|
| 1. File Integrity | Critical file hashes, SUID/SGID audit, world-writable, hidden temp, ld.so.preload |
| 2. Network Forensics | Listening port baseline, outbound audit, firewall status, DNS hijack |
| 3. Process Forensics | Hidden process, ptrace injection, name spoof, suspicious kernel modules, **auto-excluded secmon process cluster** (see `references/self-exclusion-cluster.md`) |
| 4. Authentication | SSH brute-force, SSH config, users/sudo, policy, authorized_keys inventory |
| 5. Log Correlation | Auth anomalies, invalid user enumeration, kernel errors, systemd failures, tampering |
| 6. Threat Intel | Backdoor scan, persistence cron/timers, suspicious binaries, recent modifications |
| 7. Compliance | Kernel sysctls, security updates, unattended-upgrades, password aging |
| 8. Trend Comparison | Current vs previous, findings progression |

## Realtime Checks (every 15 minutes)

Each runs as an independent try/except-isolated check that returns nil (silent) or an alert:

| Check | Severity | Purpose |
|-------|----------|---------|
| fail2ban monitor | HIGH (batch) | Batches new bans when count exceeds `realtime.fail2ban_min_new_bans` (default 5). Individual bans are routine noise on an internet-facing server; the anomaly detector on `f2b_banned_count` catches statistical surges |
| brute-force burst | CRITICAL | SSH failure concentration within 5 min |
| port scan | MEDIUM | dmesg/kernel martian evidence |
| listening ports | CRITICAL | Unauthorized new or missing ports |
| invalid user | MEDIUM | Username enumeration bursts |
| kernel errors | MEDIUM | Error spike detection |
| unauthorized SSH | CRITICAL | Sessions from non-whitelist IPs |
| self-protection | CRITICAL | Missed tick gaps, code tampering, permission drift. Tick-gap threshold auto-detects from cron schedule (`~/.hermes/cron/jobs.json`) — no hardcoded value |
| suspicious outbound | HIGH | Potential C2/IRC beaconing |

## Anomaly Detection (statistical)

Rolling baseline with two-gate logic:
- **Gate 1 (sigma):** `|value - μ| > N × σ`
- **Gate 2 (min_delta):** `|value - μ| >= MIN_DELTA`
- Both gates must pass.
- Cool-down: 60 min per metric+direction.
- Stale baseline rule: same value 3+ consecutive ticks → warn about stale baseline, not alert.

### Metrics Tracked

| Metric | Sigma | Min_Delta | Direction |
|--------|-------|-----------|-----------|
| ssh_failed_24h | 2.5σ (above) / 2.0σ (below) | 5,000 | both |
| ssh_invalid_user_24h | 2.5σ | 2,000 | above |
| unique_attacker_ips | 2.5σ | 100 | above |
| unique_attacker_subnets | 2.5σ | 80 | above |
| f2b_banned_count | 4.0σ | 20 | above |
| botnet_chain_rules | 4.0σ | 5 | above |
| martian_packets_24h | 3.0σ | 10 | above |
| new_blocked_subnets_24h | 3.0σ | 5 | above |
| kernel_errors_24h | 3.0σ | 3 | above |
| listening_ports_count | 3.0σ | 2 | above |
| established_conns | 4.0σ | 8 | above |

**Seed protocol:** First 7 days must use real `journalctl` per-day data. Synthetic seeds cause catastrophic false-positive storms.

## Botnet Detection

Subnet-level blocking at iptables via a dedicated `BOTNET` chain:

| Threshold | Action |
|-----------|--------|
| ≥3 unique IPs in a /24 + ≥100 total hits | Block entire /24 |
| Single IP ≥500 hits | Block its /24 |

Whitelist: own public IP, RFC 1918 ranges, loopback. Always check `iptables -L BOTNET -n --line-numbers` before bulk operations so you don't lock yourself out.

## Scheduling

| Job | Schedule | Pipeline | Delivery | Format |
|-----|----------|----------|----------|--------|
| Security Tick | Every 15 min (`*/15`) | C (direct API + `telegramify-markdown`) | `deliver: local`, script sends via Telegram API `sendRichMessage` with Rich HTML | Structured blocks: `<h2>`, compact table, `<hr/>` via `telegramify-markdown.richify(md, mode=\"html\")`. Silent when no findings |
| Security Audit | Every 6 hours | C (direct API + `telegramify-markdown`) | `deliver: local`, script sends via Telegram API `sendRichMessage` with Rich HTML | Structured blocks: `<h1>`/`<h2>` headings, `<table>`, `<hr/>` via `telegramify-markdown.richify(md, mode="html")` |
| Daily Digest | 08:00 UTC | C (direct API + `telegramify-markdown`) | `deliver: local`, script sends via Telegram API `sendRichMessage` with Rich HTML | Structured blocks: `<h1>`/`<h2>` headings, `<table>`, `<hr/>` via `telegramify-markdown.richify(md, mode="html")` |

Python scripts at `~/.hermes/scripts/secmon/{audit,daily,tick}.py` each:
- Run the secmon CLI command
- Parse findings into severity groups
- Build structured Markdown with headings, tables, and dividers per severity
- Convert to Rich HTML via `telegramify-markdown.richify(md, mode="html")`
- Send directly via Telegram Bot API `sendRichMessage` (bypassing Hermes adapter)
- Exit silently (no stdout) — Hermes delivery is disabled (`deliver: local`)

Bash wrappers at `/opt/secmon/scripts/` are **canonical** (emit plain Markdown stdout). The `.py` scripts are the **cron runtime** versions that handle formatting and delivery. Run `scripts/sync-cron.sh` after `git pull` to sync the bash copies. Empty tick output = silent (no notification).

## Output Readability (USER PREFERENCE — HARD RULE)

**Cron output must be human-readable Markdown — never raw JSON.**

- The user explicitly rejected raw JSON dicts embedded in output (too hard to understand)
- All report output uses `format_audit_markdown()` in `output.py` — emoji icons, severity grouping, pretty-printed detail fields, no JSON blobs
- Every audit finding now includes a **human-readable one-liner** via the `CHECK_ID_EXPLANATIONS` dict in `output.py` — explains *why* each finding matters, not just *what* it is
- Trend-layer internal meta-checks (`layer_count`, `trend_*`, `risk_increase`) are filtered from resolved/persistent trend comparisons via `_INTERNAL_TREND_CHECKS` to avoid meaningless "RESOLVED: layer_count" noise
- Enriched RESOLVED messages include original severity and text from the previous finding
- If adding new output: prefer table headers, emoji, blockquotes for explanations, compact metadata lines, and severity-grouped sections over raw data structures
- Cron wrappers pass through Markdown directly — no Python JSON parsing in the shell wrapper

## Monitoring Philosophy (USER PREFERENCE — HARD RULE)

**Silent unless actionable.**

1. High-frequency monitors (< 15 min): ALWAYS direct script execution (no LLM cron). Never use free-model LLM cron on short intervals — HTTP 429 rate limits.
2. If the script produces stdout, it's delivered. If nothing is wrong → ZERO output, exit 0.
3. Dedup via state keys. Per-ban-IP (24h), per-burst-subnet (1h), per-port (24h), per-anomaly-metric (60 min). Once alerted, never repeat within window.
4. First run reports current state. Subsequent runs only alert on NEW events.
5. Never keep reporting the same anomaly 3+ ticks → the baseline is stale, not the attack.

## Hardening Playbook (apply when audit warrants)

### 1. fail2ban
```bash
apt install -y fail2ban
# /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport
backend = polling  # NOT systemd — python3-systemd missing on Debian 12

[sshd]
enabled = true
...
```

**Pitfall:** `backend = systemd` fails unless `python3-systemd` is installed. Use `polling`.

### 2. Kernel sysctls (/etc/sysctl.d/99-hardening.conf)
Always `sysctl <name>` before setting — Debian cloud images ship most of these pre-configured.

### 3. SSH hardening
Partial (preserves root+password): MaxAuthTries 3, LoginGraceTime 30, PermitEmptyPasswords no, X11Forwarding no, ClientAliveInterval 300.
Full: above + PermitRootLogin no, PasswordAuthentication no.

### 4. NOPASSWD sudo remediation
Scan /etc/sudoers.d/* for NOPASSWD:ALL → replace with ALL (password-required).

### 5. iptables
SSH rate-limit (4/min), SYN-flood limit, invalid-drop, NULL/XMAS/SYN-RST/SYN-FIN scan block. **Always persist** with `iptables-save > /etc/iptables/rules.v4`.

## Anti-Patterns

| Anti-Pattern | Correct Approach |
|--------------|------------------|
| `bash -c "$var"` (shell injection) | `subprocess.run([cmd, arg1, arg2])` |
| Reporting same anomaly 3+ ticks | Treat as stale baseline; log and self-correct |
| LLM cron every 5 min | `no_agent=True` + direct script execution |
| Re-applying existing sysctl/iptables rules | Check current state with `sysctl`/`iptables -L` first |
| Flagging /tmp/.X11-unix as hidden threat | These are X11 Unix sockets — normal |
| dmesg for persistent history | Use `journalctl -k` — dmesg wraps |
| Flagging pid 449 `rwxp` mapping as process hollowing | pid 449 = `unattended-upgrades-shutdown`, a Python process — its JIT/mmap is benign. Exclude via `whitelist.proc_hollow_exclude_pids` or `proc_hollow_exclude_comms: ["node"]` |
| Scanning `config.yaml` / `.env` for secrets | These are the real config files — add to `whitelist.secret_exclude_paths` |
| Setting INPUT chain to DROP on a remote server | Will lock you out on next SSH disconnect — set `hardening.skip_fw_policy_check: True` |
| Cleaning `STITCH_API_KEY="placeholder"` from docs | Placeholder values still match regex — use `whitelist.secret_exclude_paths` or replace with `KEY=""` |
| Generic CTAs like `/secmon audit` in cron output | Output goes to Telegram; use `▶ \`secmon --audit\`` with Markdown backtick |
| `→ reply /secmon audit` appended to alert lines | Replace with per-alert-type fix: `→ \`chmod 600 <path>\`` via `_stdout_remediation_hint()` |
| Vague numbered steps in "What to do" sections | Show exact copy-paste commands: `- \`chmod 600 /path\` — Fix permissions` |
| `ln -sf` scripts to `~/.hermes/scripts/` | Hermes cron resolves real paths and blocks paths outside `~/.hermes/scripts/` — use `cp` instead. Run `sync-cron.sh` after `git pull` |
| Matching `self_protection:` prefix in tick.sh patterns | Wrapping source in backticks `\`self_protection\`` breaks prefix matching — match on message content like `"permissions too open"` instead |
| Hardcoding PIDs in `proc_hollow_exclude_pids` | PIDs change between runs — use `proc_hollow_exclude_comms` with process names instead
| Alerting on every individual fail2ban ban | Under constant SSH brute-force, individual bans are routine noise. Set `realtime.fail2ban_min_new_bans` (default 5) to batch alerts on bursts; anomaly detection on `f2b_banned_count` catches statistical surges |
| Alerting on long-lived outbound connections from hermes→Telegram | Hermes maintains persistent Telegram MTProto connections — expected. Add Telegram CIDRs to `whitelist.outbound_destinations` in config, keyed by `process: hermes` |
| Parsing local address instead of remote peer in `ss -tnp` output | The regex `r"(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d+)\\s"` matches the FIRST IP:port in the line, which is the **local** address, not the peer (remote). This causes false alerts like "outbound connection to *server-own-ip*:22". Fix: use `re.findall(...)` and take the **second** pair (index 1) as the destination. Always update test mock output to include BOTH local and peer columns (e.g. `"0.0.0.0:50000  <peer_ip>:<port>  users:((..."`) |
| Dumping raw `json.dumps(result)` to stdout for audit output | Users can't read raw JSON — use `format_audit_markdown()` which renders emoji icons, severity-grouped sections, and detail fields as bullet points instead |
| Only excluding child processes of secmon in hollow checks (missing parent chain) | Secmon's leaf process (the CLI tool) usually doesn't have RWX maps — the Hermes gateway parent does. Walk `/proc/*/stat` ppid **upward** from every seed PID to catch the full ancestry. See `references/self-exclusion-cluster.md` |
| Wrapping audit output in ```json code fence in shell wrapper | The markdown formatter already produces self-contained Markdown — cron wrapper should pass through directly, not re-wrap |
| Pipeing markdown output through Python `json.load()` to filter findings | `format_audit_markdown()` already groups by severity — pass full output through. If filtering needed, grep the severity headers (e.g. `grep -q "^### 🔴"`) |
| Hardcoded 20-min tick-gap threshold breaking on non-standard cron schedules | `self_protection` check uses `(now - last_tick) > 20 * 60`. If cron runs every 6h, fires every cycle. Fix: read `~/.hermes/cron/jobs.json` at runtime to auto-detect interval, set threshold to `max(interval_min * 120, 600)`. See `references/tick-gap-detection.md` |
| `layer_count`, `trend_new`, `trend_resolved`, `trend_persistent`, `risk_increase` appearing as "RESOLVED" findings in audit output | These are Trends layer's own internal meta-checks, not real security findings. They pollute the before/after diff because they're stored in `last_audit_findings` state and re-compared every run. Fix: define `_INTERNAL_TREND_CHECKS = {"layer_count", "trend_new", "trend_resolved", "trend_persistent", "risk_increase"}` and filter them out of both `prev_ids` and `cur_ids` before computing `new_ids`, `resolved`, `persistent`. Also enrich the RESOLVED message with original severity+text from the previous finding (not just the bare check_id). |
| `persist_modified` firing every audit on `systemd_timers` | The baseline stores a SHA256 of `systemctl list-timers --all`, but the output contains dynamic time columns (`PASSED`, `LAST`, `NEXT`) that change every time a timer fires. The hash will ALWAYS differ. **Fix applied:** Normalize timer output by stripping dynamic columns — only hash stable UNIT + ACTIVATES pairs using `line.rsplit(None, 2)`. See `threat_intel.py` `_collect_persistence_entries()`. |
| `modified_bin` flagging `/sbin/bpftool` (or any `/sbin/` file) as "not in dpkg" | On Debian 12 (usrmerge), `/sbin` is a symlink to `/usr/sbin`. `dpkg -S /sbin/bpftool` fails because dpkg tracks the canonical path. Fix: resolve symlinks with `os.path.realpath(fp)` before passing to `dpkg -S`. |
| Kernel security upgrade (`linux-image-amd64`) applied but not taking effect | `apt-get install linux-image-amd64` installs the new kernel image but the running kernel is unchanged until reboot. After a kernel security update, you must reboot or verify `uname -r` matches the new package version. If the server can't reboot immediately, document as deferred action in the audit report, not as "resolved". |

## Reference Files

- `references/anomaly-detection.md` — Two-gate algorithm, per-metric thresholds, sample variance, cool-down, stale baseline rule, seeding protocol
- `references/monitoring-philosophy.md` — Silent-monitoring rules, dedup windows, what warrants alerts (USER PREFERENCE — HARD RULES)
- `references/botnet-detection.md` — Subnet clustering algorithm, iptables BOTNET chain setup, whitelist, known bulletproof ASNs, boot persistence
- `references/spec-first-rebuild.md` — Workflow for extracting a spec and destroying the old implementation; recursive-delete pitfalls
- `references/audit-tuning.md` — Config-driven exclusion keys, false positive triage table, add-a-key checklist for extending secmon with new config options
- `references/cron-notification-formatting.md` — Markdown patterns, CTA design rules, per-alert-type hint table, audit/daily/tick output templates, script deployment
- `references/audit-remediation-workflow.md` — Step-by-step investigation and remediation procedure for audit findings, including false positive triage table, parallel fix batching by layer, and verification
- `references/self-exclusion-cluster.md` — Auto-discovery of secmon's own process cluster (parent chain up + child chain down) to prevent self-flagging in proc hollow checks
- `references/outbound-check.md` — Outbound connection check (TC-8) internals: regex parsing (local-vs-peer bug), whitelist system, testing pattern
- `references/tick-gap-detection.md` — Self-protection tick gap auto-detection: cron interval parsing, supported patterns, threshold formula, fallback behavior
- `references/known-false-positives.md` — Catalog of chronic false positives (systemd_timers, state-snapshot secrets, kernel-upgrade-reboot, SSH enumeration) with root causes and fix steps — consult when triaging audit findings to avoid re-investigating known non-issues


