# Spec-to-Implementation Gap Analysis

When the user asks "does the system actually implement what the spec says?", use this workflow to verify claims against running code and system state.

## Trigger

- User asks whether spec features are working
- User wants a compliance check between spec and reality
- User asks "what's missing?" or "what's implemented?"

## Workflow

### 1. Read the Spec

Locate the authoritative spec file (typically `/opt/secmon/SECURITY-AUDIT-SPEC.MD`). Extract every verifiable claim:

- Layers and their specific checks
- Realtime threat checks (TC-1 through TC-8)
- Metrics and their thresholds
- Scheduling frequencies
- State schema fields
- Alert dedup windows
- Botnet thresholds
- New checks (NC-1 through NC-11)
- Hardening playbook steps

### 2. Verify Code Implementation

For each spec claim, check the corresponding source file:

| Spec Section | Code Location |
|---|---|
| L1: File Integrity | `src/secmon/audit/file_integrity.py` |
| L2: Network Forensics | `src/secmon/audit/network.py` |
| L3: Process Forensics | `src/secmon/audit/process.py` |
| L4: Authentication | `src/secmon/audit/auth.py` |
| L5: Log Correlation | `src/secmon/audit/logs.py` |
| L6: Threat Intel | `src/secmon/audit/threat_intel.py` |
| L7: Compliance | `src/secmon/audit/compliance.py` |
| L8: Trends | `src/secmon/audit/trends.py` |
| TC-1 through TC-8 | `src/secmon/checks/__init__.py` + individual files |
| Anomaly Detection | `src/secmon/anomaly.py` |
| Metrics | `src/secmon/metrics.py` |
| Botnet | `src/secmon/botnet.py` |
| State/Config | `src/secmon/state.py`, `src/secmon/config.py` |
| Alert Pipeline | `src/secmon/alerts.py` |
| Modes | `src/secmon/modes/` |

### 3. Verify Runtime State

```bash
# Check cron jobs are running
hermes cron list  # or equivalent

# Check state file for baselines
python3 -c "import json; d=json.load(open('/var/lib/secmon/state.json')); print('daily_stats:', len(d.get('daily_stats',[]))); print('baselines:', len(d.get('baselines',{})))"

# Check system hardening matches spec
sysctl kernel.kptr_restrict  # should be 1
sshd -T | grep maxauthtries  # should be 3
iptables -L BOTNET -n | wc -l  # active botnet rules
fail2ban-client status sshd  # active bans

# Check logs for actual alert activity
tail -20 /var/log/security-monitor.log
```

### 4. Classify Findings

For each spec item, mark:
- **✅ Working**: Code implemented AND runtime verified
- **⚠️ Partial**: Code implemented but not yet active (e.g., insufficient data, needs time)
- **❌ Missing**: No code implementation
- **🔄 Deviation**: Implemented but differs from spec (note what and why)

### 5. Report Format

Present as a structured table with sections matching the spec's major headings. For each gap, explain:
- What the spec says
- What's actually happening
- Severity of the gap (functional vs cosmetic)
- Suggested fix if applicable

## Common Gaps to Watch For

| Gap Pattern | What to Check |
|---|---|
| Baselines not calibrated | `daily_stats` count < `baseline_min_samples` (usually 4) — system needs more time |
| Cron frequency mismatch | Spec says 6h, cron says 60m — intentional or oversight? |
| Missing hardening playbook | Spec §10 describes auto-remediation — usually only detection is implemented |
| Webhook not delivering | Check if webhook endpoint is reachable; cron stdout delivery works regardless |
| Metric parsing issue | e.g., `ssh_failed_24h=0` while fail2ban shows 727 total failures — journalctl vs auth.log source mismatch |
| Empty whitelists | Bulletproof hosting prefixes, Docker container whitelists — code exists but lists are empty |

## Pitfall: Don't Confuse "Not Active" With "Not Implemented"

A system may have all the code but need time to build baselines. `daily_stats: 1` with `baseline_min_samples: 4` means anomaly detection will be silent for ~2 more days. This is **correct behavior** per spec §6.1, not a bug.

Similarly, some checks return nil when conditions aren't met (e.g., no Docker containers → NC-1 returns nil). That's **correct** — the check exists, just no finding.

## Output Template

```
## ✅ WHAT'S IMPLEMENTED & WORKING
[table of working items]

## ⚠️ GAPS & ISSUES
[table of gaps with severity and suggested fix]

## 📊 SUMMARY
[counts: spec items / implemented / working now / gaps]
```
