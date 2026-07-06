# Spec Compliance Gap Analysis Workflow

## When to Use

When the user asks "does the running system match the spec?" or "are all spec features working?"

## Workflow

### 1. Read the Spec Completely
Read `SECURITY-AUDIT-SPEC.MD` (1600+ lines) and extract every feature, check, threshold, and configurable parameter into a checklist.

### 2. Code Audit
For each spec item, verify the source file exists and implements it:

```bash
# List all source modules
find /opt/secmon/src/secmon -name "*.py" | sort

# List all audit layers
ls /opt/secmon/src/secmon/audit/

# List all realtime checks
ls /opt/secmon/src/secmon/checks/
```

### 3. Runtime Verification
Check what's actually running:

```bash
# Cron jobs
cronjob list  # (Hermes cron)

# State file
cat /var/lib/secmon/state.json | python3 -m json.tool | head -50

# System hardening
sysctl kernel.kptr_restrict kernel.yama.ptrace_scope ...
sshd -T | grep -E "passwordauthentication|permitrootlogin"
iptables -L -n | head -20
fail2ban-client status sshd
```

### 4. Common "Not Really There" Patterns

| Symptom | Real Cause | Fix |
|---------|-----------|-----|
| `ssh_failed_24h: 0` despite bans | Metric only counts "Failed password"; hardened SSH never generates that | Count all auth-failure signals |
| `baselines: {}` despite record cron | Only 1 daily sample; need ≥4 | Wait 2-3 days or check dedup_slot_hours alignment |
| Audit risk score swings wildly | Inconsistent metrics between runs (caused by metric bug above) | Fix metric collection first |
| `new_blocked_subnets_24h: 0` | Attack volume below thresholds OR whitelist overlap | Verify with manual botnet check |
| Daily digest fires twice | Tick generates at 08:00, cron at 09:00 | Align cron to spec (08:00) |

### 5. Output Format

Present as a table:

| Spec Component | Status | Notes |
|---|---|---|
| Feature X | ✅/⚠️/❌ | Detail |

Then list actionable follow-ups by priority (🔴 Critical → 🟡 Important → 🟢 OK).

### 6. Post-Fix Verification

After fixing any gap:
1. Reinstall editable package: `cd /opt/secmon && source venv/bin/activate && pip install -e .`
2. Run tests: `source venv/bin/activate && python -m pytest tests/ -x -q`
3. Verify metric collection: `python3 -c "from secmon.metrics import collect_metrics; ..."`
4. Run a tick: `/opt/secmon/venv/bin/secmon --tick`
5. Commit the fix with descriptive message
