# Silent Cron Job Pattern for secmon

## Problem

The user wants secmon cron jobs to be completely silent when nothing is actionable. Using an LLM prompt (even with "reply silently if nothing wrong") causes noise — the LLM synthesizes status messages like "baselines not calibrated, learning phase, no other issues" even when `secmon --tick` produces zero stdout.

## Solution

Convert cron jobs to `no_agent=True` + script. Hermes delivers the script's stdout directly. Empty stdout = empty message = no notification sent.

## Pattern

### 1. Script at `~/.hermes/scripts/secmon-cron.sh`

```bash
#!/usr/bin/env bash
# secmon-cron.sh — Bridge between secmon CLI and Hermes cron (no_agent mode).
# Stdout = telegram message. Empty stdout = silence.
set -euo pipefail

SECMON="/opt/secmon/venv/bin/secmon"
MODE="${1:-tick}"

case "$MODE" in
  tick)
    "$SECMON" --tick 2>&1

  record)
    "$SECMON" --record 2>&1

  audit)
    # Parse JSON, output only CRITICAL/HIGH/MEDIUM findings.
    "$SECMON" --audit 2>/dev/null | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

findings = []
for f in data.get("findings", []):
    sev = f.get("severity", "INFO").upper()
    msg = f.get("message", "")
    if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
        findings.append((sev, msg))

if not findings:
    sys.exit(0)

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
findings.sort(key=lambda x: ORDER.get(x[0], 9))

for sev, msg in findings:
    print(f"[{sev}] {msg}")

sev_counts = {}
for sev, _ in findings:
    sev_counts[sev] = sev_counts.get(sev, 0) + 1
summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
print(f"\nAudit: {summary} ({len(findings)} total)")
'

  daily)
    # Always delivers — this is a human-readable digest.
    "$SECMON" --daily 2>&1
    ;;

  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac
```

### 2. Update the cron jobs

```python
# Convert tick job from LLM prompt to script
cronjob(action='update', job_id=<tick-id>, no_agent=True, script='secmon-cron.sh tick')
cronjob(action='update', job_id=<record-id>, no_agent=True, script='secmon-cron.sh record')
cronjob(action='update', job_id=<audit-id>, no_agent=True, script='secmon-cron.sh audit')
# Daily stays as-is (LLM or script, depending on whether formatting is needed)
```

### 3. Verify

```bash
# Test the script manually
bash -n ~/.hermes/scripts/secmon-cron.sh
~/.hermes/scripts/secmon-cron.sh tick    # should be silent on clean
~/.hermes/scripts/secmon-cron.sh daily   # should show full digest
```

## Job Treatment Reference

| Job | Schedule | Delivery | Recommended |
|---|---|---|---|
| secmon-tick | 15m | Alarm only | `no_agent=True` + raw stdout |
| secmon-record | 4h | Silent on success | `no_agent=True` + raw stdout |
| secmon-audit | 6h | Critical findings | `no_agent=True` + JSON filter (suppress INFO/LOW) |
| secmon-daily | 9am | Summary | LLM (format digest) or `no_agent=True` (raw) |

## Why the LLM Fails at Silence

The LLM prompt pattern:
- Agent runs `/opt/secmon/venv/bin/secmon --tick` → empty stdout
- Agent says: "Silent — nothing to report" or "Baselines not calibrated, system healthy"
- This message gets delivered → **noise**

The `no_agent=True` pattern:
- Script runs `/opt/secmon/venv/bin/secmon --tick` → empty stdout
- Hermes delivers empty message → **nothing arrives**
- Result: truly silent

User preference: "we need to suppress noise and don't need to see 'informational' messages. If there's nothing to act on — I would rather not see."

## Audit JSON Structure (for the filter)

secmon outputs:
```json
{
  "total_score": 25,
  "finding_count": 4,
  "critical_count": 1,
  "high_count": 1,
  "layers": { "auth": [{ "severity": "CRITICAL", "message": "..." }], ... },
  "findings": [
    { "severity": "CRITICAL", "message": "...", "check_id": "...", "score": 10, "detail": {} }
  ]
}
```

Severity values from `audit/base.py`: `CRITICAL` (10), `HIGH` (7), `MEDIUM` (4), `LOW` (1), `INFO` (0).

The filter suppresses `INFO` and `LOW` — those are expected/harmless findings (e.g., "kernel sysctl not hardened but not a security issue today"). CRITICAL/HIGH/MEDIUM are actionable.
