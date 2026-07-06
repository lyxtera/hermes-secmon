# Hermes Cron Integration for secmon

## Pattern: Silent-When-Clean Cron Jobs

secmon's monitoring philosophy is "silent unless actionable." When integrating with Hermes cron, this means **empty stdout = no message delivered**.

### The No-Agent Script Approach

Use `no_agent=True` with dedicated script files. The script's stdout IS the message. If stdout is empty, nothing is delivered.

```bash
# In Hermes cron job config:
no_agent: true
script: "cron-secmon-tick.sh"   # bare filename, NO arguments
```

### ⚠️ Critical Constraint: No Argument Passing

Hermes cron's `no_agent` mode treats the `script` field as a **bare filename** — no shell, no argument parsing.

**WRONG** — causes `Script not found: secmon-cron.sh tick`:
```json
{"script": "secmon-cron.sh tick"}
```

**CORRECT** — one script file per mode:
```json
{"script": "cron-secmon-tick.sh"}
```

### Recommended Scripts

Place in `~/.hermes/scripts/`:

**cron-secmon-tick.sh** — realtime threat check:
```bash
#!/usr/bin/env bash
set -euo pipefail
exec /opt/secmon/venv/bin/secmon --tick 2>&1
```
- Silent when no alerts (most ticks)
- Outputs alert lines when HIGH/CRITICAL fires
- Exit 0 = clean, exit 1 = alerts present

**cron-secmon-audit.sh** — deep audit (compact JSON):
```bash
#!/usr/bin/env bash
set -euo pipefail
/opt/secmon/venv/bin/secmon --audit 2>/dev/null | python3 -c '
import sys, json
data = json.load(sys.stdin)
ACTIONABLE = {"CRITICAL", "HIGH", "MEDIUM"}
findings = [(f["severity"].upper(), f.get("message",""))
            for f in data.get("findings", [])
            if f.get("severity","").upper() in ACTIONABLE]
if not findings:
    sys.exit(0)
ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
for sev, msg in sorted(findings, key=lambda x: ORDER.get(x[0], 9)):
    print(f"[{sev}] {msg}")
'
```
- Parses JSON output from `secmon --audit`
- Suppresses INFO/LOW findings
- Only outputs CRITICAL/HIGH/MEDIUM
- Silent when clean

**cron-secmon-record.sh** — baseline sample:
```bash
#!/usr/bin/env bash
set -euo pipefail
exec /opt/secmon/venv/bin/secmon --record 2>&1
```
- Silent on success
- Only outputs on error

### Job Configuration Reference

| Job ID | Schedule | Script | Delivery |
|--------|----------|--------|----------|
| secmon-tick | every 15m | cron-secmon-tick.sh | origin (silent when clean) |
| secmon-audit | every 6h | cron-secmon-audit.sh | origin (silent when clean) |
| secmon-daily | daily 9am | *(LLM prompt — always delivers human digest)* | origin |
| secmon-baseline-record | every 4h | cron-secmon-record.sh | origin (silent when clean) |

**Note**: The daily job uses an LLM prompt (not no_agent) because it's meant to always deliver a human-readable digest — it's not a "silent unless actionable" job.

### Anti-Pattern: LLM Wrapping for High-Frequency Jobs

**Don't do this** for jobs running more often than every ~30 minutes:
```
prompt: "Run secmon --tick and report the results"
```

The LLM will ALWAYS produce output (even "all clear!"), causing noise. High-frequency monitors must use `no_agent=True` with direct script execution.

### Pitfalls

| Pitfall | Fix |
|---------|-----|
| `script: "secmon-cron.sh tick"` → "Script not found" | Use bare filename: `script: "cron-secmon-tick.sh"` |
| `rm -rf /opt/secmon` deletes backup target | Use `rm /opt/secmon` (bare rm on symlink) |
| Forgetting to set `no_agent: true` | LLM runs even with script set → noise on empty output |
| Script not executable | `chmod +x ~/.hermes/scripts/cron-*.sh` |
