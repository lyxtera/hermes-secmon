# Cron Job Patterns for secmon

## The Silent Monitor Pattern

For high-frequency monitoring (every 5-15 minutes), use the **silent monitor pattern**:
- Script exits 0 always
- Stdout = message to deliver (empty = silent)
- Stderr goes to logs only
- No LLM involvement

This prevents the LLM from generating noise like "baselines not calibrated, nothing to report" when there is genuinely nothing to act on.

## Why Not LLM Prompts?

LLM-based cron jobs (even with instructions like "reply SILENTLY if no findings") still suffer from:
1. The LLM may ignore the silence instruction and produce a summary anyway
2. Token waste on every run
3. Rate limit risks on free tiers
4. Inconsistent formatting

## Pattern Implementation

Create a script in `~/.hermes/scripts/`:
```bash
#!/usr/bin/env bash
# Example: cron-secmon-tick.sh
set -euo pipefail
OUTPUT="$(/opt/secmon/venv/bin/secmon --tick 2>&1)" || true  # capture exit code but continue
printf '%s' "$OUTPUT"
exit 0
```

Then configure the Hermes cron job:
```bash
cronjob(action='update', job_id=<ID>, no_agent=True, script='cron-secmon-tick.sh')
```

The script's stdout becomes the message; stderr goes to Hermes logs. Empty output = no notification.