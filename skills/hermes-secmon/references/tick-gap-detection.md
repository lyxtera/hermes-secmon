# Tick Gap Detection (Self-Protection)

## Source

`src/secmon/checks/self_protection.py` — the `check()` function reads `last_tick` from state's `monitor_state` and compares it to the current time.

## The Problem

The tick gap check used a hardcoded threshold of 20 minutes (`(now - last_tick) > 20 * 60`). This worked for the default `*/15 * * * *` (every 15 min) cron schedule, but broke on any other schedule:

- `secmon-audit` (every 6h) — every run would false-alert a gap
- Any custom schedule shorter than 20 min — silent misses

## Auto-Detection Fix

`_cron_interval_minutes(job_name, default=15)` reads `~/.hermes/cron/jobs.json` and parses the job's `schedule.expr` to determine the expected interval in minutes.

### Supported Cron Patterns

| Pattern | Interval |
|---------|----------|
| `*/N * * * *` | N minutes |
| `M * * * *` | 60 minutes |
| `0 */N * * *` | N × 60 minutes |
| `0 0 ...` | 1440 minutes (daily) |

### Threshold Formula

```
tick_threshold = max(cron_interval_minutes * 2 * 60, 600)
```

That's **2× the expected interval (in seconds)**, minimum 10 minutes. This tolerates normal scheduling jitter but catches genuinely missed ticks.

### Fallback

If the cron job file can't be read, the job name isn't found, or the expression doesn't match a known pattern, it returns the default (15 min). This means the check behaves like the old hardcoded version for unrecognised schedules.

## Testing

No dedicated test file yet — covered indirectly via integration. To verify manually:

```bash
python3 << 'EOF'
from secmon.checks.self_protection import _cron_interval_minutes
# Should match your actual cron setup
print(_cron_interval_minutes("secmon-tick"))  # expects 15
print(_cron_interval_minutes("secmon-audit"))  # expects 360
print(_cron_interval_minutes("nonexistent"))   # expects 15 (default)
EOF
```
