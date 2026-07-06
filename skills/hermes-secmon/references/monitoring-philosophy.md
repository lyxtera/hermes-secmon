# Monitoring Philosophy & User Preferences

## Core Principle: Silent Unless Actionable

**User explicitly stated:** "Don't send me a real-time reminder unless there's something new or needing attention."

**Corollary — The Repeated Signal Rule:** If the same anomaly fires 3+ times
for the same metric at approximately the same value (±10%), it is no longer
an anomaly — the baseline is stale. Fix the baseline, don't keep reporting.
Never send the same noise to the user more than 2 ticks in a row.

This is a first-class preference that governs ALL monitoring cron behavior.

## Rules

1. **High-frequency monitors (< 15 min):** ALWAYS use `no_agent=True` with a script. Never use LLM-driven cron — it burns tokens and hits rate limits.
2. **Output = alert:** If the script produces stdout, it's delivered. If nothing is wrong, the script must produce ZERO output (exit 0, no stdout).
3. **Dedup via state files:** Track last-seen state (banned IPs, known ports, etc.) so repeated alerts for the same event don't spam the user.
4. **First run behavior:** Fresh state will report current status (e.g., "9 IPs already banned"). This is acceptable — it's the baseline. Subsequent runs only alert on NEW events.
5. **Filter self-traffic:** Exclude the server's own public IP from martian source alerts and from unauthorized SSH checks.

## What warrants an alert

| Event | Severity | Dedup |
|-------|----------|-------|
| New IP banned by fail2ban | HIGH | Per IP — only alert once per new IP |
| Unauthorized SSH session (non-whitelist) | CRITICAL | Per session |
| Brute-force burst (>10 fails in 5 min) | CRITICAL | Per burst window |
| Port scan evidence in dmesg | HIGH | Per unique source IP |
| New listening port | CRITICAL | Per port |
| Suspicious outbound (IRC/C2 ports) | HIGH | Per connection |
| Username enumeration burst | MEDIUM | Per burst window |

## What does NOT warrant an alert

- Same IPs still banned (no change)
- Normal HTTPS connections
- Kernel firmware warnings (regulatory.db)
- Historical brute-force count (already handled by fail2ban)
- Own IP appearing in martian source logs
- **The same anomaly repeated 3+ ticks in a row with the same value (±10%)** — the baseline is stale, not the metric anomalous

## Cron Job Configuration Pattern

```python
# CORRECT: silent monitoring
cronjob(
    action='create',
    no_agent=True,
    script='monitor.sh',  # relative to ~/.hermes/scripts/
    schedule='*/5 * * * *',
    deliver='origin'
)

# CORRECT: periodic deep audit (LLM-powered)
cronjob(
    action='create',
    prompt='Run the audit and summarize findings',
    schedule='0 */6 * * *',
    deliver='origin'
)

# WRONG: LLM cron every 5 minutes — hits rate limits, burns tokens
cronjob(
    action='create',
    prompt='Check for attacks...',
    schedule='*/5 * * * *',  # TOO FREQUENT for LLM
    deliver='origin'
)
```
