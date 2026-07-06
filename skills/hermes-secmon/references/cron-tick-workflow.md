# Cron Tick Workflow

## Running a Security Tick

The primary cron entry point. Run every 15 minutes.

```bash
/opt/secmon/venv/bin/secmon --tick
```

### Output Interpretation

The tick is designed to be **silent on success** (exit 0, no stdout). Output format is **Markdown** for Telegram delivery:

```
## 🔔 Secmon Tick
*2026-07-02 01:45 UTC*

**HIGH** `self_protection`: Secmon state permissions too open: /path/file (0o644) → `chmod 600 <path>`

### 🛠️ What to do

- `chmod 600 /path/file` — Fix permissions
- `secmon --status` — Verify

▶ `chmod 600 /path/file`
```

- Empty output = nothing new since last tick. System is healthy.
- Non-empty output = new alerts with Markdown formatting: **bold** severity, `backtick` source, inline fix command.
- "What to do" section provides copy-paste shell commands.
- CTA line (▶ \`command\`) shows the primary action.

**The tick only reports *new* events since last run.** For full picture, check logs and state.

### What to Look For in Logs

Log entries are JSON lines with fields: `ts`, `level`, `source`, `severity`, `message`, `structured`.

| Source | Typical Severity | Meaning |
|--------|-----------------|---------|
| `fail2ban` | HIGH | New SSH bans (per-IP, 24h dedup) |
| `ports` | CRITICAL | New unauthorized listening port |
| `brute_force` | CRITICAL | SSH failure burst in 5 min window |
| `outbound` | HIGH | Suspicious outbound connections |
| `anomaly` | HIGH | Statistical deviation from baseline |
| `botnet` | CRITICAL | Subnet-level blocking triggered |

### Common Scenarios

- **Silent tick + no log entries:** System is clean.
- **Silent tick + HIGH log entries:** Ongoing condition within dedup window — already reported.
- **Tick with stdout output:** New alerts generated, delivered via Markdown to Telegram.
- **Tick exit code 1:** New alerts generated (same as N > 0 in stdout).