---
name: secmon-audit-output-tuning
description: "Filter severity and format secmon audit output for Telegram."
version: 0.1.0
author: Hermes
platforms: [linux]
metadata:
  hermes:
    tags: [Devops, Security, Secmon, Telegram, Formatting]
---

# Secmon Audit Output Tuning

Tune what secmon's audit report shows — severity filtering, Telegram table formatting, and the code-review-commit cycle for output changes. Does NOT cover general secmon maintenance or anomaly tuning (see `secmon:secmon-maintenance` for that).

## When to Use

- User says "I don't want to see INFO level issues" in the audit output
- Table rows split or render incorrectly in Telegram
- Audit report has too much noise (LOW/INFO findings cluttering the view)
- User requests a different severity grouping or layout in the audit report
- Adding/removing severity levels from the audit output

## Prerequisites

- Secmon plugin at `~/.hermes/plugins/secmon/`
- Git repo with remote set up at `origin`
- User preference: never commit/push without explicit approval

## How to Run

1. Trigger the audit: use `cronjob(action='run', job_id='<audit_job_id>')` or run `secmon --audit` via terminal
2. Review the output in Telegram (user feedback tells you what to fix)
3. Patch the code in `output.py` or `audit_mode.py` per the procedure below
4. Test by triggering another audit
5. Commit when user says "commit and push"

## Quick Reference

| File | Purpose |
|------|---------|
| `src/secmon/output.py` | `format_audit_markdown()` — renders the full audit report table |
| `src/secmon/modes/audit_mode.py` | `run_audit_mode()` — bridges findings to alerts, calls formatter |
| `src/secmon/audit/__init__.py` | `run_audit()` — orchestrates all layers, returns all findings |
| `src/secmon/audit/trends.py` | Trend comparison — generates INFO-level trend_new/resolved/persistent findings |
| `src/secmon/alerts.py` | `findings_to_alerts()` — already filters INFO/LOW for the alert pipeline |
| `scripts/audit.py` | Cron delivery script — captures `--audit` stdout, sends via Telegram API |

## Procedure

### 1. Understand the Output Pipeline

The audit output flows through two separate paths:

- **Alert pipeline** (`alerts.py` → `findings_to_alerts(min_severity="HIGH")`): Already filters LOW/INFO. Only CRITICAL+HIGH findings become Telegram alerts.
- **Audit report** (`output.py` → `format_audit_markdown()`): Renders ALL severities (CRITICAL, HIGH, MEDIUM, LOW, INFO) in a single table. This is what the user sees in the "🔍 Secmon Audit" message.

The user's request "I don't want to see INFO level issues" targets the **audit report**, not the alert pipeline.

### 2. Locate the Formatting Code

The rendering is in `src/secmon/output.py` in `format_audit_markdown()`:

```python
for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
    group = [f for f in all_findings if f["severity"] == severity]
    if not group:
        continue
    # ... renders table rows for this severity group
```

To suppress INFO: either remove `"INFO"` from the loop, or add a `continue` condition.

### 3. Patch the Filter

Use `patch` to modify the severity loop. Example — skip INFO findings:

```python
for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
    group = [f for f in all_findings if f["severity"] == severity]
    if not group:
        continue
    if severity == "INFO":
        continue  # Suppress INFO-level noise from audit report
```

Or to be more aggressive and also suppress LOW:

```python
for severity in ("CRITICAL", "HIGH", "MEDIUM"):
    group = [f for f in all_findings if f["severity"] == severity]
    if not group:
        continue
```

### 4. Update the Header Counts

When suppressing severities, the summary header line (e.g. `🔴 2 CRIT · 🟠 2 HIGH · 🟡 1 MED · 🔵 3 LOW · Σ 8 risk 22`) must also be updated to reflect only the visible findings. The `low` count is computed as:

```python
low = sum(1 for f in result.get("findings", []) if f["severity"] in ("LOW", "INFO"))
```

When suppressing INFO, change this to only count LOW findings. When suppressing both, remove the `low` part from the `parts` list entirely.

### 5. Test the Change

```bash
cd ~/.hermes/plugins/secmon
source venv/bin/activate
python -c "from secmon.output import format_audit_markdown; print('import ok')"
```

Then trigger the cron audit job to verify the output in Telegram:

```python
# Use cronjob(action='run', job_id='<audit_job_id>')
# Or run directly:
# terminal(command="cd ~/.hermes/plugins/secmon && source venv/bin/activate && secmon --audit")
```

### 6. Commit (only after user says "commit and push")

```bash
cd ~/.hermes/plugins/secmon
git add src/secmon/output.py
git commit -m "fix(output): suppress INFO-level findings from audit report"
git push origin main
```

## Understanding Severity Sources

| Severity | Source | Why it appears |
|----------|--------|---------------|
| CRITICAL | Threat intel, process, network | Active compromise indicators |
| HIGH | Auth, network, threat intel | Significant exposure |
| MEDIUM | Compliance, file integrity | Configuration weakness |
| LOW | File integrity, compliance | Minor issue |
| INFO | **Trends layer** (`trends.py`) | `trend_new`, `trend_resolved`, `trend_persistent`, `layer_count` — these are *meta-checks* about the audit itself, not security findings |

The INFO findings come almost entirely from the trends layer (Layer 8). They report what changed since the last audit — new findings appeared, old ones resolved, or persistent ones remained. These are useful for change tracking but noise for a quick scan.

## Pitfalls

- **The header counts must match the visible rows.** If you suppress INFO from the table but the header still says `🔵 3 LOW`, the user will ask why there are 3 LOW rows but only 0 visible. Update both places.
- **LOW and INFO are counted together** in `format_audit_markdown()` (`f["severity"] in ("LOW", "INFO")`). If you only want to suppress INFO but keep LOW, change the aggregate count to `"LOW"` only.
- **Trends data is still stored in state.** Suppressing INFO from the report doesn't affect `state["last_audit_findings"]` — the trend comparison on the next run will still work correctly.
- **The alert pipeline is separate.** `findings_to_alerts(min_severity="HIGH")` in `audit_mode.py` already filters LOW/INFO. Changing the report filter doesn't affect alert behavior.
- **No commit without explicit approval.** Make changes, test, show the user the result. Only run `git commit` + `git push` when the user says "commit and push".

## Verification

Trigger the audit cron job and check Telegram for the output. The report should show only the severity levels you want, with matching header counts.