# Severity Filter Patches for `output.py`

Exact patches applied 2026-07-05 to suppress INFO-level findings from the secmon audit report.

## Patch 1: Fix Header Counts

The `low` variable counted both LOW and INFO together. Change to count only LOW:

```python
# BEFORE
low = sum(1 for f in result.get("findings", []) if f["severity"] in ("LOW", "INFO"))

# AFTER
low = sum(1 for f in result.get("findings", []) if f["severity"] == "LOW")
```

This ensures the header line (e.g. `🔴 2 CRIT · 🟠 2 HIGH · 🟡 1 MED · 🔵 3 LOW · Σ 8 risk 22`) matches the visible rows.

## Patch 2: Remove INFO from Severity Loop

The iteration loop renders table rows per severity. Remove `"INFO"` to suppress those rows entirely:

```python
# BEFORE
for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):

# AFTER
for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
```

## Verification

```bash
cd ~/.hermes/plugins/secmon
source venv/bin/activate
python -c "from secmon.output import format_audit_markdown; print('import ok')"
```

Then trigger the cron audit job:

```python
cronjob(action='run', job_id='<audit-job-id>')
```

## What INFO Findings Are

| check_id | Description | Source |
|----------|-------------|--------|
| `trend_new` | A new finding appeared since last audit | `audit/trends.py` |
| `trend_resolved` | A previous finding no longer present | `audit/trends.py` |
| `trend_persistent` | Same findings persist across cycles | `audit/trends.py` |
| `layer_count` | Count of findings per layer | `audit/trends.py` |

These are **meta-checks about the audit itself**, not security findings. Useful for change tracking but noise for a quick scan. Suppressing INFO from the report does not affect the alert pipeline (`findings_to_alerts(min_severity="HIGH")` already filters them out).