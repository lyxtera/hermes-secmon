#!/usr/bin/env bash
# cron-secmon-audit.sh — Hermes cron wrapper for secmon --audit
# Called by Hermes cron (no_agent mode). Output is full Markdown with
# emoji icons, severity grouping, and no raw JSON (format_audit_markdown).
# Silents (exits 0) when no findings.
set -euo pipefail

OUTPUT="$(/opt/secmon/venv/bin/secmon --audit 2>/dev/null)" && RC=$? || RC=$?

# Check if output is just the header + empty findings (clean)
if echo "$OUTPUT" | grep -q "✅ \*\*No findings"; then
  exit 0
fi

# Output is already full Markdown — pass through directly
echo "$OUTPUT"
exit 0