#!/usr/bin/env bash
# cron-secmon-record.sh — Hermes cron wrapper for secmon --record
# Called by Hermes cron (no_agent mode). Empty stdout = silent (no delivery).
# Only outputs on error.
set -euo pipefail
OUTPUT="$(/opt/secmon/venv/bin/secmon --record 2>&1)" && RC=$? || RC=$?
printf '%s' "$OUTPUT"
exit 0