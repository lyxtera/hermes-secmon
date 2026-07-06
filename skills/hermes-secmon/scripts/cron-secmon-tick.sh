#!/usr/bin/env bash
# cron-secmon-tick.sh — Hermes cron wrapper for secmon --tick
# Called by Hermes cron (no_agent mode). Empty stdout = silent (no delivery).
# Only outputs when HIGH/CRITICAL alerts fire.
set -euo pipefail
OUTPUT="$(/opt/secmon/venv/bin/secmon --tick 2>&1)" && RC=$? || RC=$?
printf '%s' "$OUTPUT"
exit 0