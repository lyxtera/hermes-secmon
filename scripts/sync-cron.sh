#!/usr/bin/env bash
# Sync secmon cron wrapper scripts from the plugin to ~/.hermes/scripts/.
# Run this after git pull to propagate script updates to Hermes cron jobs.
set -euo pipefail

SOURCE="${1:-/opt/secmon}"
SCRIPTS_DIR="${HOME}/.hermes/scripts/secmon"

if [[ ! -d "${SOURCE}/scripts" ]]; then
  echo "Error: secmon source not found at ${SOURCE}" >&2
  echo "Usage: $0 [path-to-secmon-source]" >&2
  exit 1
fi

mkdir -p "${SCRIPTS_DIR}"
cp "${SOURCE}/scripts/tick.py"  "${SCRIPTS_DIR}/tick.py"
cp "${SOURCE}/scripts/audit.py" "${SCRIPTS_DIR}/audit.py"
cp "${SOURCE}/scripts/daily.py" "${SCRIPTS_DIR}/daily.py"
chmod +x "${SCRIPTS_DIR}"/*.py

echo "Synced secmon cron scripts to ${SCRIPTS_DIR}/"
echo "  tick.py  → ${SCRIPTS_DIR}/tick.py"
echo "  audit.py → ${SCRIPTS_DIR}/audit.py"
echo "  daily.py → ${SCRIPTS_DIR}/daily.py"