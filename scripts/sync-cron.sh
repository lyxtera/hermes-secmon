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
cp "${SOURCE}/scripts/tick.sh"   "${SCRIPTS_DIR}/tick.sh"
cp "${SOURCE}/scripts/audit.sh"  "${SCRIPTS_DIR}/audit.sh"
cp "${SOURCE}/scripts/daily.sh"  "${SCRIPTS_DIR}/daily.sh"
chmod +x "${SCRIPTS_DIR}"/*.sh

echo "Synced secmon cron scripts to ${SCRIPTS_DIR}/"
echo "  tick.sh  → ${SCRIPTS_DIR}/tick.sh"
echo "  audit.sh → ${SCRIPTS_DIR}/audit.sh"
echo "  daily.sh → ${SCRIPTS_DIR}/daily.sh"