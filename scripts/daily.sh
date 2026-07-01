#!/usr/bin/env bash
# Hermes cron wrapper — daily security digest (08:00 UTC).
# Always produces human-readable output for gateway delivery.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLI="${SECMON_CLI:-/usr/local/bin/secmon}"
if [[ ! -x "${CLI}" ]] && [[ -x "${REPO_ROOT}/venv/bin/secmon" ]]; then
  CLI="${REPO_ROOT}/venv/bin/secmon"
fi

CONFIG="${SECMON_CONFIG_PATH:-/etc/secmon/config.yaml}"
ARGS=(--daily)
if [[ -f "${CONFIG}" ]]; then
  ARGS+=(--config "${CONFIG}")
fi

exec "${CLI}" "${ARGS[@]}"
