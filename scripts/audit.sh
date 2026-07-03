#!/usr/bin/env bash
# Hermes cron wrapper — deep forensic audit (every 6 hours).
# Prints Markdown audit report to stdout for gateway delivery.
set -euo pipefail

PLUGIN_DIR="${SECMON_PLUGIN_DIR:-${HOME}/.hermes/plugins/secmon}"

CLI="${SECMON_CLI:-}"
if [[ -x "${PLUGIN_DIR}/venv/bin/secmon" ]]; then
  CLI="${PLUGIN_DIR}/venv/bin/secmon"
elif [[ -x "${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon" ]]; then
  CLI="${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon"
else
  CLI="/usr/local/bin/secmon"
fi

CONFIG="${SECMON_CONFIG_PATH:-/etc/secmon/config.yaml}"
ARGS=(--audit)
if [[ -f "${CONFIG}" ]]; then
  ARGS+=(--config "${CONFIG}")
fi

_timestamp_utc() {
  date -u '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u
}

set +e
OUT="$("${CLI}" "${ARGS[@]}" 2>/dev/null)"
_rc=$?
set -e

if [[ -z "${OUT}" ]]; then
  exit 0
fi

echo "*$(_timestamp_utc)*"
echo ""
echo "${OUT}"

exit 0
