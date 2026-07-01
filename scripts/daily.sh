#!/usr/bin/env bash
# Hermes cron wrapper — daily security digest (08:00 UTC).
# Always produces human-readable output for gateway delivery.
set -euo pipefail

PLUGIN_DIR="${SECMON_PLUGIN_DIR:-${HOME}/.hermes/plugins/secmon}"

# Prefer a CLI from the plugin dir venv when available; otherwise fall back to /usr/local/bin.
CLI="${SECMON_CLI:-}"
if [[ -z "${CLI}" ]]; then
  if [[ -x "${PLUGIN_DIR}/venv/bin/secmon" ]]; then
    CLI="${PLUGIN_DIR}/venv/bin/secmon"
  elif [[ -x "${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon" ]]; then
    CLI="${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon"
  else
    CLI="/usr/local/bin/secmon"
  fi
fi

CONFIG="${SECMON_CONFIG_PATH:-/etc/secmon/config.yaml}"
ARGS=(--daily)
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

echo "=== secmon daily — $(_timestamp_utc) ==="
echo
echo "${OUT}"
echo
echo "--- What to do next ---"
echo "1) Compare metrics and anomalies against baselines."
echo "2) If anything looks unexpected, run a full forensic audit."
echo
echo "CTA: /secmon audit"

exit 0
