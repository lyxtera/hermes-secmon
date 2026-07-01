#!/usr/bin/env bash
# Hermes cron wrapper — deep forensic audit (every 6 hours).
# Prints JSON audit report to stdout for gateway delivery.
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
ARGS=(--audit)
if [[ -f "${CONFIG}" ]]; then
  ARGS+=(--config "${CONFIG}")
fi

# Hermes cron considers non-zero exit codes as job failures.
# Ignore secmon exit codes in cron context; delivery depends on stdout.
set +e
"${CLI}" "${ARGS[@]}"
_rc=$?
set -e
exit 0
