#!/usr/bin/env bash
# Hermes cron wrapper — primary security tick (every 15 min).
# Prints findings to stdout; empty output = silent tick (no gateway delivery).
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
ARGS=(--tick)
if [[ -f "${CONFIG}" ]]; then
  ARGS+=(--config "${CONFIG}")
fi

# Hermes cron considers non-zero exit codes as job failures.
# secmon returns `1` when it emits new alerts; for cron delivery we still
# want Hermes to treat that as a successful run, so always exit 0.
set +e
"${CLI}" "${ARGS[@]}"
_rc=$?
set -e
exit 0
