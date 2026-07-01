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
OUT="$("${CLI}" "${ARGS[@]}" 2>/dev/null)"
_rc=$?
set -e

# Silent ticks: if nothing was printed, emit nothing.
if [[ -z "${OUT}" ]]; then
  exit 0
fi

echo "${OUT}"

# Add actionable next steps + CTA for fast follow-up.
if [[ "${OUT}" == *"self_protection: Secmon state permissions too open"* ]]; then
  echo
  echo "=== What to do next (self-protection) ==="
  echo "Remediation (safe): lock down secmon state/config permissions."
  echo "1) Run: /secmon_remediate self_protection_fix_permissions"
  echo "2) Then verify:"
  echo "   - secmon --status"
  echo "   - hermes cron list (ensure secmon-tick is active)"
  echo
  echo "CTA: Send the command above so the Hermes agent applies the chmod fixes."
elif [[ "${OUT}" == *"self_protection: Secmon code file changed"* ]]; then
  echo
  echo "=== What to do next (self-protection) ==="
  echo "This indicates secmon code/config integrity drift."
  echo "Recommended remediation:"
  echo "1) Re-deploy from a trusted release/commit."
  echo "2) Ensure /opt/secmon (or your plugin dir) points to the expected checkout."
  echo "3) Restart Hermes gateway, then run:"
  echo "   - secmon --status"
  echo
  echo "CTA: Reply 'please audit + remediate' and include the new integrity alert details."
fi

exit 0
