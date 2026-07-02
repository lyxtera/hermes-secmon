#!/usr/bin/env bash
# Hermes cron wrapper — daily security digest (08:00 UTC).
# Always produces human-readable Markdown output for gateway delivery.
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

echo "## 📅 Secmon Daily Digest"
echo "*$(_timestamp_utc)*"
echo ""
echo '```'
echo "${OUT}"
echo '```'
echo ""
echo "### 📋 Next steps"
echo ""
echo "- Compare metrics and anomalies against baselines"
echo "- If anything looks unexpected, run a full forensic audit"
echo ""
echo "▶ \`secmon --audit\`"

exit 0