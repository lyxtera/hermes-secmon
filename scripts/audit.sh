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

echo "=== secmon audit — $(_timestamp_utc) ==="
echo
echo "${OUT}"
echo
echo "── Summary ──"
echo "  Findings:    $(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('finding_count','?'))" 2>/dev/null || echo "see above")"
echo "  Score:       $(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_score','?'))" 2>/dev/null || echo "see above")"
echo "  CRITICAL:    $(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('critical_count','?'))" 2>/dev/null || echo "see above")"
echo "  HIGH:        $(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('high_count','?'))" 2>/dev/null || echo "see above")"
echo
echo "── Next steps ──"
echo "  Review layers with CRITICAL/HIGH findings."
echo "  Fix: refer to each check_id's message for the exact remediation."
echo "  Verify: secmon --audit after applying fixes."
echo
echo "▶ secmon --audit"

exit 0
