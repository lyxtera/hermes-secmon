#!/usr/bin/env bash
# Hermes cron wrapper — deep forensic audit (every 6 hours).
# Prints JSON audit report in Markdown to stdout for gateway delivery.
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

echo "## 🔍 Secmon Audit"
echo "*$(_timestamp_utc)*"
echo ""
echo '```json'
echo "${OUT}"
echo '```'
echo ""
echo "### 📊 Summary"

findings=$(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('finding_count','?'))" 2>/dev/null || echo "?")
score=$(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_score','?'))" 2>/dev/null || echo "?")
critical=$(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('critical_count','?'))" 2>/dev/null || echo "?")
high=$(echo "${OUT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('high_count','?'))" 2>/dev/null || echo "?")

echo "| Metric | Value |"
echo "|--------|-------|"
echo "| **Score** | ${score} |"
echo "| **Findings** | ${findings} |"
echo "| **🔴 CRITICAL** | ${critical} |"
echo "| **🟠 HIGH** | ${high} |"
echo ""
echo "### 📋 Next steps"
echo ""
echo "- Review layers with **CRITICAL** or **HIGH** findings"
echo "- Each \`check_id\` above includes a message with the exact issue"
echo "- Run \`secmon --audit\` again after applying fixes to verify"
echo ""
echo "▶ \`secmon --audit\`"

exit 0