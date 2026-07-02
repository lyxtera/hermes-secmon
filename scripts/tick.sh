#!/usr/bin/env bash
# Hermes cron wrapper — primary security tick (every 15 min).
# Prints findings to stdout in Markdown; empty output = silent tick.
set -euo pipefail

PLUGIN_DIR="${SECMON_PLUGIN_DIR:-${HOME}/.hermes/plugins/secmon}"

# Prefer a CLI from the plugin dir venv when available; otherwise fall back to /usr/local/bin.
CLI="${SECMON_CLI:-}"
if [[ -x "${PLUGIN_DIR}/venv/bin/secmon" ]]; then
  CLI="${PLUGIN_DIR}/venv/bin/secmon"
elif [[ -x "${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon" ]]; then
  CLI="${SECMON_SOURCE:-/opt/secmon}/venv/bin/secmon"
else
  CLI="/usr/local/bin/secmon"
fi

CONFIG="${SECMON_CONFIG_PATH:-/etc/secmon/config.yaml}"
ARGS=(--tick)
if [[ -f "${CONFIG}" ]]; then
  ARGS+=(--config "${CONFIG}")
fi

_timestamp_utc() {
  date -u '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u
}

_emit_tick_remediation() {
  local out="$1"
  local cta=""

  echo ""
  echo "### 🛠️ What to do"
  echo ""

  if [[ "${out}" == *"permissions too open"* ]]; then
    local path=""
    path="$(echo "${out}" | sed -n 's/.*permissions too open: \([^ ]*\) .*/\1/p' | head -1)"
    echo "- \`chmod 600 ${path:-<path>}\` — Fix permissions"
    echo "- \`secmon --status\` — Verify"
    cta="chmod 600 ${path:-<path>}"
  elif [[ "${out}" == *"Secmon code file changed"* ]]; then
    echo "- \`cd $(dirname ${SECMON_SOURCE:-/opt/secmon}) && git pull\` — Pull latest code"
    echo "- \`sudo ./scripts/install.sh\` — Reinstall"
    echo "- \`secmon --status\` — Verify"
    cta="git pull && sudo ./scripts/install.sh"
  elif [[ "${out}" == *"Secmon scheduler missing"* ]]; then
    echo "- Register Hermes cron jobs from \`cron/jobs.yaml\`"
    echo "- \`hermes cron list\` — Verify"
    cta="hermes cron list"
  elif [[ "${out}" == *"symlink retargeted"* ]]; then
    echo "- \`ls -la /opt/secmon /usr/local/bin/secmon\` — Investigate"
    echo "- \`ln -sf /path/to/trusted/checkout /opt/secmon\` — Restore"
    echo "- \`secmon --audit\` — Full audit"
    cta="secmon --audit"
  elif [[ "${out}" == *"Secmon Hermes delivery target changed"* ]]; then
    echo "- \`grep deliver /etc/secmon/config.yaml\` — Inspect"
    echo "- Reconfigure if unauthorized, then \`secmon --status\`"
    cta="grep deliver /etc/secmon/config.yaml"
  elif [[ "${out}" == *"self_protection:"* ]]; then
    echo "- \`secmon --audit\` — Full investigation"
    echo "- \`tail -50 /var/log/security-monitor.log\` — Check logs"
    cta="secmon --audit"
  elif [[ "${out}" == *"brute_force:"* ]]; then
    echo "- \`fail2ban-client status sshd\` — Check fail2ban"
    echo "- \`journalctl -u ssh --since '1 hour ago' | grep 'Failed password'\` — Review logs"
    echo "- \`secmon --detect-botnet\` — Block aggressive subnets"
    cta="fail2ban-client status sshd"
  elif [[ "${out}" == *"fail2ban:"* ]] || [[ "${out}" == *"ban burst"* ]]; then
    echo "- \`fail2ban-client status sshd\` — List banned IPs"
    echo "- \`journalctl -u ssh --since '1 hour ago' | tail -30\` — Review auth"
    cta="fail2ban-client status sshd"
  elif [[ "${out}" == *"outbound:"* ]] || [[ "${out}" == *"c2:"* ]]; then
    echo "- \`ss -tlnp | grep ESTAB\` — Investigate connections"
    echo "- \`lsof -i -n | head -20\` — Trace processes"
    echo "- \`secmon --audit\` — Full audit"
    cta="ss -tlnp | grep ESTAB"
  elif [[ "${out}" == *"anomaly:"* ]]; then
    echo "- \`secmon --check\` — Check metrics"
    echo "- \`secmon --audit\` — Full audit for root cause"
    cta="secmon --check"
  elif [[ "${out}" == *"ssh:"* ]] || [[ "${out}" == *"ssh_session:"* ]]; then
    echo "- \`ss -tnp | grep ':22 '\` — Active sessions"
    echo "- \`last | head -20\` — Recent logins"
    echo "- \`secmon --audit\` — Full audit"
    cta="ss -tnp | grep ':22 '"
  elif [[ "${out}" == *"botnet:"* ]]; then
    echo "- \`iptables -L BOTNET -n --line-numbers\` — Blocked subnets"
    echo "- \`tail -20 /var/log/secmon-botnet.log\` — Botnet logs"
    cta="iptables -L BOTNET -n"
  elif [[ "${out}" == *"audit:"* ]]; then
    echo "- \`secmon --audit\` — Review full audit"
    echo "- \`grep trend /var/log/security-monitor.log | tail -5\` — Check trends"
    cta="secmon --audit"
  else
    echo "- \`cat /var/log/security-monitor.log | tail -10\` — Review alerts"
    echo "- \`secmon --audit\` — Full audit"
    cta="secmon --audit"
  fi

  if [[ -n "${cta}" ]]; then
    echo ""
    echo "▶ \`${cta}\`"
  fi
}

# Hermes cron considers non-zero exit codes as job failures.
set +e
OUT="$("${CLI}" "${ARGS[@]}" 2>/dev/null)"
_rc=$?
set -e

# Silent ticks: if nothing was printed, emit nothing.
if [[ -z "${OUT}" ]]; then
  exit 0
fi

echo "## 🔔 Secmon Tick"
echo "*$(_timestamp_utc)*"
echo ""
echo "${OUT}"
_emit_tick_remediation "${OUT}"

exit 0