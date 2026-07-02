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

_timestamp_utc() {
  date -u '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u
}

_emit_tick_remediation() {
  local out="$1"
  local cta=""

  echo
  echo "── What to do ──"

  if [[ "${out}" == *"self_protection:"*"permissions too open"* ]]; then
    local path=""
    # Extract the path from the alert line (e.g. "Secmon state permissions too open: /path/to/file (0o644)")
    path="$(echo "${out}" | sed -n 's/.*permissions too open: \([^ ]*\) .*/\1/p' | head -1)"
    echo "  Fix permissions:  chmod 600 ${path:-<path>}"
    echo "  Then verify:      secmon --status"
    cta="chmod 600 ${path:-<path>}"
  elif [[ "${out}" == *"self_protection: Secmon code file changed"* ]]; then
    echo "  Redeploy:         cd $(dirname ${SECMON_SOURCE:-/opt/secmon}) && git pull"
    echo "  Reinstall:        sudo ./scripts/install.sh"
    echo "  Verify:           secmon --status"
    cta="git pull && sudo ./scripts/install.sh"
  elif [[ "${out}" == *"self_protection: Secmon scheduler missing"* ]]; then
    echo "  Register jobs:    hermes cron add ... $(grep -r 'secmon-' /opt/secmon/cron/ 2>/dev/null)"
    echo "  Verify:           hermes cron list"
    cta="hermes cron list"
  elif [[ "${out}" == *"self_protection: Secmon install symlink retargeted"* ]] \
    || [[ "${out}" == *"self_protection: Secmon CLI symlink retargeted"* ]]; then
    echo "  Investigate:      ls -la /opt/secmon /usr/local/bin/secmon"
    echo "  Restore:          ln -sf /path/to/trusted/checkout /opt/secmon"
    echo "  Then run audit:   secmon --audit"
    cta="secmon --audit"
  elif [[ "${out}" == *"self_protection: Secmon Hermes delivery target changed"* ]]; then
    echo "  Inspect:          cat /etc/secmon/config.yaml | grep deliver_target"
    echo "  Reconfigure if unauthorized, then verify: secmon --status"
    cta="grep deliver /etc/secmon/config.yaml"
  elif [[ "${out}" == *"self_protection:"* ]]; then
    echo "  Investigate:      secmon --audit"
    echo "  Check logs:       tail -50 /var/log/security-monitor.log"
    cta="secmon --audit"
  elif [[ "${out}" == *"brute_force:"* ]]; then
    echo "  Check fail2ban:   fail2ban-client status sshd"
    echo "  Review logs:      journalctl -u ssh --since '1 hour ago' | grep 'Failed password'"
    echo "  Block subnets:    secmon --detect-botnet"
    cta="fail2ban-client status sshd"
  elif [[ "${out}" == *"fail2ban:"* ]]; then
    echo "  List banned:      fail2ban-client status sshd"
    echo "  Review auth:      journalctl -u ssh --since '1 hour ago' | tail -30"
    cta="fail2ban-client status sshd"
  elif [[ "${out}" == *"outbound:"* ]] || [[ "${out}" == *"c2:"* ]]; then
    echo "  Investigate:      ss -tlnp | grep ESTAB"
    echo "  Trace:            lsof -i -n | head -20"
    echo "  Full audit:       secmon --audit"
    cta="ss -tlnp | grep ESTAB"
  elif [[ "${out}" == *"anomaly:"* ]]; then
    echo "  Check metrics:    secmon --check"
    echo "  Full audit:       secmon --audit"
    cta="secmon --check"
  elif [[ "${out}" == *"ssh:"* ]] || [[ "${out}" == *"ssh_session:"* ]]; then
    echo "  Active sessions:  ss -tnp | grep ':22 '"
    echo "  Review:           last | head -20"
    echo "  Full audit:       secmon --audit"
    cta="ss -tnp | grep ':22 '"
  elif [[ "${out}" == *"botnet:"* ]]; then
    echo "  Blocked subnets:  iptables -L BOTNET -n --line-numbers"
    echo "  Logs:             tail -20 /var/log/secmon-botnet.log"
    cta="iptables -L BOTNET -n"
  elif [[ "${out}" == *"audit:"* ]]; then
    echo "  Review full audit:  secmon --audit"
    echo "  Check trends:       grep trend /var/log/security-monitor.log | tail -5"
    cta="secmon --audit"
  else
    echo "  Review alert:       cat /var/log/security-monitor.log | tail -10"
    echo "  Full audit:         secmon --audit"
    cta="secmon --audit"
  fi

  if [[ -n "${cta}" ]]; then
    echo
    echo "▶ ${cta}"
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

echo "=== secmon tick — $(_timestamp_utc) ==="
echo
echo "${OUT}"
_emit_tick_remediation "${OUT}"

exit 0
