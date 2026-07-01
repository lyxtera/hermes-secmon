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
  local cta="/secmon audit"

  echo
  echo "--- What to do next ---"

  if [[ "${out}" == *"self_protection: Secmon state permissions too open"* ]] \
    || [[ "${out}" == *"self_protection: Secmon config permissions too open"* ]] \
    || [[ "${out}" == *"self_protection: Secmon log permissions too open"* ]] \
    || [[ "${out}" == *"self_protection: Secmon data_dir permissions too open"* ]]; then
    echo "1) Lock down secmon file permissions (safe automated fix)."
    echo "2) Verify with /secmon status and hermes cron list."
    cta="/secmon_remediate self_protection_fix_permissions"
  elif [[ "${out}" == *"self_protection: Secmon code file changed"* ]]; then
    echo "1) Re-deploy secmon from a trusted release/commit."
    echo "2) Confirm plugin checkout path is expected (~/.hermes/plugins/secmon)."
    echo "3) Restart Hermes gateway, then run /secmon status."
    cta="audit + remediate"
  elif [[ "${out}" == *"self_protection: Secmon scheduler missing"* ]]; then
    echo "1) Re-register Hermes cron jobs (see cron/jobs.yaml)."
    echo "2) Ensure hermes gateway is running: hermes gateway start."
    echo "3) Verify with: hermes cron list"
    cta="/secmon status"
  elif [[ "${out}" == *"self_protection: Secmon install symlink retargeted"* ]] \
    || [[ "${out}" == *"self_protection: Secmon CLI symlink retargeted"* ]]; then
    echo "1) Investigate unexpected symlink changes immediately."
    echo "2) Re-point install to trusted checkout and redeploy."
    echo "3) Run /secmon audit for persistence-layer findings."
    cta="/secmon audit"
  elif [[ "${out}" == *"self_protection: Secmon Hermes delivery target changed"* ]]; then
    echo "1) Verify /etc/secmon/config.yaml hermes.deliver_target is intentional."
    echo "2) Confirm no unauthorized config edits."
    echo "3) Run /secmon status."
    cta="/secmon status"
  elif [[ "${out}" == *"self_protection:"* ]]; then
    echo "1) Treat as monitor tamper/integrity issue."
    echo "2) Run /secmon audit and review self-protection findings."
    cta="/secmon audit"
  elif [[ "${out}" == *"brute_force:"* ]]; then
    echo "1) Confirm attack source subnets in fail2ban/iptables."
    echo "2) Run botnet blocking for aggressive /24 subnets."
    cta="/secmon_detect_botnet"
  elif [[ "${out}" == *"fail2ban:"* ]]; then
    echo "1) Review newly banned IPs and auth logs."
    echo "2) Run /secmon check, then escalate with botnet analysis if needed."
    cta="/secmon_detect_botnet"
  elif [[ "${out}" == *"outbound:"* ]] || [[ "${out}" == *"c2:"* ]]; then
    echo "1) Investigate the process owning suspicious outbound connections."
    echo "2) Consider isolating the host/network path until triaged."
    echo "3) Run a full forensic audit."
    cta="/secmon audit"
  elif [[ "${out}" == *"anomaly:"* ]]; then
    echo "1) Re-check current metrics vs baseline."
    echo "2) Run /secmon check, then /secmon audit for root cause."
    cta="/secmon audit"
  elif [[ "${out}" == *"ssh:"* ]] || [[ "${out}" == *"ssh_session:"* ]]; then
    echo "1) Investigate unauthorized SSH session immediately."
    echo "2) Verify allowed IPs and active sessions."
    echo "3) Run full audit for persistence indicators."
    cta="/secmon audit"
  elif [[ "${out}" == *"botnet:"* ]]; then
    echo "1) Review newly blocked /24 subnets."
    echo "2) Confirm iptables BOTNET chain and whitelist settings."
    cta="/secmon status"
  elif [[ "${out}" == *"audit:"* ]]; then
    echo "1) Review CRITICAL/HIGH audit findings in detail."
    echo "2) Ask Hermes to summarize and prioritize remediation."
    cta="/secmon audit"
  else
    echo "1) Review alert details above."
    echo "2) Run a full forensic audit if impact is unclear."
    cta="/secmon audit"
  fi

  echo
  echo "CTA: ${cta}"
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
