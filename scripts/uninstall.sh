#!/usr/bin/env bash
# Secmon uninstaller — removes symlinks, Hermes cron jobs, venv; preserves source by default.
set -euo pipefail

SOURCE_DIR="${SECMON_SOURCE:-/opt/secmon}"
CLI_PATH="${SECMON_CLI:-/usr/local/bin/secmon}"
VENV_DIR="${SECMON_VENV:-${SOURCE_DIR}/venv}"
CONFIG_DIR="/etc/secmon"
DATA_DIR="/var/lib/secmon"
PURGE=0
REMOVE_BOTNET=0
REMOVE_SOURCE_LINK=1

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Remove secmon installation artifacts. Does NOT delete the source checkout by default.

Options:
  --source DIR       Installed symlink path (default: ${SOURCE_DIR})
  --cli PATH         CLI symlink (default: ${CLI_PATH})
  --purge            Also remove config, state, and logs
  --remove-botnet    Flush iptables BOTNET chain before exit
  --keep-source      Leave ${SOURCE_DIR} symlink in place
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --cli) CLI_PATH="$2"; shift 2 ;;
    --venv) VENV_DIR="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    --remove-botnet) REMOVE_BOTNET=1; shift ;;
    --keep-source) REMOVE_SOURCE_LINK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if command -v hermes >/dev/null 2>&1; then
  echo "==> Removing Hermes cron jobs"
  for job in secmon-tick secmon-audit secmon-daily; do
    hermes cron remove "${job}" 2>/dev/null || true
  done
  echo "==> Disabling Hermes plugin"
  hermes plugins disable secmon 2>/dev/null || true

  # Remove Hermes wrapper scripts we installed (if present).
  HERMES_SCRIPTS_DIR="${HOME}/.hermes/scripts/secmon"
  rm -rf "${HERMES_SCRIPTS_DIR}" 2>/dev/null || true
else
  echo "==> Hermes CLI not found — skip cron/plugin cleanup"
fi

echo "==> Removing CLI symlink"
if [[ -L "${CLI_PATH}" ]]; then
  rm -f "${CLI_PATH}"
elif [[ -e "${CLI_PATH}" ]]; then
  echo "Warning: ${CLI_PATH} exists and is not a symlink; not removed" >&2
fi

if [[ "${REMOVE_SOURCE_LINK}" -eq 1 ]] && [[ -L "${SOURCE_DIR}" ]]; then
  echo "==> Removing source symlink ${SOURCE_DIR}"
  rm -f "${SOURCE_DIR}"
fi

if [[ -d "${VENV_DIR}" ]]; then
  echo "==> Removing virtual environment ${VENV_DIR}"
  rm -rf "${VENV_DIR}"
fi

if [[ "${REMOVE_BOTNET}" -eq 1 ]]; then
  echo "==> Removing iptables BOTNET chain"
  while iptables -C INPUT -j BOTNET 2>/dev/null; do
    iptables -D INPUT -j BOTNET
  done
  iptables -F BOTNET 2>/dev/null || true
  iptables -X BOTNET 2>/dev/null || true
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save || true
  fi
fi

if [[ "${PURGE}" -eq 1 ]]; then
  echo "==> Purging config, state, and logs"
  rm -rf "${CONFIG_DIR}" "${DATA_DIR}"
  rm -f /var/log/security-monitor.log /var/log/secmon-botnet.log /var/log/secmon-audit.json
else
  echo "==> Preserving config (${CONFIG_DIR}), state (${DATA_DIR}), and logs"
  echo "    Re-run with --purge to remove them."
fi

echo "Secmon uninstalled."
