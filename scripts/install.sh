#!/usr/bin/env bash
# Secmon installer — symlink-based deployment + Hermes plugin/cron registration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_DIR="${SECMON_SOURCE:-/opt/secmon}"
CLI_PATH="${SECMON_CLI:-/usr/local/bin/secmon}"
VENV_DIR="${SECMON_VENV:-${SOURCE_DIR}/venv}"
CONFIG_DIR="/etc/secmon"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
DATA_DIR="/var/lib/secmon"
LOG_FILE="/var/log/security-monitor.log"
BOTNET_LOG="/var/log/secmon-botnet.log"
SKIP_HERMES_CRON=0

usage() {
  cat <<EOF
Usage: sudo $0 [options]

Install secmon using symlinks to the source checkout (no code copy).
Registers the Hermes plugin and cron jobs when the hermes CLI is available.

Options:
  --source DIR         Stable symlink path (default: ${SOURCE_DIR})
  --repo DIR           Source checkout (default: ${REPO_ROOT})
  --cli PATH           CLI symlink path (default: ${CLI_PATH})
  --venv DIR           Python venv directory (default: \${SOURCE_DIR}/venv)
  --skip-hermes-cron   Do not register Hermes cron jobs
  -h, --help           Show this help

Environment overrides: SECMON_SOURCE, SECMON_CLI, SECMON_VENV
EOF
}

REPO="${REPO_ROOT}"

# If we're already running from a Hermes project plugin directory, reuse it.
# This avoids creating unnecessary symlinks like /opt/secmon -> <repo>.
if [[ "${SOURCE_DIR}" == "/opt/secmon" ]] && [[ -f "${REPO_ROOT}/plugin.yaml" ]] && [[ "${REPO_ROOT}" == *"/.hermes/plugins/"* ]]; then
  echo "==> Using Hermes plugin directory directly: ${REPO_ROOT}"
  SOURCE_DIR="${REPO_ROOT}"
  VENV_DIR="${SOURCE_DIR}/venv"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --cli) CLI_PATH="$2"; shift 2 ;;
    --venv) VENV_DIR="$2"; shift 2 ;;
    --skip-hermes-cron) SKIP_HERMES_CRON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if [[ ! -f "${REPO}/pyproject.toml" ]]; then
  echo "Invalid repo: ${REPO} (missing pyproject.toml)" >&2
  exit 1
fi

for cmd in python3 iptables; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

echo "==> Creating directories"
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${DATA_DIR}/snapshots"
touch "${LOG_FILE}" "${BOTNET_LOG}"
chmod 700 "${DATA_DIR}"
chmod 600 "${CONFIG_FILE}" 2>/dev/null || true
chmod 640 "${LOG_FILE}" "${BOTNET_LOG}" 2>/dev/null || true

echo "==> Installing BPF auditd rules (best-effort)"
BPF_RULES_SRC="${SOURCE_DIR}/packaging/secmon-bpf.rules"
BPF_RULES_DST="/etc/audit/rules.d/secmon-bpf.rules"
if [[ -f "${BPF_RULES_SRC}" ]] && [[ -d /etc/audit/rules.d ]]; then
  cp "${BPF_RULES_SRC}" "${BPF_RULES_DST}"
  chmod 640 "${BPF_RULES_DST}" 2>/dev/null || true
  echo "    Installed ${BPF_RULES_DST}"
  if command -v augenrules >/dev/null 2>&1 && systemctl is-active auditd >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || echo "    Warning: augenrules --load failed (restart auditd manually)" >&2
  elif ! command -v auditctl >/dev/null 2>&1; then
    echo "    Note: install auditd for short-lived BPF syscall monitoring (optional)" >&2
  fi
else
  echo "    Skipped (rules source or /etc/audit/rules.d missing)"
fi

echo "==> Linking source checkout -> ${SOURCE_DIR}"
mkdir -p "$(dirname "${SOURCE_DIR}")"
if [[ "${SOURCE_DIR}" != "${REPO_ROOT}" ]]; then
  if [[ -L "${SOURCE_DIR}" ]]; then
    ln -sfn "${REPO}" "${SOURCE_DIR}"
  elif [[ -e "${SOURCE_DIR}" ]]; then
    echo "Refusing to overwrite non-symlink ${SOURCE_DIR}" >&2
    exit 1
  else
    ln -s "${REPO}" "${SOURCE_DIR}"
  fi
else
  echo "==> Skipping symlink (already using ${SOURCE_DIR})"
fi

echo "==> Creating Python virtual environment"
if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip -q
pip install -e "${SOURCE_DIR}" -q

echo "==> Installing CLI symlink ${CLI_PATH}"
mkdir -p "$(dirname "${CLI_PATH}")"
ln -sfn "${VENV_DIR}/bin/secmon" "${CLI_PATH}"

chmod +x "${SOURCE_DIR}/scripts/tick.py" \
  "${SOURCE_DIR}/scripts/audit.py" \
  "${SOURCE_DIR}/scripts/daily.py"

if [[ ! -e "${CONFIG_FILE}" ]]; then
  # Handle dangling symlink (cp cannot write "through" it).
  if [[ -L "${CONFIG_FILE}" ]]; then
    rm -f "${CONFIG_FILE}"
  fi
  echo "==> Installing example config -> ${CONFIG_FILE}"
  cp "${SOURCE_DIR}/config.yaml.example" "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"
  echo "    Edit ${CONFIG_FILE} and set whitelist.own_ip before production use."
fi

read_deliver_target() {
  python3 - <<'PY' "${CONFIG_FILE}"
import sys
import yaml
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    print((cfg.get("hermes") or {}).get("deliver_target", "") or "")
except Exception:
    print("")
PY
}

if command -v hermes >/dev/null 2>&1; then
  echo "==> Enabling Hermes plugin"
  hermes plugins enable secmon 2>/dev/null || true

  if [[ "${SKIP_HERMES_CRON}" -eq 0 ]]; then
    DELIVER="$(read_deliver_target)"
    DELIVER_ARGS=()
    if [[ -n "${DELIVER}" ]]; then
      DELIVER_ARGS=(--deliver "${DELIVER}")
    fi

    echo "==> Registering Hermes cron jobs (no-agent mode)"

    # Hermes cron requires --script to be relative to ~/.hermes/scripts/.
    # Copy delivery scripts there (symlinks won't work — cron resolves real paths
    # and blocks paths outside the scripts directory). After git pull,
    # re-run install.sh or manually copy the updated scripts.
    HERMES_SCRIPTS_DIR="${HOME}/.hermes/scripts/secmon"
    mkdir -p "${HERMES_SCRIPTS_DIR}"
    cp "${SOURCE_DIR}/scripts/tick.py" "${HERMES_SCRIPTS_DIR}/tick.py"
    cp "${SOURCE_DIR}/scripts/audit.py" "${HERMES_SCRIPTS_DIR}/audit.py"
    cp "${SOURCE_DIR}/scripts/daily.py" "${HERMES_SCRIPTS_DIR}/daily.py"
    chmod +x "${HERMES_SCRIPTS_DIR}/tick.py" \
      "${HERMES_SCRIPTS_DIR}/audit.py" \
      "${HERMES_SCRIPTS_DIR}/daily.py"

    # Deploy sync-cron helper
    cp "${SOURCE_DIR}/scripts/sync-cron.sh" "${HERMES_SCRIPTS_DIR}/sync-cron.sh"
    chmod +x "${HERMES_SCRIPTS_DIR}/sync-cron.sh"

    echo "==> Deploying bundled skills to ~/.hermes/skills/devops/"
    HERMES_SKILLS_DIR="${HOME}/.hermes/skills/devops"
    mkdir -p "${HERMES_SKILLS_DIR}"
    for skill in hermes-secmon secmon-maintenance secmon-audit-output-tuning; do
      if [[ -d "${SOURCE_DIR}/skills/${skill}" ]]; then
        rm -rf "${HERMES_SKILLS_DIR}/${skill}"
        cp -r "${SOURCE_DIR}/skills/${skill}" "${HERMES_SKILLS_DIR}/${skill}"
        echo "    ${skill}: deployed"
      fi
    done

    # Deploy sync-skills helper
    HERMES_SYNC_SCRIPT="${HOME}/.hermes/scripts/secmon/sync-skills.sh"
    cp "${SOURCE_DIR}/scripts/sync-skills.sh" "${HERMES_SYNC_SCRIPT}"
    chmod +x "${HERMES_SYNC_SCRIPT}"
    echo "    sync-skills.sh: deployed"

    register_cron_job() {
      local name="$1"
      local schedule="$2"
      local script_rel="$3"
      if hermes cron list 2>/dev/null | grep -q "${name}"; then
        echo "    ${name}: already registered"
        return 0
      fi
      hermes cron add "${schedule}" \
        --no-agent \
        --script "${script_rel}" \
        --name "${name}" \
        "${DELIVER_ARGS[@]}" 2>/dev/null || {
        echo "    Warning: failed to register ${name} (configure hermes.deliver_target?)" >&2
      }
    }

    register_cron_job "secmon-tick" "*/15 * * * *" "secmon/tick.py"
    register_cron_job "secmon-audit" "0 */6 * * *" "secmon/audit.py"
    register_cron_job "secmon-daily" "0 8 * * *" "secmon/daily.py"
    register_cron_job "secmon-skills-sync" "0 */6 * * *" "secmon/sync-skills.sh"
  fi
else
  echo "==> Hermes CLI not found — skipping plugin enable and cron registration"
  echo "    Install Hermes Agent, then run:"
  echo "      hermes plugins enable secmon"
  echo "    See cron/jobs.yaml for job definitions."
fi

echo "==> Verifying installation"
"${CLI_PATH}" --status || true

cat <<EOF

Secmon installed successfully (Hermes Agent plugin).

  Source (symlink): ${SOURCE_DIR} -> $(readlink -f "${SOURCE_DIR}")
  CLI:              ${CLI_PATH} -> $(readlink -f "${CLI_PATH}")
  Config:           ${CONFIG_FILE}
  State:            ${DATA_DIR}/state.json
  BPF audit rules:  ${BPF_RULES_DST} (if auditd installed)
  Logs:             ${LOG_FILE}
  Plugin:           secmon (enable with: hermes plugins enable secmon)

Next steps:
  1. Set whitelist.own_ip in ${CONFIG_FILE}
  2. Set hermes.deliver_target (e.g. telegram, discord, slack)
  3. Ensure Hermes gateway is running: hermes gateway start
  4. Run: ${CLI_PATH} --record   (repeat over 24h+ for baselines)
  5. Review: ${LOG_FILE}
  6. Optional: apt install auditd && systemctl enable --now auditd  (BPF syscall bridge)
  7. After verifying expected BPF: ${CLI_PATH} --bpf-baseline promote --key <stable_key>

To uninstall: sudo ${SOURCE_DIR}/scripts/uninstall.sh
EOF
