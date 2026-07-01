# Secmon — Hermes Agent Security Plugin

Production-grade security monitoring for servers, delivered as a **Hermes Agent plugin**. Secures the server while the Hermes agent is deployed there — combining statistical anomaly detection, realtime threat checks, multi-layer forensic audits, and automated botnet /24 blocking.

Designed to run as root on a single VPS. Silent when normal — output appears only when findings are detected (except `--status`, `--daily`, and `--audit`). Notifications are delivered through the **Hermes Gateway**; scheduling uses **Hermes Cron** no-agent jobs (no OS crontab required).

## Features

- **Hermes plugin integration** — seven LLM-callable tools, `/secmon` and `/secmon_remediate` slash commands, and `pre_llm_call` security context injection
- **Hermes Gateway notifications** — cron jobs capture script stdout and deliver to Telegram, Discord, Slack, and other configured platforms
- **Hermes Cron scheduling** — no-agent watchdog jobs for tick (15 min), audit (6 h), and daily digest (08:00 UTC)
- **11 metrics** — SSH failures, attacker IPs/subnets, fail2ban bans, botnet rules, kernel errors, listening ports, and more
- **9 realtime threat checks** — self-protection, brute-force bursts, new fail2ban bans, port changes, unauthorized SSH sessions, suspicious/C2 outbound connections, etc.
- **Audit-to-alert bridge** — CRITICAL/HIGH deep-audit findings dispatched through the same dedup/log/stdout pipeline
- **Advanced compromise detection** — process hollowing, persistence baseline diff, process lineage, secret exposure, eBPF/kernel tamper
- **Two-gate anomaly detection** — sigma threshold + minimum absolute delta with rolling baselines (Bessel's correction)
- **8+ audit layers** — file integrity, network, process, auth, logs, threat intel, compliance, trends
- **11 extended checks (NC-1–NC-11)** — Docker privilege escalation, DNS integrity, eBPF, supply chain, log gaps, and more
- **Botnet /24 blocking** — automatic iptables BOTNET chain with whitelist enforcement
- **Structured JSON-line logging** — alert deduplication with local log retention

## Requirements

| Requirement | Notes |
|-------------|-------|
| **OS** | Debian 12 (Bookworm) or compatible |
| **Python** | 3.11+ |
| **Hermes Agent** | Gateway running for cron delivery (`hermes gateway start`) |
| **Privileges** | root (for iptables, journalctl, /proc inspection) |
| **iptables** | Required for botnet blocking and firewall audits |
| **fail2ban** | Recommended; optional but improves SSH defense metrics |
| **netfilter-persistent** | Recommended for persisting iptables rules across reboots |

Optional tools (graceful degradation if missing):

- `bpftool` — eBPF integrity checks (NC-9)
- `debsums` — supply chain verification (NC-10)
- `docker` — container escape detection (NC-1)

## Installation

Secmon uses **symlink-based deployment**: the source checkout stays where you cloned it; stable paths (`/opt/secmon`, `/usr/local/bin/secmon`) point back to that checkout. No code is copied during install.

### Option A: Hermes plugins install (recommended)

```bash
hermes plugins install <owner>/security-audit --enable
sudo /opt/secmon/scripts/install.sh
```

### Option B: Manual install from checkout

On the target VPS as root, from your clone directory:

```bash
sudo ./scripts/install.sh
```

Options:

```bash
sudo ./scripts/install.sh --repo /path/to/security-audit --source /opt/secmon --skip-hermes-cron
```

The installer will:

1. Create `/opt/secmon` → symlink to your checkout
2. Create a venv at `/opt/secmon/venv` and `pip install -e` the package (registers the Hermes plugin entry point)
3. Symlink `/usr/local/bin/secmon` → venv entry point
4. Create `/etc/secmon`, `/var/lib/secmon`, log files with secure permissions
5. Run `hermes plugins enable secmon` (when Hermes CLI is available)
6. Register three Hermes Cron no-agent jobs (tick, audit, daily)

### Manual installation

If you prefer not to use the script:

#### 1. Install system packages

```bash
apt update
apt install -y python3 python3-pip python3-venv \
  iptables fail2ban netfilter-persistent

# Optional
apt install -y bpftool debsums
```

#### 2. Link the checkout (do not copy)

```bash
ln -s /path/to/security-audit /opt/secmon
cd /opt/secmon
```

#### 3. Create a virtual environment

```bash
python3 -m venv /opt/secmon/venv
source /opt/secmon/venv/bin/activate
pip install --upgrade pip
pip install -e .
```

Symlink the CLI:

```bash
ln -sf /opt/secmon/venv/bin/secmon /usr/local/bin/secmon
```

#### 4. Create data and log directories

```bash
mkdir -p /var/lib/secmon/snapshots
mkdir -p /etc/secmon
touch /var/log/security-monitor.log
touch /var/log/secmon-botnet.log
chmod 700 /var/lib/secmon
```

#### 5. Configure the monitor

```bash
cp config.yaml.example /etc/secmon/config.yaml
chmod 600 /etc/secmon/config.yaml
```

Edit `/etc/secmon/config.yaml` — set `whitelist.own_ip` and `hermes.deliver_target`.

#### 6. Enable the Hermes plugin

```bash
hermes plugins enable secmon
hermes gateway start   # or: hermes gateway install && hermes gateway start
```

#### 7. Register Hermes cron jobs

See [`cron/jobs.yaml`](cron/jobs.yaml) for job definitions. Example:

```bash
DELIVER=telegram   # or discord, slack, etc.

hermes cron add "*/15 * * * *" --no-agent \
  --script secmon/tick.sh --name secmon-tick --deliver "${DELIVER}"

hermes cron add "0 */6 * * *" --no-agent \
  --script secmon/audit.sh --name secmon-audit --deliver "${DELIVER}"

hermes cron add "0 8 * * *" --no-agent \
  --script secmon/daily.sh --name secmon-daily --deliver "${DELIVER}"
```

Hermes Cron no-agent mode runs the script on schedule and delivers stdout verbatim via the Gateway. Empty stdout on a clean tick = silent (no notification).

#### 8. Verify

```bash
secmon --status
hermes cron list
```

Record an initial baseline sample:

```bash
secmon --record
```

## Hermes plugin tools

When enabled (`hermes plugins enable secmon`), the agent can call:

| Tool | Description |
|------|-------------|
| `secmon_status` | Show baselines, state, and current metrics |
| `secmon_check` | Run realtime threat checks + anomaly detection |
| `secmon_audit` | Full multi-layer forensic audit (JSON) |
| `secmon_record` | Collect metrics and append baseline sample |
| `secmon_daily` | Human-readable daily security digest |
| `secmon_detect_botnet` | Botnet /24 analysis and iptables blocking |
| `secmon_remediate` | Apply safe remediation actions (e.g. fix file permissions) |

Slash commands:

```text
/secmon status
/secmon check
/secmon audit
/secmon_remediate self_protection_fix_permissions
```

A `pre_llm_call` hook injects a short security context summary (last audit score, open findings, baseline status) into each agent turn.

## Gateway notifications

Notifications are **not** sent via webhooks. Instead:

1. Hermes Cron runs a no-agent script (`secmon/tick.sh`, `secmon/audit.sh`, `secmon/daily.sh` under `~/.hermes/scripts/`)
2. The script invokes `secmon` and prints structured output to stdout
3. The Hermes Gateway delivers stdout to the configured platform

Every non-silent delivery follows this structure:

```text
=== secmon [tick|audit|daily] — YYYY-MM-DD HH:MM UTC ===

[SEVERITY] source: message  →  reply /secmon audit
...

--- What to do next ---
1) Context-appropriate remediation steps
2) Verification commands

CTA: /secmon audit   (or /secmon_remediate self_protection_fix_permissions, etc.)
```

- **Silent when normal:** empty stdout on a clean tick = no notification.
- **Actionable:** each alert line includes a remediation hint; wrappers append a `What to do next` section and a single CTA command.

Configure the delivery target in `/etc/secmon/config.yaml`:

```yaml
hermes:
  deliver_target: "telegram"   # telegram, discord, slack, signal, etc.
  min_severity: HIGH
```

Or set `SECMON_DELIVER_TARGET` via environment (mapped to `hermes.deliver_target`).

For one-off alerts from a running script (deploy hook, CI step):

```bash
secmon --check | hermes send --deliver telegram
```

## Uninstallation

```bash
sudo /opt/secmon/scripts/uninstall.sh
```

Options:

| Flag | Effect |
|------|--------|
| `--purge` | Remove `/etc/secmon`, `/var/lib/secmon`, and log files |
| `--remove-botnet` | Flush iptables BOTNET chain |
| `--keep-source` | Leave `/opt/secmon` symlink in place |

The uninstaller removes Hermes cron jobs (`secmon-tick`, `secmon-audit`, `secmon-daily`) and disables the plugin. The source checkout is **never deleted** unless you remove it yourself.

## Usage

Exactly one mode per CLI invocation:

| Mode | Command | Description |
|------|---------|-------------|
| Tick | `secmon --tick` | Primary cron entry: metrics, checks, anomalies, botnet, daily digest |
| Check | `secmon --check` | Threat checks + anomaly detection only |
| Record | `secmon --record` | Collect metrics and append baseline sample |
| Daily | `secmon --daily` | Human-readable daily security digest |
| Botnet | `secmon --detect-botnet` | Standalone /24 subnet analysis and blocking |
| Status | `secmon --status` | Show baselines, state, and current metrics |
| Audit | `secmon --audit` | Full multi-layer forensic audit (JSON to stdout) |

Global options:

```bash
secmon --config /path/to/config.yaml --status
secmon -v --check    # verbose logging
```

## Configuration reference

Configuration is loaded in priority order:

1. Environment variables (`SECMON_*`)
2. YAML config file (`/etc/secmon/config.yaml` or `SECMON_CONFIG_PATH`)
3. Built-in defaults

Per-metric threshold overrides via environment:

```bash
export SECMON_OVERRIDE_SSH_FAILED_24H_MIN_DELTA=8000
export SECMON_OVERRIDE_SSH_FAILED_24H_SIGMA_ABOVE=3.0
export SECMON_ANOMALY_COOLDOWN_MINUTES=30
```

See [`config.yaml.example`](config.yaml.example) for all options.

## Project layout

```
security-audit/
├── plugin.yaml                 # Hermes plugin manifest (repo root)
├── pyproject.toml              # Package + hermes_agent.plugins entry point
├── config.yaml.example         # Example configuration
├── cron/
│   └── jobs.yaml               # Hermes Cron job definitions
├── scripts/
│   ├── install.sh              # Symlink installer + Hermes registration
│   ├── uninstall.sh            # Reversible uninstall
│   ├── tick.sh                 # Hermes cron wrapper (15 min)
│   ├── audit.sh                # Hermes cron wrapper (6 h)
│   └── daily.sh                # Hermes cron wrapper (daily)
├── SECURITY-AUDIT-SPEC.MD        # Full build specification
├── src/
│   ├── secmon/                 # Core monitoring engine
│   │   ├── checks/             # Realtime threat checks
│   │   ├── audit/              # 8 forensic audit layers + NC-1–NC-11
│   │   └── modes/              # CLI mode handlers
│   └── secmon_plugin/          # Hermes plugin (register, tools, schemas)
└── tests/                      # Test suite (95%+ coverage)
```

## Development

Run the test suite:

```bash
pip install -r requirements.txt
pip install -e .
pytest
```

Run with coverage report:

```bash
pytest --cov=secmon --cov-report=term-missing
```

For local Hermes plugin testing, enable project plugins:

```bash
export HERMES_ENABLE_PROJECT_PLUGINS=true
hermes plugins enable secmon
```

## Post-installation checklist

1. Run `sudo ./scripts/install.sh` (or `hermes plugins install … --enable`)
2. Set `whitelist.own_ip` and `known_ssh_ips` in config
3. Set `hermes.deliver_target` to your preferred Gateway platform
4. Ensure Hermes gateway is running: `hermes gateway status`
5. Run `secmon --status` to confirm state initializes
6. Run `secmon --record` several times over 24+ hours to build baselines
7. Verify Hermes cron jobs: `hermes cron list`
8. Review `/var/log/security-monitor.log` for false positives; tune thresholds
9. Ensure fail2ban sshd jail is active: `fail2ban-client status sshd`
10. Confirm iptables BOTNET chain exists after first botnet run: `iptables -L BOTNET -n`

## Logs and state

| Path | Purpose |
|------|---------|
| `/var/lib/secmon/state.json` | Canonical state (baselines, dedup, audit baselines) |
| `/var/lib/secmon/snapshots/` | Daily state snapshots (7-day retention) |
| `/var/log/security-monitor.log` | Structured JSON-line event log |
| `/var/log/secmon-botnet.log` | Botnet /24 block actions |

To restore state from a snapshot, copy a snapshot file back to `state.json`.

## License

See repository license file if present. Specification: [`SECURITY-AUDIT-SPEC.MD`](SECURITY-AUDIT-SPEC.MD).
