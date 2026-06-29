# secmon — Security Audit & Monitoring

Production-grade security monitoring for **Debian 12 (Bookworm) cloud VPS** servers. Combines statistical anomaly detection, realtime threat checks, multi-layer forensic audits, and automated botnet /24 blocking.

Designed to run as root on a single VPS. Silent when normal — output appears only when findings are detected (except `--status`, `--daily`, and `--audit`).

## Features

- **11 metrics** — SSH failures, attacker IPs/subnets, fail2ban bans, botnet rules, kernel errors, listening ports, and more
- **8 realtime threat checks** — brute-force bursts, new fail2ban bans, port changes, unauthorized SSH sessions, suspicious outbound connections, etc.
- **Two-gate anomaly detection** — sigma threshold + minimum absolute delta with rolling baselines (Bessel's correction)
- **8+ audit layers** — file integrity, network, process, auth, logs, threat intel, compliance, trends
- **11 extended checks (NC-1–NC-11)** — Docker privilege escalation, DNS integrity, eBPF, supply chain, log gaps, and more
- **Botnet /24 blocking** — automatic iptables BOTNET chain with whitelist enforcement
- **Structured JSON-line logging** — alert deduplication, optional webhook via `curl`

## Requirements

| Requirement | Notes |
|-------------|-------|
| **OS** | Debian 12 (Bookworm) or compatible |
| **Python** | 3.11+ |
| **Privileges** | root (for iptables, journalctl, /proc inspection) |
| **iptables** | Required for botnet blocking and firewall audits |
| **fail2ban** | Recommended; optional but improves SSH defense metrics |
| **netfilter-persistent** | Recommended for persisting iptables rules across reboots |

Optional tools (graceful degradation if missing):

- `bpftool` — eBPF integrity checks (NC-9)
- `debsums` — supply chain verification (NC-10)
- `docker` — container escape detection (NC-1)

## Installation

### 1. Install system packages

On the target VPS (as root):

```bash
apt update
apt install -y python3 python3-pip python3-venv \
  iptables fail2ban netfilter-persistent

# Optional
apt install -y bpftool debsums
```

### 2. Clone or copy the project

```bash
git clone <your-repo-url> /opt/secmon
cd /opt/secmon
```

Or copy the project directory to `/opt/secmon` (or any path you prefer).

### 3. Create a virtual environment (recommended)

```bash
python3 -m venv /opt/secmon/venv
source /opt/secmon/venv/bin/activate
pip install --upgrade pip
pip install -e .
```

This installs the `secmon` CLI and runtime dependency (`PyYAML`).

To install development/test dependencies as well:

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Create data and log directories

```bash
mkdir -p /var/lib/secmon/snapshots
mkdir -p /etc/secmon
touch /var/log/security-monitor.log
touch /var/log/secmon-botnet.log
chmod 700 /var/lib/secmon
```

### 5. Configure the monitor

Copy the example configuration and edit it for your server:

```bash
cp config.yaml.example /etc/secmon/config.yaml
chmod 600 /etc/secmon/config.yaml
```

**Required:** set your server's public IP:

```yaml
whitelist:
  own_ip: "203.0.113.1"   # your VPS public IP
  known_ssh_ips:
    - "203.0.113.1"
```

Also configure expected DNS nameservers if you use NC-3:

```yaml
dns:
  expected_nameservers:
    - "8.8.8.8"
    - "8.8.4.4"
```

Alternatively, use environment variables (highest priority):

```bash
export SECMON_OWN_IP=203.0.113.1
export SECMON_DATA_DIR=/var/lib/secmon
export SECMON_CONFIG_PATH=/etc/secmon/config.yaml
```

The monitor runs without a config file using built-in defaults, but `own_ip` should be set on any production host.

### 6. Verify installation

```bash
secmon --status
```

You should see state version 3, empty baselines (until you record samples), and current metric values.

Run a one-off check (silent if nothing is wrong):

```bash
secmon --check
```

Record an initial baseline sample:

```bash
secmon --record
```

### 7. Schedule cron jobs

Add to root's crontab (`crontab -e`):

```cron
# Primary monitor — threat checks, anomalies, botnet, daily digest
*/15 * * * * /opt/secmon/venv/bin/secmon --tick

# Deep audit (JSON output for LLM summarization or log ingestion)
0 */6 * * * /opt/secmon/venv/bin/secmon --audit >> /var/log/secmon-audit.json 2>&1
```

If you installed without a venv and `secmon` is on `PATH`:

```cron
*/15 * * * * secmon --tick
```

### 8. (Optional) Enable webhook alerts

In `/etc/secmon/config.yaml`:

```yaml
alerting:
  webhook_url: "https://your-endpoint.example/alerts"
  webhook_min_level: CRITICAL
```

Alerts are sent via `curl` POST with a JSON payload.

## Uninstallation

To fully remove secmon from a server (as root):

### 1. Stop scheduled jobs

Remove secmon lines from root's crontab:

```bash
crontab -e
```

Delete any lines containing `secmon --tick`, `secmon --audit`, or similar.

### 2. Uninstall the Python package

If you used a virtual environment:

```bash
source /opt/secmon/venv/bin/activate
pip uninstall -y secmon
deactivate
```

If you installed globally with `pip install -e .`:

```bash
pip uninstall -y secmon
```

### 3. Remove iptables BOTNET rules

secmon adds a custom `BOTNET` chain and a jump rule in `INPUT`. Remove them before deleting the project:

```bash
# List blocked subnets (optional — note any you may want to keep blocking manually)
iptables -L BOTNET -n

# Remove the jump from INPUT to BOTNET (repeat until no match)
while iptables -C INPUT -j BOTNET 2>/dev/null; do
  iptables -D INPUT -j BOTNET
done

# Flush and delete the BOTNET chain
iptables -F BOTNET
iptables -X BOTNET

# Persist the cleaned ruleset
netfilter-persistent save
```

If you only want to clear blocks but keep the chain for a future reinstall:

```bash
iptables -F BOTNET
netfilter-persistent save
```

### 4. Remove application files (optional)

```bash
rm -rf /opt/secmon          # project directory and venv
rm -rf /etc/secmon          # configuration
rm -rf /var/lib/secmon      # state, baselines, snapshots
rm -f /var/log/security-monitor.log
rm -f /var/log/secmon-botnet.log
rm -f /var/log/secmon-audit.json
```

Keep `/var/lib/secmon` and the log files if you plan to reinstall and want to preserve baselines or history.

### 5. System packages (optional)

secmon does not install `fail2ban`, `iptables`, or other system packages. Remove them only if nothing else on the host needs them:

```bash
apt remove -y fail2ban netfilter-persistent
# Do not remove iptables unless you manage firewall another way
```

## Usage

Exactly one mode per invocation:

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
├── pyproject.toml          # Package metadata and pytest/coverage config
├── requirements.txt        # Runtime + dev dependencies
├── config.yaml.example     # Example configuration
├── SECURITY-AUDIT-SPEC.MD  # Full build specification
├── src/secmon/             # Application source
│   ├── checks/             # 8 realtime threat checks
│   ├── audit/              # 8 forensic audit layers + NC-1–NC-11
│   └── modes/              # CLI mode handlers
└── tests/                  # Test suite (95%+ coverage)
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

## Post-installation checklist

1. Set `whitelist.own_ip` and `known_ssh_ips` in config
2. Run `secmon --status` to confirm state initializes
3. Run `secmon --record` several times over 24+ hours to build baselines
4. Enable the 15-minute `--tick` cron job
5. Review `/var/log/security-monitor.log` for false positives; tune thresholds in config
6. Ensure fail2ban sshd jail is active: `fail2ban-client status sshd`
7. Confirm iptables BOTNET chain exists after first botnet run: `iptables -L BOTNET -n`
8. Persist iptables rules: `netfilter-persistent save`

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
