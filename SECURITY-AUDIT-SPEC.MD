# Security Audit & Monitoring System — Build Specification

**Version:** 1.0
**Target Platform:** Debian 12 (Bookworm) cloud VPS
**Purpose:** Production-grade, multi-layer security monitoring, threat detection, statistical anomaly detection, and automated hardening for single-server cloud deployments.
**Audience:** Any AI agent or developer implementing from scratch. Language-agnostic. No references to any existing implementation.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [State & Persistence](#3-state--persistence)
4. [Configuration System](#4-configuration-system)
5. [Metric Collection Framework](#5-metric-collection-framework)
6. [Statistical Anomaly Detection](#6-statistical-anomaly-detection)
7. [Realtime Threat Checks](#7-realtime-threat-checks)
8. [Full Audit Layers](#8-full-audit-layers)
9. [Botnet Detection & Subnet Blocking](#9-botnet-detection--subnet-blocking)
10. [Automated Hardening Playbook](#10-automated-hardening-playbook)
11. [Alerting & Output Pipeline](#11-alerting--output-pipeline)
12. [Scheduling & Cron Architecture](#12-scheduling--cron-architecture)
13. [Proposed New Checks](#13-proposed-new-checks)
14. [Testing Requirements](#14-testing-requirements)
15. [Deployment & Rollback](#15-deployment--rollback)
16. [Security Review & Hardening of the Monitor Itself](#16-security-review--hardening-of-the-monitor-itself)
17. [Edge Cases & Failure Modes](#17-edge-cases--failure-modes)

---

## 1. System Overview

### 1.1 What it does

This system provides continuous security monitoring for a single cloud VPS running Debian 12. It combines:

- **Scheduled deep audits** covering 8+ forensic layers (file integrity, network, process, auth, logs, threat intel, compliance, trends)
- **Statistical anomaly detection** using rolling baselines — catches unusual patterns without hardcoded thresholds
- **Realtime threat checks** every 15 minutes for active attacks (brute-force bursts, new fail2ban bans, unauthorized sessions, etc.)
- **Botnet detection** with automatic /24 subnet blocking at the iptables level
- **Automated hardening** (fail2ban, sysctl, iptables, SSH config, sudo policy)

### 1.2 Design Principles

1. **Silent when normal.** Zero output when nothing is wrong. The system only produces output when findings or anomalies are detected.
2. **Two-tier scheduling.** High-frequency checks (≤ 15 min) use direct script execution (no LLM overhead). Deep audits and summarization use LLM-driven analysis every 6+ hours.
3. **Atomic state.** Every state mutation writes to a temporary file and renames atomically. Corrupt state files are replaced with safe defaults.
4. **Per-component isolation.** Every metric collector and threat check is wrapped in its own try/catch block. A failure in one component never cascades.
5. **Dedup everything.** Repeated signals are suppressed. The same anomaly firing 3+ times with the same value is a stale baseline, not a new alert.
6. **Configurable, not hardcoded.** All thresholds, paths, and tuning parameters live in a configuration layer with sensible defaults.

### 1.3 Capability Matrix

| Capability | Frequency | Delivery | Mode |
|---|---|---|---|
| Statistical anomaly detection | Every 15 min | Log file only (unless anomaly found) | Direct execution |
| Realtime threat checks | Every 15 min | Log file only (unless threat found) | Direct execution |
| Metric baseline recording | Every 6 hours | Log file only | Direct execution |
| Botnet detection & blocking | Every 6 hours | Log file (new blocks reported) | Direct execution |
| Daily security digest | 08:00 UTC daily | Human-readable report | Direct execution |
| Deep 8+ layer audit | Every 6 hours | Natural language summary | LLM-driven |
| Status query | On-demand | Immediate report | Direct execution |

---

## 2. Architecture

### 2.1 High-Level Data Flow

```
┌──────────────────────────────────────────────────────────────┐
│                     ENTRY POINT                              │
│              (arg dispatch: mode selection)                  │
└──────┬───────────────────────────────────────────────────────┘
       │
       ├── tick mode (primary cron entry, every 15 min)
       │   ├── 1. Collect metrics (with cache)
       │   ├── 2. Run all realtime threat checks
       │   ├── 3. Detect statistical anomalies
       │   ├── 4. Record baseline (every 6h, if due)
       │   ├── 5. Run botnet detection (every 6h, if due)
       │   ├── 6. Produce daily report (08:00 UTC, if new day)
       │   └── 7. Dispatch findings through alert pipeline
       │
       ├── check mode (standalone: threat checks + anomalies)
       ├── record mode (standalone: metric collection + baseline append)
       ├── daily mode (standalone: daily digest)
       ├── detect-botnet mode (standalone: subnet analysis + blocking)
       ├── status mode (read-only: show baselines, state, health)
       └── audit mode (standalone: full multi-layer deep audit)

       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│                    ALERT PIPELINE                             │
│                                                              │
│   Sources:  threat checks / anomaly detection / botnet       │
│   Filters:  dedup by key + time window                       │
│   Outputs:  → structured log file (always)                   │
│             → stdout (only if findings exist)                │
│             → webhook (optional, severity-gated)             │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Module Boundaries

The system is divided into these concerns (language-agnostic names):

| Module | Responsibility | Dependencies |
|---|---|---|
| **Entry Point** | Parse CLI args, dispatch to mode handler | All modules |
| **Configuration** | Load settings from file + env vars, provide defaults | None |
| **State Manager** | Read/write persistent state, atomic writes, snapshots, schema migration | File system |
| **Metric Collectors** | Gather raw metrics from the operating system (journalctl, ss, iptables, fail2ban) | Shell commands |
| **Baseline Engine** | Compute rolling statistical baselines (mean, stdev, min, max) from time-series data | State Manager |
| **Anomaly Detector** | Compare current metrics against baselines using sigma + min-delta gates | Baseline Engine, Configuration |
| **Threat Check Registry** | Registry of realtime threat checks, each returning findings or nil | Metric Collectors, State Manager |
| **Deep Audit Engine** | Multi-layer forensic audit (8+ layers), each independent | Shell commands |
| **Botnet Blocker** | Subnet clustering, threshold evaluation, iptables manipulation, whitelist enforcement | Shell commands |
| **Alert Dispatcher** | Deduplicate findings, format output, route to all configured outputs | State Manager, Configuration |
| **Output Presenters** | Format findings for terminal, JSON, daily digest, webhook payload | Alert Dispatcher |

### 2.3 Design Rules

- **No shell interpolation in subprocess calls.** All external command invocations use argument-list form (e.g., `[cmd, arg1, arg2]`), never string interpolation with shell interpretation.
- **Every external command is wrapped in error handling.** Timeouts, missing binaries, and unexpected output are all handled gracefully.
- **State mutations are write-then-rename.** Write to `file.tmp`, then atomic rename to `file`. This prevents partial writes from corrupting state.
- **Pure read operations never mutate state.** Modes like `status` and `check` only read.
- **Baseline recordings explicitly exclude themselves from detection.** The `record` mode collects and stores; the `check` mode only detects.
- **All module-internal constants come from the configuration module.** No magic numbers in logic code.

---

## 3. State & Persistence

### 3.1 State File Schema

A single canonical file stores all persistent data. Schema (language-agnostic):

```
State {
  version: Integer                    // Schema version for migration
  created_at: ISO8601 Timestamp       // Initial creation time
  updated_at: ISO8601 Timestamp       // Last write time

  // Rolling baseline of daily metric samples
  daily_stats: Array<{
    timestamp: ISO8601,
    ssh_failed_24h: Integer,
    ssh_invalid_user_24h: Integer,
    unique_attacker_ips: Integer,
    unique_attacker_subnets: Integer,
    f2b_banned_count: Integer,
    botnet_chain_rules: Integer,
    martian_packets_24h: Integer,
    new_blocked_subnets_24h: Integer,
    kernel_errors_24h: Integer,
    listening_ports_count: Integer,
    established_conns: Integer
  }>

  // Computed statistical baselines per metric
  baselines: Map<String, {
    mean: Float,
    stdev: Float,              // Sample standard deviation (n-1)
    min: Integer,
    max: Integer,
    sample_size: Integer,
    calibrated_at: ISO8601
  }>

  // Audit-specific state (file hashes, SUID baseline, known ports)
  audit_baseline: {
    file_hashes: Map<FilePath, HashHex>,
    suid_cache: Array<FilePath>,
    known_ports: Map<PortNumber, ServiceName>
  }

  // Cool-down tracking for anomaly suppression
  last_flagged_anomalies: Map<String, {
    time: ISO8601,
    value: Integer
  }>

  // History of recent anomalies for trend analysis
  last_anomalies: Array<{
    metric: String,
    direction: String,
    severity: String,
    timestamp: ISO8601,
    current_value: Integer,
    mean: Float,
    stdev: Float,
    sigma: Float
  }>

  last_anomaly_check: ISO8601

  // Realtime monitor state (dedup tracking)
  monitor_state: {
    last_f2b_snapshot: String,       // Previously known banned IP list
    known_ports_output: String,      // Previous "ss -tlnp" output
    last_record: ISO8601,           // Last baseline recording
    last_daily: ISO8601,            // Last daily digest
    last_botnet_check: ISO8601      // Last botnet detection run
  }

  // Schema migration audit trail
  migration_history: Array<{
    from_version: Integer,
    to_version: Integer,
    at: ISO8601
  }>

  // Metric value cache (TTL-based, for performance)
  metric_cache: {
    timestamp: ISO8601,
    values: Map<String, Integer>
  }
}
```

### 3.2 Atomic Write Protocol

```
function save_state(data):
    tmp_path = state_file_path + ".tmp"
    write_json(tmp_path, data)
    atomic_rename(tmp_path, state_file_path)
    // Also write daily snapshot if date changed
    snapshot_path = snapshot_dir + "/state." + today_date() + ".json"
    atomic_write(snapshot_path, data)
    prune_snapshots(keep=7)  // Keep 7 most recent daily snapshots
```

### 3.3 Corruption Recovery

```
function load_state():
    if state_file not found:
        return default_state()

    try:
        data = read_json(state_file)
    catch ParseError:
        log_error("state file corrupt, using defaults")
        backup_corrupt_file()
        return default_state()

    if data.version < current_version:
        data = run_migrations(data)

    return data
```

### 3.4 Snapshot Rotation

Daily snapshots are written to a dedicated subdirectory, keeping the 7 most recent. Rollback procedure: copy a snapshot back to the main state file.

---

## 4. Configuration System

### 4.1 Configuration Sources (Priority Order)

1. **Environment variables** (prefixed with `SECMON_`) — highest priority, for runtime overrides
2. **Configuration file** (YAML format) — persistent settings
3. **Built-in defaults** — fallback values

The system must run without any configuration file present, using only defaults.

### 4.2 Configurable Parameters

| Category | Parameter | Default | Description |
|---|---|---|---|
| **General** | `data_dir` | Platform-dependent | Working directory for state, snapshots, logs |
| **General** | `log_file` | `/var/log/security-monitor.log` | Structured event log |
| **General** | `snapshot_retention_days` | `7` | Days of state snapshots to retain |
| **Whitelist** | `own_ip` | Required — no default | Server's own public IP (excluded from alerts) |
| **Whitelist** | `known_ssh_ips` | `[own_ip]` | IPs that are allowed SSH access |
| **Whitelist** | `network_prefixes` | RFC 1918 ranges | IP prefixes never blocked (private + loopback) |
| **Anomaly** | `baseline_min_samples` | `4` | Minimum samples before anomaly detection activates |
| **Anomaly** | `max_baseline_days` | `30` | Maximum age of baseline samples before expiry |
| **Anomaly** | `dedup_slot_hours` | `6` | Minimum gap between baseline recordings |
| **Anomaly** | `cache_ttl_seconds` | `300` | How long collected metrics are cached (5 min) |
| **Anomaly** | `cooldown_minutes` | `60` | Minimum interval before re-alerting same anomaly |
| **Realtime** | `ssh_brute_force_threshold` | `10` | Failed auth attempts in 5 min to trigger alert |
| **Realtime** | `invalid_user_threshold` | `5` | Invalid user attempts in 5 min to trigger alert |
| **Realtime** | `kernel_error_threshold` | `3` | Kernel errors in 24h to trigger alert |
| **Botnet** | `lookback_hours` | `24` | Analysis window for botnet clustering |
| **Botnet** | `min_ips_per_subnet` | `3` | Minimum unique IPs in a /24 to consider it a botnet |
| **Botnet** | `min_hits_per_subnet` | `100` | Minimum total hits from a /24 to block |
| **Botnet** | `solo_min_hits` | `500` | Single IP hit count that triggers /24 block |
| **Alerting** | `webhook_url` | `""` (disabled) | Optional HTTP endpoint for critical alerts |
| **Alerting** | `webhook_min_level` | `CRITICAL` | Minimum severity to dispatch via webhook |
| **Suspicious Ports** | `ranges` | IRC: 6660-6700 | Port ranges to flag on outbound connections |
| **Suspicious Ports** | `specific` | 4444, 5555, 8080, 9090 | Specific C2/proxy ports to flag |
| **Metrics** | `overrides` | `{}` | Per-metric threshold overrides |

### 4.3 Environment Variable Convention

```
SECMON_OWN_IP=203.0.113.1
SECMON_ANOMALY_COOLDOWN_MINUTES=30
SECMON_OVERRIDE_SSH_FAILED_24H_MIN_DELTA=8000
SECMON_OVERRIDE_SSH_FAILED_24H_SIGMA_ABOVE=3.0
```

Environment variables override the equivalent config file values. Underscores map to nested keys.

---

## 5. Metric Collection Framework

### 5.1 Metric Definitions

| Metric Key | Group | Source | Description |
|---|---|---|---|
| `ssh_failed_24h` | attack | `journalctl` — count "Failed password" | Total failed SSH auth attempts in 24h |
| `ssh_invalid_user_24h` | attack | `journalctl` — count "Invalid user" | Invalid username attempts in 24h |
| `unique_attacker_ips` | attack | `journalctl` — extract + dedup IPs | Unique source IPs attempting auth in 24h |
| `unique_attacker_subnets` | attack | `journalctl` — group IPs by /24 | Unique /24 subnets attempting auth in 24h |
| `f2b_banned_count` | defense | `fail2ban-client status sshd` output | Current number of active fail2ban SSH bans |
| `botnet_chain_rules` | defense | `iptables -L BOTNET -n` output | Number of DROP rules in the BOTNET chain |
| `martian_packets_24h` | system | `journalctl -k` — count "martian" | Martian source packets logged in 24h |
| `new_blocked_subnets_24h` | defense | Botnet log file — count blocks in 24h | Number of /24 subnets newly blocked in 24h |
| `kernel_errors_24h` | system | `journalctl -k --priority=err` | Kernel error messages in 24h |
| `listening_ports_count` | system | `ss -tlnp` — count lines | Number of TCP listening ports |
| `established_conns` | system | `ss -tnp state established` — exclude loopback | Number of established TCP connections |

### 5.2 Collection Design

- **Single journalctl pass for SSH metrics.** One call to `journalctl --since '24 hours ago'` provides all four auth-related metrics. Parse once, extract all counts.
- **Per-metric error isolation.** Each collector is wrapped in its own try/catch. If `fail2ban-client` fails because fail2ban isn't installed, `f2b_banned_count` returns 0 rather than crashing the entire collection.
- **Return all keys, even on failure.** The collector always returns a map with all metric keys present. Failures produce 0 values, not missing keys.
- **No shell string interpolation.** All subprocess invocations use argument arrays.

### 5.3 Metric Cache

- **TTL: 300 seconds (5 minutes).** After collection, metrics are cached in memory.
- **Cache scope:** Per-process. Not persisted to disk between runs.
- **Invalidation:** Calling `record` mode invalidates the cache (forces fresh collection). `check` mode reuses cached metrics if still fresh.
- **Purpose:** Avoids running 3+ journalctl calls, 2 ss calls, 1 iptables call, and 1 fail2ban call every 15 minutes. Real collection takes 2-5 seconds on a typical VPS; the cache reduces this to near-zero for subsequent checks within the TTL window.

### 5.4 Collection Procedure

```
function collect_metrics():
    if cache is fresh:
        return cache.values

    // Single journalctl pass for SSH metrics
    auth_lines = run(["journalctl", "--since", "24 hours ago"])
    ssh_failed = count_lines_matching(auth_lines, "Failed password")
    ssh_invalid = count_lines_matching(auth_lines, "Invalid user")
    attacker_ips = extract_and_dedup_ips(auth_lines)
    attacker_subnets = group_by_24(attacker_ips)

    // Defense metrics
    f2b_bans = run(["fail2ban-client", "status", "sshd"])
               | extract_number("Currently banned")

    botnet_rules = run(["iptables", "-L", "BOTNET", "-n"])
                   | count_lines_matching("DROP")

    // System metrics
    kernel_msgs = run(["journalctl", "-k", "--since", "24 hours ago"])
    martians = count_lines_matching(kernel_msgs, "martian")
    kernel_errs = run(["journalctl", "-k", "--since", "24 hours ago", "--priority=err"])
                  | count_lines(exclude_patterns=["regulatory.db"])

    // Network metrics
    listening = run(["ss", "-tlnp"]) | count_non_header_lines
    established = run(["ss", "-tnp", "state", "established"])
                  | count_lines_excluding(["127.0.0.1", "::1"])

    // Botnet block count
    new_blocks = count_lines_in_log_matching(
        botnet_log_path, "BLOCKED", since_hours=24
    )

    cache.set(all_metrics)
    return all_metrics
```

---

## 6. Statistical Anomaly Detection

### 6.1 Algorithm

The system uses rolling-baseline statistical anomaly detection with two independent gates that must both pass to trigger an alert.

#### Gate 1: Sigma Threshold

```
deviation = |current_value - baseline_mean| / baseline_stdev
if deviation > sigma_threshold: gate_1_passes = true
```

#### Gate 2: Minimum Absolute Delta

```
absolute_delta = |current_value - baseline_mean|
if absolute_delta >= min_delta: gate_2_passes = true
```

**Both gates must pass.** This prevents false positives from metrics that naturally have very low variance (tiny absolute changes producing enormous sigma values) and from metrics that are inherently noisy (large sigma but changes are within normal range).

#### When Baseline Sample Size < Minimum

When the baseline has fewer than `baseline_min_samples` entries, anomaly detection is suppressed entirely for that metric. This prevents false positives during the initial data-gathering period.

#### When Standard Deviation is Zero

When σ = 0 (all baseline values identical, or single sample), use pure deviation:
- Above direction: alert if `current > mean` AND `|current - mean| >= min_delta`
- Below direction: alert if `current < mean` AND `|current - mean| >= min_delta`

### 6.2 Per-Metric Thresholds

| Metric | Sigma (Above) | Sigma (Below) | Min Delta | Rationale |
|---|---|---|---|---|
| `ssh_failed_24h` | 2.5σ | 2.0σ | 5,000 | Real daily swing is 1,200–12,000; drops could indicate log tampering |
| `ssh_invalid_user_24h` | 2.5σ | — | 2,000 | Daily swing 900–6,200 |
| `unique_attacker_ips` | 2.5σ | — | 100 | Daily swing 42–274 |
| `unique_attacker_subnets` | 2.5σ | — | 80 | Daily swing 34–247 |
| `f2b_banned_count` | 4.0σ | — | 20 | Bans fluctuate 0–8/day normally; conservative threshold prevents spam |
| `botnet_chain_rules` | 4.0σ | — | 5 | Monotonically grows; only alert on sudden jumps |
| `martian_packets_24h` | 3.0σ | — | 10 | Rare; 1–6/day typical |
| `new_blocked_subnets_24h` | 3.0σ | — | 5 | Occasionally 6 after setup; stabilizes to 0–2 |
| `kernel_errors_24h` | 3.0σ | — | 3 | Usually 0; >3 is concerning |
| `listening_ports_count` | 3.0σ | — | 2 | Constant; any change is suspicious |
| `established_conns` | 4.0σ | — | 8 | Low-count, high natural variance (2–10) |

### 6.3 Sample Variance

Use **sample variance (n-1 denominator)** — Bessel's correction — rather than population variance (n). This provides a more accurate estimate for small sample sizes (< 30 entries), which is the typical operating range.

### 6.4 Severity Classification

| Deviation | Severity |
|---|---|
| > 2.0 × sigma_threshold | CRITICAL |
| > 1.5 × sigma_threshold | HIGH |
| > 1.0 × sigma_threshold | MEDIUM |
| ≤ 1.0 × sigma_threshold | No alert |

### 6.5 Anomaly Cool-Down

To prevent repeated alerts for the same persistent anomaly:

- Track each unique `{metric_key}+{direction}` combination with the timestamp of its last alert.
- If the same metric+direction was flagged within the last 60 minutes (configurable), suppress the alert.
- After the cool-down window expires, re-alert if the anomaly persists.
- **Stale baseline rule:** If the same metric fires 3+ consecutive check cycles with approximately the same value (±10%), the baseline is stale, not the metric anomalous. Log a "stale baseline" warning instead of re-alerting. Auto-suggest recalibration or reseeding.

### 6.6 Baseline Computation

```
function compute_baselines(daily_stats):
    for each metric_key:
        values = [entry[metric_key] for entry in daily_stats]
        if len(values) < baseline_min_samples:
            continue (insufficient data)

        n = len(values)
        mean = sum(values) / n
        squared_diffs = [(v - mean) ** 2 for v in values]
        stdev = sqrt(sum(squared_diffs) / (n - 1))  // Bessel's correction

        baselines[metric_key] = {
            mean, stdev,
            min: min(values),
            max: max(values),
            sample_size: n,
            calibrated_at: now()
        }
```

### 6.7 Baseline Seeding Protocol

Initial baselines must be seeded with **real journalctl data** from the target server, not synthetic data. Procedure:

1. Query `journalctl` per-day for the past 7 days:
   - SSH failures: count "Failed password" per 24h window
   - Invalid users: count "Invalid user"
   - Unique IPs: extract and deduplicate
   - Unique subnets: group by /24

2. For non-journalctl metrics (fail2ban bans, botnet rules, martians, etc.), collect current values as seed.

3. Populate `daily_stats` with exactly one entry per day for 7 days.

**Why real data:** SSH attack volume varies enormously between servers. A server on a popular cloud IP range may see 6,000–12,000 daily attempts; a less-targeted server may see 50. Synthetic data tuned for one scenario will produce constant false positives or missed detections on the other.

### 6.8 Auto-Calibration (Post-Deployment)

After 14+ baseline samples (approximately one week at one sample per 6 hours, or two weeks at one per day):

1. Compute the observed value range per metric (P10 to P90).
2. Compare current `min_delta` to the observed range. If `min_delta` is outside 20-50% of the range, log a suggestion for adjustment.
3. **Never auto-apply.** Suggestions go to the log file. The operator manually reviews and updates the configuration.
4. If no `daily_stats` entry in 72 hours (system was offline), clear baselines and reseed.

---

## 7. Realtime Threat Checks

### 7.1 Check Registry

Each check is an independent function that returns either `nil` (no finding) or a finding object with severity, message, and structured data. Checks run every 15 minutes via the `tick` mode.

### 7.2 Check Definitions

#### 7.2.1 Fail2ban Ban Monitor

**Purpose:** Detect new IPs banned by fail2ban since the last check.
**Severity:** HIGH

**Logic:**
1. Query `fail2ban-client status sshd` for currently banned IP list.
2. Compare against stored snapshot from previous check.
3. New IPs not seen before → alert.
4. IPs from already-blocked /24 subnets → list as informational noise (not alert).
5. Update stored snapshot.

**Dedup:** Per-IP, 24-hour window. Once an IP has been reported as banned, don't re-alert for the same IP within 24h.

#### 7.2.2 SSH Brute-Force Burst Detection

**Purpose:** Detect concentrated brute-force bursts within a 5-minute window.
**Severity:** CRITICAL (novel sources), INFO (already-blocked sources)

**Logic:**
1. Query `journalctl --since '5 minutes ago'` for SSH auth failures.
2. Count failures. If below threshold, return nil.
3. If above threshold, extract source IPs and group by /24 subnet.
4. Subnets already blocked in iptables BOTNET chain → INFO (expected noise).
5. Novel subnets → CRITICAL with /24 breakdown.

**Dedup:** Per-novel-subnet, 1-hour window.

#### 7.2.3 Port Scan Detection

**Purpose:** Detect port scanning activity from kernel/dmesg logs.
**Severity:** MEDIUM

**Logic:**
1. Query journalctl kernel logs for recent martian source entries, blocked connection attempts, or flood indications.
2. Exclude entries where the source IP is the server's own IP.
3. If any external sources found, alert with source IP list.

**Dedup:** Once per check cycle (entire check result, not per IP).

#### 7.2.4 Listening Port Monitor

**Purpose:** Detect unauthorized or unexpected listening ports.
**Severity:** CRITICAL

**Logic:**
1. Run `ss -tlnp` to list all TCP listening ports with process info.
2. Compare against stored snapshot from previous check.
3. Any new port → CRITICAL alert (potential backdoor).
4. Any departed port → CRITICAL alert (service failure or compromise).
5. Update stored snapshot.

**Dedup:** Per-port number, 24-hour window.

#### 7.2.5 Invalid User Enumeration Detection

**Purpose:** Detect systematic username enumeration attacks.
**Severity:** MEDIUM

**Logic:**
1. Query `journalctl --since '5 minutes ago'` for "Invalid user" entries.
2. Count unique invalid usernames.
3. If above threshold, extract source IPs and group by /24.
4. Subnets already in BOTNET chain → skip.
5. Novel sources → alert with username list and subnet breakdown.

**Dedup:** Per-novel-subnet, 1-hour window.

#### 7.2.6 Kernel Error Monitor

**Purpose:** Detect unusual kernel error activity.
**Severity:** MEDIUM

**Logic:**
1. Query `journalctl -k --priority=err --since '24 hours ago'`.
2. Filter out known-harmless errors (regulatory.db firmware, wireless-regdb).
3. If error count exceeds threshold, alert with error summary.

**Dedup:** Once per check cycle.

#### 7.2.7 Unauthorized SSH Session Monitor

**Purpose:** Detect active SSH sessions from non-whitelisted IPs.
**Severity:** CRITICAL

**Logic:**
1. Run `ss -tnp 'dport = :22'` to list established SSH connections.
2. Extract peer IPs.
3. Compare against whitelist (own IP, known management IPs).
4. Any connection from non-whitelisted IP → CRITICAL alert with peer IP.

**Dedup:** Per peer IP, until session ends (tracked by presence in subsequent checks).

#### 7.2.8 Suspicious Outbound Connection Monitor

**Purpose:** Detect potential C2 (Command & Control) beaconing or data exfiltration.
**Severity:** HIGH

**Logic:**
1. Run `ss -tnp state established` to list all established connections.
2. Filter out loopback (127.0.0.1, ::1) and known infrastructure (Telegram relay IPs, Hermes gateway).
3. Check destination ports against suspicious list (IRC: 6660-6700, common C2: 4444, 5555, 8080, 9090, and any SSH-reverse ports like 2222).
4. If any match, alert with destination IP:port and process info.

**Dedup:** Per `{destination_ip}:{destination_port}`, 24-hour window.

### 7.3 Check Execution Pattern

```
function run_checks(state):
    findings = []
    for each check in registry:
        try:
            result = check.function(state)
            if result is not nil:
                findings.append(result)
        catch any error:
            log_error("check {check.name} failed: {error}")
            // Continue with next check — never cascade
    return findings
```

---

## 8. Full Audit Layers

### 8.1 Overview

The deep audit runs every 6 hours (LLM-driven) and covers these layers. Each layer is an independent module returning a list of findings, each with a severity score.

#### Severity Scale

| Severity | Score | Meaning |
|---|---|---|
| CRITICAL | 10 | Active compromise indicator |
| HIGH | 7 | Significant exposure requiring immediate attention |
| MEDIUM | 4 | Configuration weakness |
| LOW | 1 | Minor issue |
| INFO | 0 | Informational, no action needed |

### 8.2 Layer 1: File Integrity

| Check | Description |
|---|---|
| Critical file hash baseline | SHA-256 hash comparison of system files (passwd, shadow, group, sudoers, sshd_config, hosts, resolv.conf, etc.) against stored baseline. Reports additions, removals, and content changes. |
| SUID/SGID binary audit | Find all setuid/setgid executables. Compare against a known-good whitelist for Debian 12. Report unexpected additions. Exclude snapshot/manual paths (timeshift, etc.). |
| World-writable file detection | Scan for world-writable files outside standard locations (/tmp, /var/tmp, /dev/shm). Critical if in system directories. |
| Hidden file/directory scan | Scan for hidden files (.prefix) in /tmp, /var/tmp, /dev/shm. Exclude known X11 Unix sockets, systemd-private directories, and snap packages. |
| ld.so.preload integrity | Check if `/etc/ld.so.preload` exists. If it does, verify contents — it's a common rootkit persistence mechanism. |
| /tmp sticky bit | Verify /tmp has the sticky bit set and is world-writable. |

### 8.3 Layer 2: Network Forensics

| Check | Description |
|---|---|
| Listening port baseline | Compare current listening ports against expected ports. Flag additions and removals. |
| Outbound connection audit | List all established outbound connections with process info. Flag connections to suspicious ports (IRC, C2, proxy). |
| Firewall status | Verify iptables is active with rules. Check for DROP default policy on INPUT. Check for port scan protection rules (NULL, XMAS, FIN, SYN+RST scans). Verify presence using both hex flag notation and named chain inspection (SCANS, BOTNET, PORT_SCAN, ANTI_SCAN, BAD_FLAGS). |
| DNS hijack detection | Verify `/etc/resolv.conf` contains expected DNS servers (not hijacked by malware). Flag non-standard nameservers. |
| ARP table inspection | Check ARP table for suspicious entries (duplicate MACs, unusual IPs). |
| Promiscuous mode detection | Check if any network interface is in promiscuous mode (packet sniffing). |

### 8.4 Layer 3: Process Forensics

| Check | Description |
|---|---|
| Hidden process detection | Compare process lists from `/proc` walk vs `ps` output. Processes visible in one but not the other suggest rootkit activity. |
| Process name spoofing | Check for processes with names mimicking system processes but running from unusual paths (e.g., `[kworker]` from `/tmp`). |
| Suspicious parent-child relationships | Flag processes where the parent is unusual (e.g., a web server spawning a shell). |
| Kernel module integrity | List loaded kernel modules. Flag any with suspicious names, missing from the standard repo, or with tainted flags. |
| Elevated process detection | List processes running as root that don't normally require root. Flag unexpected root processes. |

### 8.5 Layer 4: Authentication Audit

| Check | Description |
|---|---|
| SSH brute-force analysis | Count failed/successful SSH auth attempts in the past 24h, 7d. Report ratios and trends. |
| SSH configuration audit | Check sshd_config for: MaxAuthTries, PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, LoginGraceTime, ClientAliveInterval, PubkeyAuthentication. Flag deviations from secure baseline. If the operator intentionally keeps root login and password auth, skip those specific items. |
| Sudo user enumeration | List all users with sudo access. Flag unexpected entries. |
| NOPASSWD detection | Scan `/etc/sudoers` and `/etc/sudoers.d/` for NOPASSWD directives. Report all entries — these allow privilege escalation without password. |
| Password policy | Check PAM configuration for password complexity, history, and aging policies. |
| Authorized keys inventory | List all SSH authorized_keys files on the system. Count keys per user. Flag users with keys who shouldn't have them. |
| Last login audit | List recent successful logins. Flag logins from unexpected IPs or at unusual times. |

### 8.6 Layer 5: Log Correlation

| Check | Description |
|---|---|
| Auth log anomaly detection | Scan auth.log for patterns: unusual login times, impossible travel, session duration anomalies. |
| Invalid user enumeration | List the top invalid usernames attempted. Flag systematic enumeration vs. random guessing. (Demoted to INFO — it's a side-effect of brute-force attacks.) |
| Kernel error analysis | List and categorize recent kernel errors. Flag security-relevant errors (SElinux/AppArmor denials, protection violations). |
| Systemd unit failures | Check for failed systemd units that might indicate disabled security services. |
| Log tampering detection | Check log file sizes and modification times for gaps or unexpected truncation. Verify that auth.log and syslog are being written to. |
| Journal gap detection | Check journalctl for time gaps that might indicate log tampering or rotation issues. |

### 8.7 Layer 6: Threat Intelligence

| Check | Description |
|---|---|
| Backdoor signature scan | Scan common web roots and writable directories for webshell patterns (eval, base64_decode, system, passthru in PHP files, etc.), reverse shell one-liners, and known backdoor filenames. |
| Persistence mechanism audit | Enumerate all cron jobs (user and system), systemd timers, rc.local scripts, .profile/.bashrc modifications, and systemd service overrides. Flag any that aren't expected. |
| Recently modified binary scan | Find executables modified in the past 7 days. Cross-reference against apt package database. Flag binaries modified outside normal package updates. |
| Suspicious downloaded files | Scan common download locations (/tmp, /var/tmp, /dev/shm, home directories) for recently created executable files. |

### 8.8 Layer 7: Compliance & Hardening

| Check | Description |
|---|---|
| Kernel sysctl hardening | Verify key sysctl values: kptr_restrict, yama.ptrace_scope, protected_hardlinks, protected_symlinks, rp_filter, log_martians, accept_source_route, accept_redirects, send_redirects, icmp_echo_ignore_broadcasts, tcp_syncookies. |
| Security updates | Check for pending security updates. Count packages with available upgrades. Flag if unattended-upgrades is not installed or configured. |
| Unattended upgrades | Verify unattended-upgrades package is installed and configured to auto-install security updates. |
| Password aging | Check /etc/login.defs for PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE. |
| Core dump restrictions | Verify core dumps are restricted (fs.suid_dumpable). |
| ASLR verification | Check that Address Space Layout Randomization is enabled (kernel.randomize_va_space = 2). |

### 8.9 Layer 8: Trend Comparison

| Check | Description |
|---|---|
| Current vs. previous diff | Compare all findings from current audit against the previous run. Categorize as new, resolved, or persistent. |
| Risk score trending | Track total risk score over time. Alert on sudden increases. |
| Finding category breakdown | Group findings by category and track per-category trends. |

### 8.10 Additional Checks Already in a Conceptual Design Phase

These are checks that go beyond the standard forensic layers but have been prototyped or discussed:

#### Process Hollowing / Code Injection Detection

Scan process memory maps for unusual executable regions, specifically looking for anonymous executable mappings (rwx without file backing) which indicate code injection or process hollowing.

#### Cron/at Job Injection Detection

Monitor all crontabs and at jobs for entries that were not present in the previous scan. Flag new entries from non-standard locations.

#### SSH Key Rotation Tracking

Maintain a hash of all authorized_keys files. Flag any addition, removal, or modification. Track the number of keys per user.

---

## 9. Botnet Detection & Subnet Blocking

### 9.1 Detection Algorithm

When auth logs show many similar IPs attacking SSH, they're often botnets using multiple IPs from the same /24 subnet. Individual fail2ban bans are too slow; block the entire /24.

**Algorithm:**

1. Extract all IP addresses from `journalctl --since '{lookback_hours} hours ago'` auth output.
2. Count hits per IP, then group by /24 subnet.
3. For each /24:
   - **Botnet trigger:** ≥ `min_ips_per_subnet` unique IPs AND ≥ `min_hits_per_subnet` total hits.
   - **Heavy scanner trigger:** ≥ `solo_min_hits` total hits from any count of IPs.
4. If triggered:
   - Check whitelist (own IP prefix, RFC 1918 ranges). Skip if whitelisted.
   - Check if already blocked in iptables BOTNET chain. Skip if already blocked.
   - Add iptables DROP rule: `iptables -A BOTNET -s {subnet} -j DROP`.
   - Log the block to the botnet log file.
5. Persist rules: `iptables-save > /etc/iptables/rules.v4`.

### 9.2 iptables Chain Setup

```
// Create the BOTNET chain (once, idempotent)
iptables -N BOTNET 2>/dev/null

// Insert as first rule in INPUT chain (once, idempotent)
iptables -I INPUT -j BOTNET 2>/dev/null
```

### 9.3 Whitelist

Always block these ranges from ever being added to the BOTNET chain:

- The server's own public IP prefix (e.g., `188.130.207.0/24`)
- All RFC 1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`

### 9.4 Known Bulletproof Hosting Prefixes

Proactively maintain a list of /24 prefixes from known bulletproof hosting ASNs. These should be pre-blocked or flagged for review:

**ASNs to monitor:**
- AS48090 / AS47890 (DMZHOST / UNMANAGED LTD)
- AS214472 (PFCLOUD / Storm Industries)
- AS197170 (TechTies)
- AS200730 (ISAEV)
- AS209588 (GLOBALHOST)
- AS215929 (DATACAMPUS)

The prefix list should be maintainable (config file, not hardcoded) since it changes periodically.

### 9.5 Boot-Time Restoration

On system boot, the iptables BOTNET chain must be restored. Two mechanisms:

1. **iptables-persistent:** `netfilter-persistent save` after each block.
2. **Systemd oneshot service:** Runs on boot, restores from `/etc/iptables/rules.v4`.

### 9.6 Unblocking

Provide a utility to:
- List all currently blocked subnets with rule numbers
- Unblock a specific subnet by removing its iptables rule
- Flush the entire BOTNET chain (emergency recovery)

---

## 10. Automated Hardening Playbook

### 10.1 Pre-Hardening Checks

Before applying any hardening:

1. Check current state: `sysctl <name>`, `iptables -L -n --line-numbers`, `grep` config files.
2. Don't re-apply existing rules/values. Duplicate iptables rules waste entries and slow matching. Duplicate sysctl entries with different values cause conflicts.
3. Apply modularly — each hardening item is independent. Applying SSH MaxAuthTries doesn't require changing PermitRootLogin.

### 10.2 Hardening Steps (in order)

#### Step 1: fail2ban

```
Install fail2ban package.
Create jail.local configuration:
  - bantime: 3600 seconds (1 hour; operator may prefer longer, up to 30 days)
  - findtime: 600 seconds (10 min)
  - maxretry: 3
  - banaction: iptables-multiport
  - backend: polling (NOT systemd — python3-systemd often missing on Debian 12)
  - Enable sshd jail.

Create recidive jail for repeat offenders:
  - bantime: 604800 seconds (7 days; operator may prefer longer)
  - findtime: 86400 seconds (24h)
  - maxretry: 3

Create /var/run/fail2ban directory if not auto-created.
Restart and enable fail2ban service.
Verify: fail2ban-client status sshd.
```

#### Step 2: Kernel sysctl Hardening

```
Add to /etc/sysctl.conf or /etc/sysctl.d/99-hardening.conf:

# Anti-DDoS / SYN flood protection
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1

# ICMP / smurf attack protection
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0

# Kernel hardening
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Core dump restrictions
fs.suid_dumpable = 0

Apply with: sysctl -p.
```

#### Step 3: SSH Hardening

```
Two tiers available:

Tier 1 (Partial — preserves root login + password auth):
  Create /etc/ssh/sshd_config.d/99-hardening.conf:
    MaxAuthTries 3
    LoginGraceTime 30
    PermitEmptyPasswords no
    X11Forwarding no
    ClientAliveInterval 300
    ClientAliveCountMax 2

Tier 2 (Full — key-only, no root):
  Same as Tier 1 plus:
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes

Choose based on operator preference.
Verify with: sshd -t && systemctl restart sshd.
```

#### Step 4: iptables Firewall Rules

```
Check existing rules first (iptables -L INPUT -n --line-numbers).
Add only what's missing:

# SSH rate limiting (brute-force prevention)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Invalid packet drop
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Port scan pattern detection
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP        # XMAS scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP       # NULL scan
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# ICMP redirect block
iptables -A INPUT -p icmp --icmp-type redirect -j DROP

Persist (only if netfilter-persistent is already managing rules):
  iptables-save > /etc/iptables/rules.v4
```

#### Step 5: NOPASSWD Sudo Remediation

```
Scan /etc/sudoers and /etc/sudoers.d/* for NOPASSWD directives.
Replace NOPASSWD:ALL with ALL (password-required).
Set file permissions to 440.
```

### 10.3 Post-Hardening Verification

After all hardening steps:
1. Verify SSH still accepts connections (don't lock yourself out).
2. Run a full audit to confirm missing checks are now passing.
3. Risk score should decrease significantly (e.g., from ~38 to ~14 on a typical fresh Debian 12 VPS).

---

## 11. Alerting & Output Pipeline

### 11.1 Alert Data Structure

```
Alert {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
  source: String           // Which check/module produced this: "fail2ban", "anomaly", etc.
  message: String          // Human-readable one-line finding
  dedup_key: String        // Unique key for suppression ("f2b:1.2.3.4", "anomaly:ssh_failed_24h+above")
  structured: Map          // Machine-readable detail for log parsing and webhook JSON
}
```

### 11.2 Dedup Rules

| Finding Source | Dedup Key Format | Suppression Window |
|---|---|---|
| New fail2ban ban | `f2b:{ip}` | 24 hours |
| SSH brute-force (novel subnet) | `bf_burst:{subnet}` | 1 hour |
| Port scan evidence | `port_scan` | 1 hour |
| New listening port | `port:{number}` | 24 hours |
| Invalid user burst (novel subnet) | `enum:{subnet}` | 1 hour |
| Kernel error spike | `kernel` | 1 hour |
| Unauthorized SSH | `ssh:{peer_ip}` | Until session ends |
| Suspicious outbound | `outbound:{ip}:{port}` | 24 hours |
| Anomaly detection | `anomaly:{metric}+{direction}` | 60 minutes |
| Botnet /24 blocked | `botnet:{subnet}` | 24 hours |

### 11.3 Output Routing

```
Alert → [Dedup Check] → if new:
    → Structured log file (always, JSON lines)
    → stdout (only if severity ≥ INFO and output mode is not silent)
    → Webhook (only if severity ≥ configured webhook_min_level and webhook_url is set)
```

### 11.4 Log Format

Structured JSON lines, one object per line:

```
{"ts":"2026-06-29T10:57:00Z","level":"INFO","source":"fail2ban","severity":"HIGH","message":"New SSH ban: 1.2.3.4","structured":{"new_bans":["1.2.3.4"],"total_blocked_subnets":41}}
```

Rotate via standard `logrotate` configuration (daily rotation, 30-day retention, compress).

### 11.5 Output Formats by Mode

| Mode | Stdout Behavior |
|---|---|
| `check` | Findings only. Silent (no stdout, exit 0) when normal. |
| `record` | Always silent. Metrics go to state file only. |
| `daily` | Always produces report — human-readable digest. |
| `detect-botnet` | Silent unless new subnets blocked. Reports what was blocked. |
| `status` | Always produces report — current baselines and state. |
| `audit` | Always produces JSON report — passed to LLM summarizer. |

### 11.6 Webhook Payload

```
{
  "severity": "HIGH",
  "source": "fail2ban",
  "hostname": "<server hostname>",
  "timestamp": "2026-06-29T10:57:00Z",
  "message": "New SSH ban: 1.2.3.4",
  "structured": {
    "new_bans": ["1.2.3.4"],
    "total_blocked_subnets": 41
  }
}
```

Deliver via simple HTTP POST using a subprocess call to `curl` (avoids TLS library dependencies).

---

## 12. Scheduling & Cron Architecture

### 12.1 Two-Tier Scheduling Principle

| Frequency | Execution Type | Rationale |
|---|---|---|
| Every 1–15 minutes | Direct script execution (no LLM) | Zero token cost, instant, no rate limits |
| Every 6+ hours | LLM-driven analysis | Reasoning, summarization, natural language output |

Never use LLM-driven execution for intervals under 15 minutes — it burns tokens and hits API rate limits on free-tier models.

### 12.2 Job Definitions

| Job Name | Schedule | Execution | Delivery | Purpose |
|---|---|---|---|---|
| **Security Tick** | Every 15 min | Direct (no LLM) | Log file only | Realtime checks + anomaly detection + scheduling internal tasks |
| **Security Audit** | Every 6 hours | LLM analysis | Operator chat | Deep audit summary in natural language |

### 12.3 Internal Scheduling (within Tick)

The `tick` mode runs every 15 minutes but internally schedules less frequent tasks:

| Internal Task | Frequency | How it works |
|---|---|---|
| Realtime threat checks | Every tick (15 min) | Always runs |
| Anomaly detection | Every tick (15 min) | Always runs (with metric cache) |
| Baseline recording | Every 6 hours | Checks `last_record` timestamp; if ≥ 6h ago, records and updates timestamp |
| Botnet detection | Every 6 hours | Checks `last_botnet_check` timestamp; if ≥ 6h ago, runs detection |
| Daily digest | 08:00 UTC | Checks if `last_daily` date ≠ today's date; if so, produces report |

This consolidation means only one cron entry is needed for all high-frequency work.

### 12.4 Audit Job Structure

The 6-hour audit job:
1. Executes the deep audit script in JSON output mode.
2. The JSON output is provided to an LLM for natural-language summarization.
3. The LLM summarizes findings, highlights CRITICAL/HIGH items, and notes trends.
4. The summary is delivered to the operator.

### 12.5 Cron Health Monitoring

The `tick` mode logs start and end timestamps. Missing ticks are detectable:
- If `last_record` timestamp is > 6 hours old, a tick was missed.
- If `last_anomaly_check` timestamp is > 20 minutes old, a tick was missed.

---

## 13. Proposed New Checks

### 13.1 Rationale

The following are **new checks** not present in the existing system. They address gaps in coverage for modern attack techniques, container escapes, supply chain attacks, and configuration drift. Each is specified with acceptance criteria so an implementor can build and verify them independently.

### 13.2 New Check Specifications

---

#### NC-1: Container/Docker Privilege Escalation Detection

**Layer:** Process Forensics (3)
**Severity:** HIGH

**What to check:**
- Enumerate all running Docker containers (if Docker is installed).
- For each container, check: is it running in privileged mode (`--privileged`)?
- Does any container mount the host's Docker socket (`/var/run/docker.sock`)?
- Does any container mount host filesystem paths like `/`, `/etc`, `/root`?
- Are there any unexpected containers not matching a known whitelist?

**Why:** Privileged containers and Docker socket mounts are common escape vectors. An attacker who compromises a web application in a privileged container can break out to the host.

**Data sources:** `docker ps`, `docker inspect` (if Docker available), `/proc/*/cgroup`, `/proc/*/mountinfo`.

**Acceptance criteria:**
- Returns CRITICAL for any privileged container not in a configurable whitelist.
- Returns HIGH for any container with Docker socket mount.
- Returns MEDIUM for host filesystem mounts.
- Returns nil if Docker is not installed or no containers are running.

---

#### NC-2: Network Interface Anomaly Detection

**Layer:** Network Forensics (2)
**Severity:** HIGH

**What to check:**
- Check if any network interface is in promiscuous mode (`ip link show | grep PROMISC`).
- Check for unexpected network interfaces (tun/tap devices not created by known VPNs).
- Monitor for interface MTU changes (some rootkits modify MTU to hide traffic).
- Check for ARP table anomalies (duplicate MAC addresses, gateway MAC changes).

**Why:** Promiscuous mode indicates packet sniffing — either legitimate (tcpdump) or malicious (traffic capture). Unexpected interfaces suggest VPN tunnels or C2 backchannels.

**Data sources:** `ip link show`, `ip neigh show`, `/proc/net/arp`, `/sys/class/net/*/flags`.

**Acceptance criteria:**
- Returns CRITICAL for promiscuous mode on an external-facing interface.
- Returns HIGH for unexpected tun/tap devices.
- Returns MEDIUM for ARP table anomalies.
- Returns nil when all interfaces are in normal mode.

---

#### NC-3: DNS Resolver Integrity Check

**Layer:** Network Forensics (2)
**Severity:** HIGH

**What to check:**
- Verify `/etc/resolv.conf` nameservers match expected values.
- Check for `options` lines that weaken DNS security (e.g., `options ndots:0`).
- Check `/etc/nsswitch.conf` hosts line for unexpected modules.
- Verify systemd-resolved configuration if active.
- Check for hardcoded entries in `/etc/hosts` that override critical domains.

**Why:** DNS hijacking is a stealthy attack. Malware often changes DNS to redirect traffic through attacker-controlled nameservers for credential harvesting or C2 communication.

**Data sources:** `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/hosts`, `systemd-resolve --status`.

**Acceptance criteria:**
- Returns CRITICAL if nameservers don't match expected list.
- Returns HIGH for suspicious hosts file entries targeting security/update domains.
- Returns MEDIUM for non-standard nsswitch hosts configuration.
- Returns nil when DNS configuration matches expected baseline.

---

#### NC-4: TLS/Certificate Hygiene Monitor

**Layer:** Compliance (7)
**Severity:** MEDIUM

**What to check:**
- Scan `/etc/ssl/certs/` for certificates nearing expiration (< 30 days).
- Check for self-signed certificates in use by public-facing services.
- Detect certificates with weak key sizes (< 2048-bit RSA, < 256-bit EC).
- Identify certificates using deprecated algorithms (SHA-1, MD5).

**Why:** Expired certificates cause outages. Self-signed certificates on public services indicate misconfiguration. Weak keys and deprecated algorithms expose services to downgrade attacks.

**Data sources:** `openssl x509 -in <cert> -text -noout`, filesystem scan of `/etc/ssl/`, Apache/Nginx config parsing for cert paths.

**Acceptance criteria:**
- Returns HIGH for certificates expired or expiring within 7 days.
- Returns MEDIUM for certificates expiring within 30 days.
- Returns LOW for weak key sizes.
- Returns INFO for self-signed certificates on public services.
- Returns nil when all certificates are valid and strong.

---

#### NC-5: User Account Integrity Monitor

**Layer:** Authentication Audit (4)
**Severity:** CRITICAL

**What to check:**
- Compare current user list against stored baseline. Flag additions.
- Check for users with UID 0 other than root.
- Check for users with empty passwords (check `/etc/shadow` for `!` / `*` / empty field).
- Check for accounts with login shells that shouldn't have them (daemon accounts).
- Check group memberships — flag new additions to `sudo`, `wheel`, `admin`, `docker` groups.
- Check recently modified `authorized_keys` files.

**Why:** New user accounts with elevated privileges are a classic indicator of compromise. Attackers often create backdoor accounts or add their SSH keys to legitimate users.

**Data sources:** `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/home/*/`, `authorized_keys` files, last modification timestamps.

**Acceptance criteria:**
- Returns CRITICAL for: new UID 0 account, empty-password account with shell.
- Returns HIGH for: new user with sudo group membership, unauthorized SSH key addition.
- Returns MEDIUM for: daemon account with login shell, new user without privileges.
- Maintains baseline of known users and group memberships for comparison.

---

#### NC-6: Suspicious Mount Detection

**Layer:** Process Forensics (3)
**Severity:** HIGH

**What to check:**
- List all mounted filesystems. Flag unexpected types (tmpfs in non-standard locations, devtmpfs outside /dev, overlay anywhere unexpected).
- Check for bind mounts that expose restricted paths.
- Verify `/proc` is mounted (not a fake proc by some rootkits).
- Check for mounts with `noexec` missing on writable filesystems (/tmp, /var/tmp, /dev/shm).

**Why:** Attackers use mount namespace manipulation and tmpfs mounts to hide files and processes. Bind mounts can bypass filesystem restrictions.

**Data sources:** `/proc/mounts`, `/proc/self/mountinfo`, `mount` output.

**Acceptance criteria:**
- Returns CRITICAL for bind mount exposing a restricted path (e.g., `/etc/shadow` bound elsewhere).
- Returns HIGH for tmpfs mounts in unexpected locations.
- Returns MEDIUM for writable mounts missing noexec (except where explicitly allowed).
- Returns nil for standard Debian 12 mount configuration.

---

#### NC-7: Systemd Service Integrity Check

**Layer:** Threat Intelligence (6)
**Severity:** HIGH

**What to check:**
- Enumerate all enabled systemd services. Compare against stored baseline.
- Check for services with `ExecStart` pointing to unusual paths (e.g., /tmp, /var/tmp, /dev/shm).
- Check for overridden system services (mask files, override directories).
- Detect services with `User=root` and `ExecStart` in user-writable locations.
- Check systemd timers for suspicious schedules. Flag new timer units.

**Why:** Modern Linux malware increasingly uses systemd for persistence — it's cleaner than cron, survives reboots, and is often overlooked in audits.

**Data sources:** `systemctl list-unit-files`, `systemctl cat <service>`, `/etc/systemd/system/`, `/lib/systemd/system/`.

**Acceptance criteria:**
- Returns CRITICAL for service with ExecStart in /tmp or /dev/shm.
- Returns HIGH for new enabled services not in baseline.
- Returns MEDIUM for masked system services (could indicate attacker disabling security).
- Returns INFO for overridden services with legitimate-looking changes.
- Maintains baseline of known services for change detection.

---

#### NC-8: Time Synchronization Integrity Check

**Layer:** Compliance (7)
**Severity:** MEDIUM

**What to check:**
- Verify NTP synchronization is active (check `timedatectl`, `chronyc`, or `ntpq`).
- Check for large time drift (> 5 seconds from any configured NTP source).
- Verify the configured NTP servers are legitimate (not attacker-controlled).
- Check that time sync service is enabled and running.

**Why:** Accurate time is critical for log correlation, certificate validation, and Kerberos. Time manipulation by an attacker can hide events in logs, invalidate audit timestamps, and enable replay attacks.

**Data sources:** `timedatectl show`, `chronyc tracking`, `/etc/chrony/chrony.conf`, `/etc/systemd/timesyncd.conf`.

**Acceptance criteria:**
- Returns HIGH if time is not synchronized AND drift > 60 seconds.
- Returns MEDIUM if time sync service is not running.
- Returns LOW for drift > 5 seconds but < 60 seconds.
- Returns nil when time is synchronized with minimal drift.

---

#### NC-9: eBPF / BPF Program Integrity

**Layer:** Process Forensics (3)
**Severity:** CRITICAL

**What to check:**
- List all loaded BPF programs (requires `bpftool`).
- Check for BPF programs attached to security-relevant hooks (syscalls, network, cgroup).
- Flag any BPF program not matching a known baseline.
- Check if BPF is available but `kernel.unprivileged_bpf_disabled` is not set to 1.

**Why:** eBPF is increasingly used by advanced rootkits to intercept syscalls, hide processes, and exfiltrate data without kernel modules. Unprivileged BPF access is a significant attack surface.

**Data sources:** `bpftool prog list`, `bpftool map list`, `sysctl kernel.unprivileged_bpf_disabled`.

**Acceptance criteria:**
- Returns CRITICAL if unprivileged BPF is enabled AND BPF programs exist.
- Returns HIGH for unexpected BPF programs on security hooks.
- Returns MEDIUM if `bpftool` is not available (add to recommendations).
- Returns nil when unprivileged BPF is disabled or no unexpected programs exist.

---

#### NC-10: Supply Chain Integrity Verification

**Layer:** Compliance (7)
**Severity:** MEDIUM

**What to check:**
- Run `debsums` to verify installed package file checksums against repository metadata.
- Count files that fail checksum verification.
- Flag packages with modified files but no corresponding dpkg log entry for modification.
- Verify apt sources list integrity (check for unauthorized repository additions).

**Why:** Package file tampering is a persistent threat — attackers replace system binaries with backdoored versions. Regular checksum verification catches this.

**Data sources:** `debsums -c` (if installed), `dpkg -V`, `/etc/apt/sources.list`, `/etc/apt/sources.list.d/`.

**Acceptance criteria:**
- Returns HIGH if modified files exist in security-critical packages (openssh, sudo, libc, systemd).
- Returns MEDIUM for any modified package files.
- Returns LOW if `debsums` is not installed (recommend installation).
- Returns nil when all package files match their checksums.

---

#### NC-11: Log Integrity & Gap Detection

**Layer:** Log Correlation (5)
**Severity:** HIGH

**What to check:**
- Scan `journalctl` for time gaps > 1 hour in persistent journal.
- Check if journal is configured for persistent storage (`Storage=persistent` in journald.conf).
- Verify auth.log and syslog are being actively written to (modification time within last 15 min).
- Check for log files with unexpectedly small sizes (truncation).
- Verify auditd is running if installed.

**Why:** Log tampering is one of the first things an attacker does after gaining access. Time gaps, truncated logs, and disabled logging services are strong indicators of compromise.

**Data sources:** `journalctl --list-boots`, `journalctl --verify`, `/etc/systemd/journald.conf`, file modification times and sizes of /var/log/*.

**Acceptance criteria:**
- Returns CRITICAL if journal verification fails or persistent storage is disabled.
- Returns HIGH for auth.log gaps > 1 hour (rotation is expected, silent truncation is not).
- Returns MEDIUM if logs haven't been written to in > 1 hour on an active system.
- Returns nil when all logging is intact and functioning.

---

### 13.3 New Check Integration

New checks slot into the existing layer framework:

| New Check | Existing Layer | Integration Point |
|---|---|---|
| NC-1 (Container Escalation) | Layer 3 (Process Forensics) | New check module, runs alongside hidden process detection |
| NC-2 (Interface Anomaly) | Layer 2 (Network Forensics) | New check module, runs alongside port scan detection |
| NC-3 (DNS Integrity) | Layer 2 (Network Forensics) | Extends existing DNS hijack check |
| NC-4 (TLS Hygiene) | Layer 7 (Compliance) | New check module in compliance layer |
| NC-5 (User Account Integrity) | Layer 4 (Auth Audit) | New check module with baseline tracking |
| NC-6 (Suspicious Mounts) | Layer 3 (Process Forensics) | New check module |
| NC-7 (Systemd Integrity) | Layer 6 (Threat Intel) | Extends existing persistence mechanism audit |
| NC-8 (Time Sync) | Layer 7 (Compliance) | New check module |
| NC-9 (eBPF Integrity) | Layer 3 (Process Forensics) | New check module, conditional on bpftool |
| NC-10 (Supply Chain) | Layer 7 (Compliance) | New check module, conditional on debsums |
| NC-11 (Log Integrity) | Layer 5 (Log Correlation) | Extends existing log tampering detection |

---

## 14. Testing Requirements

### 14.1 Test Categories

| Category | Description | Target |
|---|---|---|
| **Unit tests** | Per-function correctness with mock data | 95%+ line coverage |
| **Integration tests** | Full mode cycles with controlled inputs | All modes exercised |
| **Property-based tests** | Mathematical invariants (sigma symmetry, variance properties) | Statistical integrity |
| **Check matrix tests** | Each threat check tested with nil, normal, and alertable inputs | 100% of check matrix |
| **State migration tests** | v2→v3 migration preserves all data | Lossless migration |
| **Edge case tests** | Corrupt state, empty data, missing binaries, timeouts | Graceful degradation |

### 14.2 Test Infrastructure Requirements

- **State isolation:** Every test uses a temporary state file, never the live state.
- **Command mocking:** All external subprocess calls are mockable so tests don't require actual journalctl/fail2ban/iptables output.
- **Time control:** Tests can freeze "now" to a known timestamp for deterministic scheduling tests.
- **Config isolation:** Tests provide their own configuration, not reading from environment or config files.

### 14.3 Key Test Scenarios

**Anomaly Detection:**
- Both gates pass → alert fires
- Sigma passes, min_delta fails → no alert
- Sigma fails, min_delta passes → no alert
- Standard deviation is zero on stable metric → pure deviation check
- Cool-down suppresses repeated alert within window
- Stale baseline detected (3+ identical values) → warning instead of alert

**Threat Checks:**
- Each check returns nil when system state is normal
- Each check returns alert when attack indicators present
- Per-check dedup prevents repeated alerts
- Check failures don't cascade to other checks

**State Management:**
- Corrupt JSON file → load defaults, log error
- Missing file → create defaults, continue
- Concurrent write → no corruption (atomic rename)
- Schema migration preserves all data

**Botnet Detection:**
- Subnet with 3 IPs × 100+ hits → blocked
- Single IP with 500+ hits → /24 blocked
- Whitelisted prefix → skipped
- Already-blocked subnet → skipped
- Invalid iptables chain → created automatically

---

## 15. Deployment & Rollback

### 15.1 Prerequisites

- Debian 12 (Bookworm) or compatible
- Root access (required for iptables manipulation, journalctl -k, /proc inspection)
- Python 3.9+ (or equivalent runtime for the chosen language)
- Packages: `iptables`, `fail2ban`, `netfilter-persistent` (optional for boot persistence)

### 15.2 Installation Checklist

1. Create data directory for state, snapshots, and configuration.
2. Place all source files in the data directory.
3. Create cron entry point script referencing the main entry point.
4. Run in manual mode first: `--status` to verify operation, `--check` to test detection.
5. Run `--record` several times to build an initial baseline (wait 24h minimum for meaningful data).
6. After baseline is established, create the cron job for `--tick` mode at delivery=local for 24h.
7. Review logs for false positives. Adjust thresholds via config overrides.
8. Create the 6-hour audit cron job.
9. Switch to delivery=origin for both if operator-facing alerts are desired.

### 15.3 Rollback Procedure

1. Pause the tick cron job.
2. If state file corruption is suspected, restore from the most recent daily snapshot.
3. If old version scripts exist, re-point cron to previous entry point.
4. If iptables BOTNET chain changes need reverting, use the unblock utility.

### 15.4 Upgrade Path

When deploying a new version:
1. Deploy new code alongside old (versioned subdirectory).
2. Cron entry points to a symlink — update symlink to switch versions.
3. Run state migration if schema version changed.
4. Monitor for 24h before declaring success.

---

## 16. Security Review & Hardening of the Monitor Itself

### 16.1 Principle

The security monitor is itself an attack target. An attacker who compromises the monitor can disable detection, suppress alerts, or use its root privileges for lateral movement.

### 16.2 Hardening Measures

| Measure | Implementation |
|---|---|
| **Minimal privileges** | The monitor binary/scripts should be owned by root, mode 700. No world-readable. |
| **No writable paths** | The monitor must never write to or execute from world-writable directories (/tmp, /var/tmp, /dev/shm). |
| **Config immutability** | After deployment, configuration should only be writable by root. Monitor rejects config from world-writable locations. |
| **No shell injection** | All external command invocations use argument-array form. No string interpolation. Static analysis must flag any exception. |
| **Input validation** | All values read from state file or config are validated before use. Unexpected types or ranges are replaced with defaults. |
| **Output sanitization** | Alert messages containing user-controllable data (IP addresses, usernames) are sanitized to prevent log injection (no newlines, no control characters). |
| **Self-audit** | The monitor's own binaries, config files, and state directory are included in the file integrity audit (Layer 1). Any tampering is self-reported. |
| **Cron job integrity** | The tick cron job is verified as part of the persistence mechanism audit (Layer 6). |
| **Log tampering detection** | The monitor's own log file is monitored for unexpected truncation or permission changes. |

### 16.3 What the Monitor Deliberately Does NOT Do

- **No network listening.** The monitor never opens ports or accepts remote connections. All data is gathered via local system tools.
- **No auto-mitigation beyond botnet blocking.** The monitor does not automatically kill processes, delete files, or change configurations (except for hardening playbook which requires explicit operator invocation).
- **No data exfiltration.** All data stays on the local system. Webhook dispatch is opt-in and only sends specific structured alerts.

---

## 17. Edge Cases & Failure Modes

### 17.1 Expected Behaviors

| Scenario | Expected Behavior |
|---|---|
| State file is corrupt JSON | Log error, back up corrupt file, initialize with defaults, continue normally. |
| State file missing entirely | Initialize with defaults, continue. |
| journalctl hangs or times out | Catch timeout, set all SSH-related metrics to 0, log error, continue with remaining metrics. |
| fail2ban-client not installed | Set `f2b_banned_count` to 0, skip fail2ban ban monitor check, log informational message, continue. |
| iptables BOTNET chain doesn't exist | Create it automatically, log creation. If creation fails (e.g., kernel module missing), skip botnet detection, log error. |
| Disk full — state write fails | Log error, fall back to in-memory state for the current process, do not crash. |
| Concurrent tick processes | Prevented by cron scheduler lock. If somehow concurrent, atomic rename ensures last writer wins without corruption. |
| First baseline recording (no prior data) | All metrics collected, stored as one sample. No anomaly detection until `baseline_min_samples` reached. |
| Daily report runs before any data exists | Show "no baseline" for all metrics, report only current raw values. |
| Webhook URL is unreachable | Subprocess timeout (10 seconds). Log error, continue without crashing. |
| IPv6-heavy environment | IP extraction regex patterns check for both v4 and v6. IPv6 addresses are tracked separately. Log a warning if IPv6 attack traffic is detected but not fully handled. |
| Server has no public IP (NAT-only) | `own_ip` should be set to the NAT gateway IP or empty. Whitelist checks skip self-filtering. |
| Unusual locale or language in journalctl output | Metric pattern matching uses position-independent regex (not language-dependent string matching where possible). |
| Process with extremely long command line | Truncate to maximum output length in alerts. Full command line available in structured log. |

### 17.2 Graceful Degradation Priorities

When critical dependencies are missing:

1. **journalctl missing** (extremely unlikely on systemd-based Debian 12): All journalctl-based metrics return 0. Log CRITICAL error.
2. **iptables missing**: Botnet detection and firewall audit are disabled. Log CRITICAL error.
3. **ss command missing**: Network metrics return 0. Log CRITICAL error.
4. **fail2ban missing**: f2b metrics return 0, f2b checks are skipped. Log INFO (fail2ban is optional).

The system must never crash due to a missing optional dependency.

---

## Appendix A: Metric Collection Data Flow Diagram

```
                    ┌──────────────────────┐
                    │   collect_metrics()  │
                    └──────────┬───────────┘
                               │
            ┌──────────────────┼──────────────────────┐
            │                  │                       │
            ▼                  ▼                       ▼
   ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐
   │  journalctl      │  │ system tools │  │  iptables        │
   │  --since 24h     │  │              │  │                  │
   │                  │  │ fail2ban     │  │ iptables -L      │
   │ → ssh_failed     │  │ → f2b_banned │  │ BOTNET -n        │
   │ → ssh_invalid    │  │              │  │ → botnet_rules   │
   │ → unique_ips     │  │ ss -tlnp     │  │                  │
   │ → unique_subnets │  │ → listening  │  │ botnet log       │
   │                  │  │              │  │ → new_blocks     │
   │ journalctl -k    │  │ ss -tnp      │  │                  │
   │ → martians       │  │ → established│  │                  │
   │ → kernel_errors  │  │              │  │                  │
   └─────────────────┘  └──────────────┘  └──────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Metric Cache       │
                    │   (5 min TTL)        │
                    └──────────────────────┘
```

## Appendix B: Alert Severity Decision Tree

```
Is there an active compromise?
├── YES → CRITICAL (score: 10)
│   Examples: unauthorized SSH session, new root user, kernel rootkit detected
│
├── NO → Is there a significant exposure being actively exploited?
│   ├── YES → HIGH (score: 7)
│   │   Examples: new fail2ban ban, brute-force burst, suspicious outbound connection
│   │
│   └── NO → Is there a configuration weakness that enables future attacks?
│       ├── YES → MEDIUM (score: 4)
│       │   Examples: NOPASSWD sudo, missing firewall rule, weak SSH config
│       │
│       └── NO → Is it informational but noteworthy?
│           ├── YES → LOW (score: 1)
│           └── NO → INFO (score: 0)
│               Examples: statistical baseline update, cron health status
```

## Appendix C: Deployment Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEBIAN 12 CLOUD VPS                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    CRON SCHEDULER                         │  │
│  │                                                          │  │
│  │  Every 15 min ──→ tick entry point (direct execution)    │  │
│  │  Every 6 hours ─→ audit entry point (LLM analysis)       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              SECURITY MONITOR ENGINE                      │  │
│  │                                                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │  │
│  │  │ Metrics   │  │ Threat   │  │ Anomaly  │               │  │
│  │  │ Collector │  │ Checks   │  │ Detector │               │  │
│  │  └──────────┘  └──────────┘  └──────────┘               │  │
│  │        │              │             │                     │  │
│  │        └──────────────┼─────────────┘                     │  │
│  │                       │                                   │  │
│  │  ┌──────────┐  ┌──────▼────┐  ┌──────────┐              │  │
│  │  │ Botnet   │  │  Alert    │  │  Deep    │              │  │
│  │  │ Blocker  │  │ Dispatcher│  │  Audit   │              │  │
│  │  └──────────┘  └──────────┘  └──────────┘              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│          ┌───────────────────┼───────────────────┐             │
│          ▼                   ▼                   ▼             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ State File   │  │  Structured  │  │  Human-      │        │
│  │ + Snapshots  │  │  JSON Log    │  │  Readable    │        │
│  │              │  │  File        │  │  Output      │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 SYSTEM INTERFACES                         │  │
│  │  journalctl  │  ss  │  iptables  │  fail2ban  │  /proc   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

**End of specification.** This document defines the complete architecture, all checks (existing and new), and implementation requirements for a production-grade security audit and monitoring system for Debian 12 cloud VPS deployments. It is designed to be language-agnostic and self-contained — any competent developer or AI agent should be able to implement the full system from this document alone.
