# Anomaly Detection Framework

## Algorithm

Statistical anomaly detection via rolling baselines — only alerts when metrics deviate significantly from the norm.

### Two-Gate Logic

A metric must pass BOTH gates to trigger an alert:

- **Gate 1 (sigma):** `|value - μ| > N × σ`
- **Gate 2 (min_delta):** `|value - μ| >= MIN_DELTA[metric]`

**Why both:** Without min_delta, low-count metrics with tiny σ produce infinite-sigma alerts on +1 fluctuation. Without sigma, min_delta alone would alert on every small bump.

### Sample Variance

Use **n-1 denominator** (Bessel's correction) not population variance (n). Better estimates for small samples (<30).

### When σ = 0

Pure deviation check:
- Above: alert if `current > mean` AND `|current - mean| >= min_delta`
- Below: alert if `current < mean` AND `|current - mean| >= min_delta`
- Severity: HIGH for above, MEDIUM for below

### Severity Classification

| Deviation | Severity |
|-----------|----------|
| > 2.0 × sigma_threshold | CRITICAL |
| > 1.5 × sigma_threshold | HIGH |
| > 1.0 × sigma_threshold | MEDIUM |
| ≤ 1.0 × sigma_threshold | No alert |

### Cool-Down

Tracked per `{metric_key}+{direction}` with timestamp. If same metric+direction flagged <60 min ago → suppress. After 60 min, re-alert if still anomalous.

### Stale Baseline Rule

If same metric fires 3+ consecutive ticks with approximately the same value (±10%), the baseline is stale. Log a "stale baseline" warning instead of re-alerting. Options:
1. Auto-pop oldest daily_stats entry to shift baseline toward current
2. Log warning and recommend re-seeding
3. Raise min_delta or sigma threshold

**Never keep re-reporting the same signal.**

## Metrics & Thresholds

| Metric | Sigma (Above) | Sigma (Below) | Min_Delta | Source |
|--------|---------------|---------------|-----------|--------|
| ssh_failed_24h | 2.5 | 2.0 | 5,000 | journalctl "Failed password" |
| ssh_invalid_user_24h | 2.5 | — | 2,000 | journalctl "Invalid user" |
| unique_attacker_ips | 2.5 | — | 100 | journalctl IP extraction |
| unique_attacker_subnets | 2.5 | — | 80 | journalctl /24 grouping |
| f2b_banned_count | 4.0 | — | 20 | fail2ban-client status |
| botnet_chain_rules | 4.0 | — | 5 | iptables -L BOTNET |
| martian_packets_24h | 3.0 | — | 10 | journalctl -k "martian" |
| new_blocked_subnets_24h | 3.0 | — | 5 | botnet log file |
| kernel_errors_24h | 3.0 | — | 3 | journalctl -k --priority=err |
| listening_ports_count | 3.0 | — | 2 | ss -tlnp |
| established_conns | 4.0 | — | 8 | ss -tnp (exclude loopback) |

## Metric Cache

- **300s (5 min) TTL** — per-process cache
- `--check` reuses cached metrics if fresh
- `--record` invalidates cache (forces fresh collection)
- Prevents 3 journalctl + 2 ss + 1 iptables + 1 fail2ban calls every 15 min

## Baseline Seeding Protocol

**CRITICAL:** Seed with REAL journalctl data from the target server, not synthetic data.

1. Query journalctl per-day for past 7 days:
   ```
   for d in 1..7:
     ssh = count "Failed password" in [d, d-1) days ago
     ips = unique IPs in same window
     subs = unique /24s in same window
   ```
2. Populate daily_stats with one entry per day for 7 days.
3. Collect current values for non-journalctl metrics.

**Why:** SSH attack volume varies 100× between servers. Synthetic seeds tuned for one scenario produce constant false positives on another.

## Calibration Protocol

After 14+ samples (~2 weeks):
1. Compute observed range per metric (P10-P90)
2. Set min_delta to ~30-40% of observed range
3. Never auto-apply — log suggestion, operator reviews

## Output Format (anomalies only, silent when normal)

```
🚨 ANOMALY DETECTED [MEDIUM] — 2026-06-28T08:00UTC

🟠 **Failed SSH attempts (24h)** — 📈 above normal
   Current: **15000** | Baseline: μ=6204, σ=4032 | 2.18σ deviation
```

## Critical Pitfalls

1. **`--check` must NEVER call record_metrics()** — recording is exclusively via `--record`
2. **Dedup by time slot** — only one entry per slot in daily_stats (latest wins). Slot size = 6h for 4 samples/day
3. **journalctl -k not dmesg** — dmesg wraps/rotates. journalctl -k has persistent history
4. **established_conns excludes localhost** — filter both 127.0.0.1 and ::1
5. **IPv6 loopback format** — check both "::1" and "0:0:0:0:0:0:0:1"
6. **f2b_banned_count was deliberately omitted from old thresholds** because it spammed the user. Now added at 4.0σ / min_delta=20 with cooldown to prevent spam.
