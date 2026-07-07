# BPF Watcher — Setup & Operations

New stable-key NC-9 delta watcher that replaces the old fragile ID-based BPF checks. Uses persistent identity keys, risk scoring, loader provenance, and a state-machine watchlist to silently absorb transient BPF programs and escalate only on persistent high-risk artifacts.

## Architecture

```
scan ──► classify ──► watchlist ──► escalate (if persistent + high risk)
              │
              ├── systemd whitelist  → IGNORED (no watch needed)
              ├── baseline match     → BASELINE_MATCH (known-good)
              ├── low risk (<70)     → SURVEILLANCE (watch but no alert)
              ├── high risk (70-99)  → ALERT_HIGH
              └── critical (100+)    → ALERT_CRITICAL
```

### State machine

| State | Meaning | Alert? |
|-------|---------|--------|
| IGNORED | Known systemd program (name + type + attach + loader) | No |
| BASELINE_MATCH | Previously promoted by operator | No |
| SURVEILLANCE | New, unknown, low risk score — being watched | No |
| VANISHED | Was in watchlist, no longer present — absorbed | No |
| ALERT_HIGH | Risk score ≥70 | Yes |
| ALERT_CRITICAL | Risk score ≥100 | Yes |

### Stable identity keys

Programs identified by `prog:<type>:<tag>:<xlated_sha256>:<attach_fingerprint>` — survive reboots, ID reshuffling, and kernel upgrades.

## Configuration

Add to `~/.hermes/secmon/config.yaml` (or `/etc/secmon/config.yaml` for legacy setups):

```yaml
bpf:
  systemd_loader_paths:
    - "/usr/lib/systemd/systemd"
    - "/lib/systemd/systemd"
  systemd_cgroup_prefixes:
    - "/system.slice"
```

The hardcoded `SYSTEMD_WHITELIST_RULES` in `classifier.py` auto-matches `sd_fw_ingress`, `sd_fw_egress`, `sd_devices` by name + type + attach + loader.

**Pitfall:** Config search order is `/etc/` → `~/.hermes/` → cwd. If both exist, `/etc/` wins. For automatic backup coverage, prefer `~/.hermes/` and remove the `/etc/` copy.

## Commands

```bash
# BPF-only watch (quick, no full audit)
secmon --bpf-watch

# List the watchlist (programs in surveillance)
secmon --bpf-watchlist list

# Clear a watchlist entry (false positive)
secmon --bpf-watchlist clear --key "prog:cgroup_skb:..."

# List baseline (promoted programs)
secmon --bpf-baseline list

# Promote a program to baseline
secmon --bpf-baseline promote --key "prog:cgroup_device:..."
```

## First-time Setup

After installing/updating secmon, the BPF baseline starts empty. Existing systemd programs enter SURVEILLANCE at score 0 (no alert). Promote them:

```bash
# 1. Add bpf config to ~/.hermes/secmon/config.yaml
# 2. Run BPF watch to populate the watchlist
secmon --bpf-watch
# 3. Verify watchlist
secmon --bpf-watchlist list
# 4. Promote all entries to baseline
while read -r key; do
  secmon --bpf-baseline promote --key "$key"
done < <(secmon --bpf-watchlist list | python3 -c "
import json, sys
for key in json.load(sys.stdin).get('programs',{}):
    print(key)
")
# 5. Verify: watchlist empty, baseline populated
```

## Pitfalls

- **Empty loader provenance** — BPF programs without FD holder PIDs have blank loader metadata (exe, systemd_unit). Systemd whitelist can't confirm loader, so programs stay SURVEILLANCE at score 0. Fix: promote manually.
- **Reboot resets BPF IDs** — Old ID-based code flagged every program as new after reboot. Stable keys fix this.
- **auditd bridge optional** — `packaging/secmon-bpf.rules` tracks `bpf()` syscalls. Only needed for short-lived BPF programs that vanish before the next scan.
- **--bpf-watch is fast but not free** — runs bpftool JSON commands, ~1-2 seconds on typical system.

## Related Files

| File | Purpose |
|------|---------|
| `src/secmon/bpf/watcher.py` | Watch refresh, delta detection, alert escalation |
| `src/secmon/bpf/audit.py` | Audit integration — called from process.py NC-9 |
| `src/secmon/bpf/classifier.py` | Risk scoring, systemd whitelist, classification |
| `src/secmon/bpf/collector.py` | bpftool JSON collection, parsing |
| `src/secmon/bpf/models.py` | Data models: WatchState, BpfProgram, ClassificationResult |
| `src/secmon/bpf/identity.py` | Stable key computation |
| `src/secmon/bpf/provenance.py` | Loader metadata from /proc |
| `src/secmon/bpf/watchlist.py` | State helpers: promote, update, clear |
| `src/secmon/bpf/auditd.py` | auditd bridge: lost/backlog, ausearch |
| `src/secmon/modes/bpf.py` | CLI mode handlers |