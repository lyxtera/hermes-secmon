# BPF Watcher — Check IDs & Classifier Rules Reference

## State Machine Transitions

| From | To | Condition | Emits |
|------|----|-----------|-------|
| *(not in watchlist)* | SURVEILLANCE | New BPF program detected, score < 70 | NC-9-bpf-surveillance-started (INFO) |
| *(not in watchlist)* | ALERT_HIGH | New BPF program, score ≥ 70 | NC-9-bpf-high-risk-program (HIGH) |
| *(not in watchlist)* | ALERT_CRITICAL | New BPF program, score ≥ 100 | NC-9-bpf-critical-program (CRITICAL) |
| SURVEILLANCE | ALERT_HIGH | Score increased to ≥ 70 | NC-9-bpf-high-risk-program (HIGH) |
| SURVEILLANCE | ALERT_CRITICAL | Score increased to ≥ 100 | NC-9-bpf-critical-program (CRITICAL) |
| SURVEILLANCE | VANISHED | Program gone on next scan | *(silent)* |
| ALERT_HIGH | VANISHED | Program gone on next scan | *(silent)* |
| any | IGNORED | Matches systemd whitelist | *(silent)* |
| any | BASELINE_MATCH | Promoted via `--bpf-baseline promote` | NC-9-bpf-baseline-promoted (INFO) |

## Check IDs

| Check ID | Severity | Score | Trigger | Data in detail |
|----------|----------|-------|---------|----------------|
| NC-9-bpf-surveillance-started | INFO | 0 | New program entered watchlist (first observation, score < 70) | stable_key, risk_score, bpf_id, reasons |
| NC-9-bpf-critical-program | CRITICAL | 3 | Program escalated to ALERT_CRITICAL (score ≥ 100) | stable_key, risk_score, bpf_id, prev_state, new_state |
| NC-9-bpf-high-risk-program | HIGH | 3 | Program escalated to ALERT_HIGH (score ≥ 70) | stable_key, risk_score, bpf_id, prev_state, new_state |
| NC-9-bpf-high-risk-map | HIGH | 3 | Map escalated to ALERT_HIGH | stable_key, risk_score, bpf_id, prev_state, new_state |
| NC-9-bpf-monitoring-gap | HIGH | 3 | auditd lost or backlog counter increased | audit_lost, audit_backlog, prev_lost, prev_backlog |
| NC-9-bpf-link-updated | HIGH | 3 | New link attachment appeared on watched program | stable_key, risk_score, bpf_id |
| NC-9-bpf-pinned-persistence | MEDIUM | 3 | New pinned path on watched program | stable_key, pins, bpf_id |
| NC-9-bpf-loader-suspicious | HIGH | 3 | Loader changed to suspicious path (score ≥ 40) | stable_key, risk_score, bpf_id |
| NC-9-bpf-map-mutated | HIGH | 3 | Map metadata changed (max_entries/flags/FD holders) | stable_key, bpf_id |
| NC-9-bpf-baseline-promoted | INFO | 0 | Watchlist entry promoted to baseline | stable_key, kind |

## Stable Key Format

**Programs** (preferred — xlated available):
```
prog:{type}:{tag}:{xlated_sha256}:{attach_fingerprint[:16]}
```

**Programs** (fallback — no xlated):
```
prog:{type}:{tag}:{name}:{map_schema_hash[:16]}:{attach_fingerprint[:16]}
```

**Maps:**
```
map:{type}:{name}:{key_size}:{value_size}:{max_entries}:{flags}:{btf_hash[:16]}
```

## Score Breakdown (classifier.py)

| Factor | Max score | What triggers it |
|--------|-----------|-----------------|
| Program type risk | 40 | kprobe, kretprobe, lsm, fentry, fexit, raw_tracepoint, tracepoint, perf_event, struct_ops |
| Attach risk | 60 per match | security_*, commit_creds, prepare_kernel_cred, execve, openat, vfs_read/write, tcp_connect, bpf_*, ptrace, process_vm_readv |
| Loader: exe in /tmp | 40 | Loader binary in /tmp, /var/tmp, /dev/shm |
| Loader: deleted exe | 30 | Loader binary marked (deleted) |
| Loader: not in dpkg | 20 | Binary not tracked by dpkg |
| Loader: root without unit | 25 | euid=0 and no systemd unit |
| Loader: suspicious comm | 35 | bash/sh/python/perl/node/curl/wget |
| Map type risk | 30 per map | prog_array, array_of_maps, hash_of_maps, ringbuf, user_ringbuf, perf_event_array, sockmap, sockhash, devmap, cpumap, xskmap, task_storage, inode_storage, sk_storage |

Total clamped to 150.

## Severity Thresholds

| Score Range | WatchState | Audit Finding |
|-------------|------------|---------------|
| 0–69 | SURVEILLANCE | INFO (first observation only) |
| 70–99 | ALERT_HIGH | HIGH |
| 100–150 | ALERT_CRITICAL | CRITICAL |

## Systemd Whitelist Rules (hardcoded in classifier.py)

Program must match ALL four conditions:

1. **Name** in `{sd_fw_ingress, sd_fw_egress, sd_devices}`
2. **Prog type** matches: `cgroup_skb` for sd_fw_*, `cgroup_device` for sd_devices
3. **Attach type** matches: `cgroup_ingress`/`cgroup_egress` for sd_fw, `cgroup_device` for sd_devices
4. **Loader** is systemd: exe resolved to paths in `bpf.systemd_loader_paths` (default: `/usr/lib/systemd/systemd`, `/lib/systemd/systemd`) OR systemd unit is `systemd.service`/`init.scope`

## Non-Promotable Program Types

Certain program types **cannot** be promoted to baseline even manually:
`lsm`, `kprobe`, `kretprobe`, `fentry`, `fexit`, `raw_tracepoint`, `struct_ops`

Also blocked: any program that references a `prog_array` map (can dispatch to other programs dynamically).

## Key Source Files

| File | Lines | What's in it |
|------|-------|-------------|
| `src/secmon/bpf/audit.py` | 149 | `run_bpf_audit()` — scan, classify, watchlist, findings |
| `src/secmon/bpf/watcher.py` | 227 | `run_bpf_watch()` — refresh + escalation loop + delta detection |
| `src/secmon/bpf/classifier.py` | 264 | Risk scoring, systemd whitelist, `can_promote_program()` |
| `src/secmon/bpf/collector.py` | 296 | Full bpftool JSON inventory |
| `src/secmon/bpf/identity.py` | 60 | Stable key generation |
| `src/secmon/bpf/watchlist.py` | 190 | State helpers, `promote_to_baseline()`, `clear_watchlist_entry()` |
| `src/secmon/bpf/provenance.py` | 166 | /proc loader forensics |
| `src/secmon/bpf/models.py` | 180 | Data classes, WatchState enum |