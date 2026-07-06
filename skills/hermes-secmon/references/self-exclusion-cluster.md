# Self-Exclusion Process Cluster

## Problem

The audit's process forensics layer (L3) scans `/proc/*/maps` for anonymous executable mappings (`proc_hollow_anon`, `proc_hollow_deleted`, `proc_hollow_rwx`). The Hermes gateway itself is a Python process that creates JIT RWX mappings — without exclusion, every audit flags its own parent process chain as suspicious.

Hardcoding PIDs doesn't work (they change on restart). Hardcoding comm names is fragile (Python/bash have many legitimate uses).

## Solution: Auto-Discovered Process Cluster

Implemented in `src/secmon/audit/process.py` in the hollow-check section.

### Phase 1 — Seed Detection

Scan all `/proc/*/cmdline` for the string `"secmon"` (case-insensitive). Any process whose command line contains this string is added to a seed set.

```python
for pid in proc_pids:
    cmdline = open(f"/proc/{pid}/cmdline", "rb").read()...
    if "secmon" in cmdline.lower():
        secmon_cluster.add(pid)
```

This catches:
- The `secmon` CLI binary
- `audit.sh` / `tick.sh` bash processes that reference paths like `~/.hermes/plugins/secmon/`
- Python processes running secmon code

### Phase 2 — Walk Parent Chain

For each seed PID, walk up via `/proc/*/stat` field 4 (ppid) until PID 1 or a loop. Union all PIDs encountered into the cluster.

```python
def _parent_chain(pid: int) -> set[int]:
    chain = set()
    while pid > 1:
        chain.add(pid)
        stat = open(f"/proc/{pid}/stat").read()
        m = re.match(r"\d+ \(.+?\) \S (\d+)", stat)
        pid = int(m.group(1))
        if pid in chain: break  # loop guard
    return chain
```

This catches the entire ancestry — e.g. `secmon --audit` → `bash (audit.sh)` → `hermes gateway (PID 5397)` → `systemd`.

### Phase 3 — Walk Child Chain

Scan all `/proc/*/stat` for ppid matching any cluster PID. Add matching children to the cluster.

```python
for pid in proc_pids:
    stat = open(f"/proc/{pid}/stat").read()
    m = re.match(r"\d+ \(.+?\) \S (\d+)", stat)
    if m and int(m.group(1)) in secmon_cluster:
        secmon_cluster.add(pid)
```

This catches transient worker processes secmon may spawn.

### Phase 4 — Exclude by Comm Name

Merge well-known secmon-related comm names into the exclusion comm set:

```python
exclude_comms |= {"secmon", "secmon-audit", "secmon.sh", "audit.sh"}
```

This covers dynamically-spawned processes where `/proc/*/maps` might be read before the cmdline scan sees them.

### Phase 5 — Apply

All cluster PIDs are added to `exclude_pids`. The hollow-check loop skips:
- `if pid in exclude_pids: continue`
- `if comm_name in exclude_comms: continue`

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Match `"secmon"` in full cmdline, not just binary name | Script paths like `~/.hermes/plugins/secmon/venv/bin/` or cwd references contain the string; binary name alone misses cron-launched bash wrappers |
| Walk parent chain, not just children | The Hermes gateway (parent) is the process with RWX maps, not the secmon child. Without upward walk, only the leaf audit process is excluded |
| Union-based, not list-based | Processes can belong to multiple clusters; dedup is free |
| Guard against PID-1 and loops | `/proc/*/stat` ppid can form cycles (zombie/inherit edge cases); loop break prevents infinite walk |
| No state persistence | Cluster is rebuilt fresh per audit run — PIDs are ephemeral |

## When to Extend

Add a new comm name to the auto-exclude set when secmon runs via a wrapper that doesn't have `"secmon"` in its cmdline. Example:

```python
exclude_comms |= {"secmon", "secmon-audit", "secmon.sh", "audit.sh", "new-wrapper-name"}
```

## Verification

Run the audit and check the CRITICAL count drops to 0 for proc_hollow_anon:

```bash
secmon --audit | grep -c '🔴.*CRITICAL'
```

Previous findings from the same processes show as `trend_resolved` in the ℹ️ INFO section on the next run.
