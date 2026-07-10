# Self-Protection Module — Removed

**Commit:** N/A (deleted in-place from `src/secmon/checks/self_protection.py`)
**Date:** 2026-07-10

## What was removed

The entire `self_protection.py` module was deleted from `src/secmon/checks/` and unregistered from `checks/__init__.py`. It checked:

| Check | Severity | Reason for removal |
|-------|----------|-------------------|
| Tick gap detection | CRITICAL | False positives every ~6h — see below |
| Cron/schedule integrity | CRITICAL | Trivially bypassable by root |
| Symlink integrity | CRITICAL | Trivially bypassable by root |
| Code file hashing/tamper | CRITICAL | Trivially bypassable by root |
| Config tamper detection | HIGH | Trivially bypassable by root |
| Permission drift | MEDIUM | Trivially bypassable by root |

## Why tick-gap detection was the actual problem

### Root cause chain

1. `secmon-tick` runs every 15 min via Hermes cron
2. At 6h boundaries, `run_tick()` runs a deep audit that can take >15 min
3. The Hermes cron scheduler (`scheduler.py` line 3514) **skips overlapping runs** of the same job ID — if `secmon-tick` is in `_running_job_ids`, the `:15` run is silently dropped
4. The `:30` tick fires, reads `last_tick` from state file → sees a 30-min gap → CRITICAL alert

### What replaced it

The `last_tick` timestamp is still persisted, but only for record-keeping — no alert is generated from it. `run_tick()` in `tick.py` now saves `last_tick` at the very start of the function:

```python
ms = state.setdefault("monitor_state", {})
ms["last_tick"] = utcnow_iso()
save_state(cfg, state)
```

This ensures the state file always has a recent timestamp even if the tick takes 20+ minutes.

### Why not just fix the gap threshold?

The fundamental assumption that "a gap in ticks means something is wrong" doesn't hold for a scheduled system where:

- The cron scheduler itself may skip runs (Hermes's in-process scheduler is not a real-time system)
- Long-running checks (deep audit, BPF collection) can overlap the next scheduled slot
- A root-level attacker can just stop the cron, delete state, or kill the process — none of this module stops them

The self-protection module provided a false sense of security for checks that any root-level actor can trivially bypass. Removing it eliminates the primary source of daily false CRITICAL alerts.
