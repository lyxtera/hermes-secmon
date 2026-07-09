# Concurrent State-File Race (Tick Gap Root Cause)

## The Pattern

When two `secmon` processes (e.g. `--tick` and `--audit`) independently
read `/var/lib/secmon/state.json`, modify it in memory, then write it back,
the **last writer wins** — silently reverting any changes made by the first.

## What Happened

At midnight UTC, three cron jobs fire near-simultaneously:

| Time (UTC) | Job | Event |
|-----------|-----|-------|
| 00:00:21 | secmon-tick starts | Reads state (last_tick=23:45) |
| 00:00:21 | Internal 6h deep audit fires inside `run_tick()` | Stretches runtime |
| 00:01:40 | secmon-audit starts | Reads **stale** state (tick hasn't saved yet) |
| ~00:02:00 | Tick finishes, saves state | last_tick=00:00:21 written |
| ~00:02:01 | Audit finishes, saves state | **Overwrites** — last_tick reverts to 23:45 |
| 00:15:21 | Next tick | Sees 30m gap → CRITICAL `self_prot:missed_tick` |

## Tell-Tale Signs

- **Tick gap alert** at exactly `:15` or `:45` positions after a 6h boundary
- **state.json.corrupt.*`** backups from `00:01` (first audit run on July 4)
- **last_tick** in state is 30 min older than expected
- **Cron output** shows both jobs ran fine ("ok" status) — no crash evidence

## The Fix: `fcntl.flock()` Advisory Locking

Applied in `src/secmon/state.py`:

```python
import fcntl
from contextlib import contextmanager

@contextmanager
def _state_lock(state_path: str, exclusive: bool = False):
    lock_path = state_path + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(lock_fd, mode)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

def load_state(...):
    with _state_lock(spath, exclusive=False):  # shared — concurrent reads OK
        ...

def save_state(...):
    with _state_lock(spath, exclusive=True):   # exclusive — blocks all readers
        ...
```

- **Shared lock** (`LOCK_SH`) on reads — concurrent readers pass through
- **Exclusive lock** (`LOCK_EX`) on writes — blocks readers; only one writer at a time
- Lock released when fd closes (exit, crash, or context manager exit)
- `.lock` file persists on disk — kernel tracks the lock on the inode; no stale-lock problem

## Verification

After applying the fix:
```bash
# Run both concurrently (test)
secmon --tick &
secmon --audit &
wait
# Check state — last_tick should be recent, not reverted
python3 -c "
import json
d = json.load(open('/var/lib/secmon/state.json'))
print('last_tick:', d['monitor_state']['last_tick'])
"
```

State tests still pass:
```bash
pytest tests/test_state.py -v --tb=short
```

## Key Insight

The race is invisible in single-instance testing. It only surfaces under
production cron concurrency. The fix must go at the **state access layer**
(`load_state`/`save_state`), not in individual cron job logic — any future
mode that touches state needs the same protection.