# Secmon test-suite pitfalls — full session detail (2026-08-09)

Session: delegated port_removed transition-dedup fix to the Pi coding agent
(`pi -p`, openrouter, `--no-extensions`), then ran the suite until green.
Result: **192 passed, 4 skipped**; `python -m secmon --check` exits 0.
This file records the machine-specific gotchas and the exact evidence trail.

## Env pollution — SECMON_* from /root/.hermes/.env

Sourcing `/root/.hermes/.env` (needed for OPENROUTER_API_KEY) does `set -a`, which
exports EVERYTHING in that file, including `SECMON_OWN_IP` (and possibly
SECMON_CONFIG_PATH / SECMON_ANOMALY_*). `load_config` runs `_apply_env()` AFTER
the yaml merge, so env values win.

Evidence: `tests/test_config.py::test_load_yaml_config` writes
`whitelist.own_ip: 10.0.0.1` to a tmp yaml and asserts it back — got the machine's
real IP (213.7.225.107) instead. With `env -u SECMON_OWN_IP ...` it passes.

Lesson: after sourcing .env in a shell, run ANY downstream tooling (pytest, other
CLIs) with the SECMON_* vars unset, or re-check `env | grep SECMON` first.

## Live-config bleed into the cfg fixture

conftest `cfg` fixture: `load_config(overrides={...})` with no path → candidate
list finds `~/.hermes/secmon/config.yaml` (exists on this box) → deep-merge.
Consequences observed:

| Test | Live-config value that broke it | Test-local fix |
|------|--------------------------------|----------------|
| `test_outbound_whitelist_skips_telegram` | `whitelist.outbound_destinations` = process-only entries (git-remote-*, hermes, rpi-connectd) — list deep-merge REPLACES default Telegram CIDR entries | Set `cfg["whitelist"]["outbound_destinations"] = [{"cidr": "149.154.160.0/20", "process": "hermes"}, {"cidr": "91.108.56.0/22", "process": "hermes"}]` in the test |
| `test_compliance_debsums_critical` | `hardening.skip_debsums_check: True` → NC-10 branch skipped | `cfg.setdefault("hardening", {})["skip_debsums_check"] = False` in the test |

Note: on a dev box without `/root/.hermes/secmon/config.yaml` these tests pass —
the bleed is machine-specific but permanent on THIS server.

## Time-drift test rot

- conftest `frozen_time` = 2026-06-29, patches `secmon.utils.utcnow`,
  `secmon.baseline.utcnow`, `secmon.anomaly.utcnow`, `secmon.alerts.utcnow`,
  `secmon.metrics.utcnow`, `secmon.utils.utcnow_iso` — **NOT**
  `secmon.state.utcnow`.
- `record_sample` (baseline.py) appends a sample stamped 2026-06-29 (frozen), then
  calls `trim_daily_stats` (state.py) which uses REAL clock `utcnow()` from
  `secmon.state.utcnow`. Real clock 2026-08-09 → cutoff 2026-07-10 → sample
  (06-29) trimmed → `len(daily_stats) == 1` fails with 0.
- `test_trim_daily_stats` hardcodes `"2026-06-29T00:00:00Z"` as the "recent" entry
  → also older than the 30-day cutoff → both entries trimmed → `len == 1` fails.

Fixes (test-only, robust to clock):
```python
with patch("secmon.state.utcnow", return_value=frozen_time):
    assert record_sample(state, cfg, metrics)
...
new = {"timestamp": datetime.now(timezone.utc).isoformat(), **{k: 1 for k in METRIC_KEYS}}
```

## `secmon --check` writes state.json

`python -m secmon --check --config <path>` runs `run_check` = threat checks +
audit pipeline + **`save_state()`**. Observed: `/var/lib/secmon/state.json` mtime
advances on every run and a daily snapshot is written to
`/var/lib/secmon/snapshots/state.<date>.json`.

If a task forbids touching state.json but mandates `--check`, the mandate wins and
the write happens — verify afterwards that it was a benign round-trip:
```python
import json
cur = json.load(open('/var/lib/secmon/state.json'))
snap = json.load(open('/var/lib/secmon/snapshots/state.<today>.json'))
assert cur == snap                # identical → clean load→save
```
Additionally, running `--check` with newly-edited audit code migrates LIVE state
(e.g. adds `audit_baseline.reported_removed_ports: []` via setdefault). Benign but
real — note it in the report. Bonus: the migrated live state is itself evidence —
`s last_audit_findings` showed `trend_resolved: RESOLVED [HIGH] Listening port
removed: 30141`, proving the fix live.

## Proving pre-existing failures (stash two-file trick)

```bash
git stash push -- src/secmon/audit/network.py tests/test_push_95.py   # ONLY your files
<pytest the failing tests>   # same failures on HEAD versions → pre-existing
git stash pop                # restores, no conflicts (files untouched in between)
```
In this session this proved 4 of the 5 "failures" were pre-existing AND revealed
the 5th (test_load_yaml_config) disappeared with a clean env — i.e. it was my own
env pollution, not the repo.

## Pi delegation notes that mattered

- `pi -p "$(cat /tmp/prompt.txt)" --provider openrouter --no-extensions`;
  `--no-extensions` is required (settings.json webui extensions crash pi 0.73.1).
- Run in background with `timeout 600 pi ... > log 2>&1`; the log stays 0 bytes
  while pi works (output buffered until exit) — do NOT poll it as a hang signal.
- Exit code of the `timeout` wrapper (`$?` after `PIPESTATUS`) is the success signal.
- Verify pi's narrative yourself: it reported "184 passed, 4 skipped, 5 failed"
  with a plausible excuse for each; the real picture (clean env + hypothesis fix +
  4 rot fixes) only emerged from independent runs.