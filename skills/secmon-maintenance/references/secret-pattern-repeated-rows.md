# Secret Pattern: "Repeated Rows" Interpretation

A common confusion: a secmon-tick alert shows multiple rows of the same `secret_pattern` finding at once, e.g.:

```
🟠 HIGH — Audit (Secret Pattern): Secret material pattern in /root/.../file1.env
🟠 HIGH — Audit (Secret Pattern): Secret material pattern in /root/.../file2.yaml
🟠 HIGH — Audit (Secret Pattern): Secret material pattern in /root/.../script.sh
```

**This is NOT a bug or duplicate dedup failure.** Each row is a **different file** that matched one of the API-key / PEM / AWS-secret patterns. The tick script lists every finding as a separate row. The dedup store (`/var/lib/secmon/state.json`) prevents the SAME file from being re-dispatched within the dedup window (6h for `audit:` findings), but different files are always distinct alerts.

## When the user says "repeated items"

They mean multiple rows of the same *finding type* (e.g., `secret_pattern`) in one tick. The fix is to:

1. Identify which files are legitimate infrastructure (expected API keys, config files) vs false positives (env-var references, placeholder templates).
2. Add legitimate files (or their parent directories) to `secret_exclude_paths` in `~/.hermes/secmon/config.yaml`.
3. The current `_is_excluded()` function supports **directory-prefix matching** — adding `/root/.my-tool` excludes `/root/.my-tool/config.env` and all subfiles. (Previously used exact-match-only, but the prefix-matching fix was committed.)
4. Remove stale entries from the exclude list when a component is purged (e.g., old Mnemosyne paths).

## Directory-prefix exclusion verified

The current code in `threat_intel.py`:

```python
def _is_excluded(fp: str, exclude_paths: set[str]) -> bool:
    if fp in exclude_paths:
        return True
    for ex in exclude_paths:
        if fp.startswith(ex + "/") or fp.startswith(ex + os.sep):
            return True
    return False
```

So `secret_exclude_paths: - /root/.memory-tencentdb/plugin/scripts` covers both `install-hermes-plugin-v2.sh` and `install-openclaw-plugin-v2.sh` underneath it.

## Verifying after adding exclusions

```bash
timeout 60 /root/.hermes/plugins/secmon/venv/bin/secmon \
  --tick --config /root/.hermes/secmon/config.yaml
# Empty output = no findings
```

## Clean stale entries when purging a component

When removing a component entirely (e.g., Mnemosyne), also remove its now-nonexistent paths from `secret_exclude_paths`. The paths point to files that no longer exist, so they're harmless but confusing during maintenance.