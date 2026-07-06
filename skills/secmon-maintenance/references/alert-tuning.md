# Alert Tuning Reference

False positive patterns and fixes discovered during secmon maintenance.

## SUID Binary False Positives

**Symptoms:** `Unexpected SUID: /usr/bin/pkexec`, `Unexpected SUID: /usr/bin/umount`

**Root cause:** `DEBIAN_SUID_WHITELIST` in `src/secmon/audit/file_integrity.py` hardcodes
`/bin/*` paths but Debian 12 usrmerge migrated these to `/usr/bin/`. The whitelist
also doesn't include all legitimate system SUID binaries (e.g., `pkexec` from polkit).

**Fix:** Add missing paths to `DEBIAN_SUID_WHITELIST` — include both `/bin/` and `/usr/bin/` variants:

```python
DEBIAN_SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",      # ← add
    "/usr/bin/mount",        # ← add
    "/usr/bin/umount",       # ← add
    "/bin/mount",            # keep for legacy systems
    "/bin/umount",           # keep for legacy systems
    "/bin/su",               # keep for legacy systems
}
```

**Verify legitimate SUID binaries:**
```bash
find /usr/bin -perm -4000 -type f | sort
```

## Fail2ban Threshold Tuning

**Symptoms:** `SSH ban burst: X new bans` alerts firing every 15 min tick.

**Root cause:** `fail2ban_min_new_bans: 5` is too low for a server under constant
SSH brute force (common for internet-facing servers — 180+ bans/day).

**Fix:** Raise threshold in `/etc/secmon/config.yaml`:

```yaml
realtime:
  fail2ban_min_new_bans: 50       # default 5 → 50
  invalid_user_threshold: 10      # optional increase
  kernel_error_threshold: 3
  ssh_brute_force_threshold: 10
```

**Note:** `/etc/secmon/config.yaml` requires `sudo` to edit.

## Stale Cache After Fix

**Symptoms:** Alert keeps firing even after patching the whitelist.

**Root cause:** `suid_cache` in `/var/lib/secmon/state.json` still holds the old
baseline — `file_integrity.py` writes `suid_cache` on every audit run, but the
whitelist check happens *before* the cache is updated in the same run.

**Fix:** Reset state:
```bash
sudo secmon --reset-baseline
# or manually:
sudo sed -i 's/"suid_cache":\[[^]]*\]/"suid_cache":[]/' /var/lib/secmon/state.json
```

## Audit Output Formatting

The `format_audit_markdown()` function in `src/secmon/output.py` produces
output that gets delivered to Telegram. **The delivery pipeline determines
what formatting renders correctly.** See SKILL.md §5 for the full
pipeline comparison.

### Agent Pipeline (`no_agent: false`)

Full Markdown rendering including:
- `**bold**`, `_italic_`, `` `code` ``
- `| table |` with `:---:` alignment
- `> blockquote`, `## headings`, `||spoiler||`

Use `**bold**` in code (standard Markdown) — the agent converts to Telegram entities.

### Plain-Text Pipeline (`no_agent: true`)

Only Telegram Bot API MarkdownV2 parses formatting:
- `*bold*` ✅, `_italic_` ✅, `` `code` `` ✅
- `| pipe tables |` ❌ (raw text)
- `> blockquote` ❌ (raw text)
- `__underline__` ❌ (raw text)
- `||spoiler||` ❌ (raw text)
- `## headings` ❌ (raw text)

Use `*bold*` instead of `**bold**` for this pipeline. Compact bullet lists
are the most reliable format.

### Common Mistake

Claiming Telegram "does not support tables" is wrong. The agent pipeline
renders tables correctly. The limitation is specific to plain-text cron
delivery (`no_agent: true`). Always check which pipeline the cron job uses
before deciding the format.

## Severity Bar Formatting

The summary bar at the top of audit output should include severity labels:

```text
🔴 1 CRIT · 🟠 2 HIGH · 🟡 1 MED · 🔵 3 LOW · Σ 7 risk 18
```

Not bare counts without labels. The user corrected this.

## Guidance Templates

The `_render_guidance()` function can produce double spaces in actions
like `"Search within  for"` — this is a template formatting bug where
a path-detail placeholder is empty but the surrounding spacing remains.
Keep an eye out for these when reviewing output.

## Pending Fixes (from this session)

These were identified during analysis but deferred:

1. **Exclude `state-snapshots/` from secret scanning** — Hermes backup
   snapshots contain config files with API keys but are local archives,
   not exposed secrets. Eliminates 2 HIGH alerts.
2. **Filter Trends bookkeeping** — `layer_count`, `trend_persistent`,
   `trend_new` are internal tracking IDs, not security findings. Filter
   them from user-facing audit output.
3. **Whitelist `systemd_timers` persistence changes** — systemd timers
   change normally with service updates. Flag as expected fluctuation.
4. **Fix guidance template double-space** — `"Search within  for"`
   has extra space before the word "for".

## Related

- File: `src/secmon/audit/file_integrity.py` — SUID whitelist location
- Config: `/etc/secmon/config.yaml` — threshold values
- State: `/var/lib/secmon/state.json` — cached baselines
- Output: `src/secmon/output.py` — Telegram formatting
- Tick alerts: `src/secmon/alerts.py` — `dispatch()` function
