# README Sync Audit — Full Procedure

When the README has fallen behind the codebase, use this systematic diff-based audit to identify every stale section.

## Procedure

### 1. Find the last README update

```bash
cd ~/.hermes/plugins/secmon
git log -1 --format="%H %ai %s" -- README.md
```

This gives you the commit hash and date. Any commit after that is a potential README gap.

### 2. Collect all changes since then

```bash
# Get the commit range
git log --oneline <last-readme-hash>..HEAD

# Exclude chore commits (skill syncs, formatting) — they don't change behavior
# Focus on feat/fix/refactor commits
```

### 3. For each non-chore commit, identify what changed

```bash
git log --stat <hash>..HEAD
git diff <hash>..HEAD -- . ':!README.md' ':!tests/' ':!skills/'
```

Key categories to look for:
- **New config options** — any `.get()` call in `src/` for a new whitelist key or threshold
- **New CLI flags or modes** — changes to `__main__.py` or `modes/`
- **Deleted modules** — files removed from `src/`
- **Behavior changes** — check logic changed (e.g., new auto-suppression, new matching)
- **Path changes** — config/data/script paths moved

### 4. Cross-reference against README sections

| README section | What to check |
|---|---|
| Features list | Check counts match (realtime checks, metrics, layers). Remove deleted features. |
| Installation | Verify config paths, required steps, directory names match actual `install.sh` |
| CLI usage table | Every mode/flag in `--help` should be documented |
| Config priority | Search path must match `config.py` |
| Audit exclusion table | Every `whitelist.*` key in code must have a row. Check examples match `config.yaml.example` |
| BPF watcher section | CLI commands, check IDs, config schema must match actual code |
| Outbound whitelist | Supported match fields (`cidr`, `ip`, `process`, `parent_process`) must match `outbound.py` |
| Config immutability | If CRITICAL_FILES tracking exists, document it |
| Self-protection / tick-gap | If module was deleted, replace with removal rationale |
| Logs and state | Paths must match `config.py` defaults |
| Project layout | Directory tree must match actual repo structure |

### 5. Also check `config.yaml.example`

The example file is the canonical reference for users. Every new config key in `src/` must appear in the example. Use placeholder values distinct from production (e.g., `own_ip: 203.0.113.1`).

```bash
# Check the example wasn't forgotten
git diff HEAD -- config.yaml.example
```

### 6. Verify the diff is clean

Before committing, review the full README diff:

```bash
git diff --stat README.md        # file changed, + lines / - lines
git diff README.md               # full content review
```

## Real example from this session

After 18 non-chore commits (Jul 7–16), the README had:
- 7 stale references to `/etc/secmon/` — should be `~/.hermes/secmon/`
- Self-protection listed in features but module was deleted
- Tick-gap auto-detection section referenced deleted code
- `proc_hollow_exclude_comms` example missing `unattended-upgr`
- `parent_process` not documented in outbound whitelist
- Config immutability not documented
- `secret_exclude_paths` prefix matching not noted

The fix: 44 lines added, 19 removed across all sections.