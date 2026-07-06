---
name: secmon-maintenance
description: Maintain and tune the secmon security monitor plugin - investigate alerts, debug false positives, tune thresholds, and commit fixes to the public repo.
triggers:
  - secmon alert investigation
  - false positive debugging in security monitors
  - tuning fail2ban or anomaly thresholds
  - syncing secmon with remote repo
  - unexpected SUID or similar secmon alerts
  - audit report review and findings triage
  - investigating port_removed / secret_pattern / persist_modified findings
  - applying security upgrades
  - config whitelist tuning (secret_exclude_paths, ignored_ports)
  - suppressing INFO/LOW findings from audit report output
  - user says "I don't want to see X level issues" in audit output
  - deploying or updating cron delivery scripts (audit.py / daily.py / tick.py)
  - cron script location or path blocked outside ~/.hermes/scripts/
  - empty table / zero-findings notification cleanup
---

# Secmon Maintenance

Recurring workflow for maintaining secmon (security monitor plugin for Hermes Agent). The user runs secmon in beta testing phase and prefers fixing code at source over local workarounds.

## Cron Delivery Script Lifecycle — Deployment Model

**All cron delivery scripts (audit.py, daily.py, tick.py) live in the plugin repo** under `scripts/` so they're git-tracked. They get **deployed** to `~/.hermes/scripts/secmon/` by the install/deploy mechanism — never placed manually.

### Why not symlinks or absolute paths?

Hermes cron's `_run_job_script()` in `cron/scheduler.py` validates that scripts **must** resolve within `HERMES_HOME/scripts/` (security guard against path traversal/injection). Absolute paths to the plugin dir, symlinks to plugin dir — all blocked at runtime. The only portable option is to copy the files there.

### Deployment via install.sh

`scripts/install.sh` does:
```bash
HERMES_SCRIPTS_DIR="${HOME}/.hermes/scripts/secmon"
mkdir -p "${HERMES_SCRIPTS_DIR}"
cp "${SOURCE_DIR}/scripts/audit.py" "${HERMES_SCRIPTS_DIR}/audit.py"
cp "${SOURCE_DIR}/scripts/daily.py" "${HERMES_SCRIPTS_DIR}/daily.py"
cp "${SOURCE_DIR}/scripts/tick.py" "${HERMES_SCRIPTS_DIR}/tick.py"
chmod +x "${HERMES_SCRIPTS_DIR}"/*.py
```

Then registers cron with relative paths (`secmon/audit.py`) which resolve under `~/.hermes/scripts/`.

### Post-pull update

After `git pull`, run `sync-cron.sh` to re-deploy:
```bash
bash ~/.hermes/plugins/secmon/scripts/sync-cron.sh ~/.hermes/plugins/secmon
```

### Cron job registration (no-agent mode)

Jobs use `no_agent: true` so stdout from the script is delivered verbatim. When the script calls the Telegram Bot API directly (`sendRichMessage`), set `deliver: local` so Hermes doesn't double-deliver:
```bash
hermes cron add "0 */6 * * *" --no-agent \
  --script secmon/audit.py --name secmon-audit --deliver telegram
```

### Zero-findings = silent exit (hard rule)

Every delivery script **must** exit silently when there are no findings to report. An empty table with no data rows is noise:

```python
# At the end of parsing — if nothing to report, exit 0 (no output)
total = sum(len(v) for v in sections.values())
if total == 0:
    sys.exit(0)  # silent — no message sent
```

This applies to all three jobs: tick, audit, daily. Empty stdout = Hermes sends nothing. Non-empty stdout = Hermes delivers it.

Also apply this in tick.py for routine SSH suppression — after filtering out routine patterns, if no reportable findings remain, `sys.exit(0)`.

### Scripts that call Telegram API directly

When a script sends via `sendRichMessage` (Pipeline C), it needs:
- `telegramify-markdown` installed in the **Hermes venv** (`/usr/local/lib/hermes-agent/venv/bin/pip install telegramify-markdown`)
- `TELEGRAM_BOT_TOKEN` sourced from `/root/.hermes/.env`
- Hardcoded `CHAT_ID` for the destination
- `deliver: local` on the cron job (to avoid double delivery)
- `sys.exit(0)` on no-findings (before any send attempt)

### Key files

| Location | Purpose |
|----------|---------|
| `~/hermes/plugins/secmon/scripts/audit.py` | Source (git-tracked) |
| `~/hermes/plugins/secmon/scripts/daily.py` | Source (git-tracked) |
| `~/hermes/plugins/secmon/scripts/tick.py` | Source (git-tracked) |
| `~/hermes/plugins/secmon/scripts/sync-skills.sh` | Sync agent-updated skills → repo (cron-fed) |
| `~/.hermes/scripts/secmon/{audit,daily,tick}.py` | Deployed copy (not git-tracked) |
| `~/.hermes/scripts/secmon/sync-skills.sh` | Deployed sync script |
| `~/hermes/plugins/secmon/scripts/install.sh` | Deploys scripts + registers cron |
| `~/hermes/plugins/secmon/scripts/sync-cron.sh` | Re-deploys after git pull |
| `~/hermes/plugins/secmon/skills/` | Bundled skills source (git-tracked) |
| `~/.hermes/skills/devops/{hermes-secmon,secmon-maintenance,secmon-audit-output-tuning}/` | Deployed skills (agent-editable, auto-indexed) |

## Important User Rule — Commit Discipline

> **Never commit or push anything until the user confirms the task is fully done.**
> Make all changes locally, test/verify the fix, then wait for explicit "commit and push" instruction.
> The user explicitly corrected this as a hard rule — violating it loses trust.

## Post-Feature Checklist — README Completeness

**After adding new config options to the code, always update the README and config.yaml.example.** If a whitelist key, threshold, or config option exists in the code but isn't in the README's exclusion tuning table or config example, users won't know it exists.

**Checklist:**
- Does the new config option appear in the README's **Audit exclusion tuning** table?
- Does it appear in `config.yaml.example`?
- If it's a whitelist key, does it appear in the `whitelist` section examples?

**Real example from this session:** `whitelist.port_removed` (static port suppression) was added to `network.py` but never made it to the README's exclusion table. The process-name variant (`port_removed_processes`) was documented in the triage reference, but the static port list was not — discover this by diffing `git diff HEAD~26..HEAD -- src/` for new config `.get()` calls and cross-referencing against the README.

## Workflow Pattern

### 1. Sync Secmon with Remote
```bash
cd ~/.hermes/plugins/secmon
git fetch
# If remote was force-pushed (divergent branches):
git reset --hard origin/main
# Then reinstall:
sudo ./scripts/install.sh
```

**Pitfall:** `git pull` fails with "divergent branches" if remote was force-pushed. Use `git reset --hard origin/main` instead.

### 2. Investigate Alerts
When secmon triggers false positives (e.g., "Unexpected SUID" alerts):

1. **Read the source code** - Find the check implementation:
   ```bash
   grep -r "unexpected_suid\|SUID" ~/.hermes/plugins/secmon/src/secmon/ --include="*.py" -l
   ```

2. **Identify root cause** - Common issues:
   - Hardcoded whitelists missing legitimate binaries
   - Path mismatches due to OS changes (e.g., Debian 12 usrmerge: `/bin/` → `/usr/bin/`)
   - Threshold too sensitive for the environment

3. **Check if false positive** - Verify the alert is not a real threat:
   ```bash
   # For SUID alerts:
   ls -la /path/from/alert
   # Check if it's a legitimate system binary
   ```

### 3. Fix False Positives

**Code fixes (preferred over config workarounds):**
- Patch the source code in `~/.hermes/plugins/secmon/src/secmon/`
- Commit and push to public repo so all users benefit
- Example: Adding missing paths to `DEBIAN_SUID_WHITELIST` in `file_integrity.py`

**Config tuning (for thresholds):**
- Edit `/etc/secmon/config.yaml`
- Use `sudo` to edit (file is in protected system path)
- Example: Increase `fail2ban_min_new_bans` from 5 to 50 for busy servers

### 4. Verify with User — Never Commit Until Confirmed ⚠️

**Hard rule: all changes stay local until the user gives explicit "commit and push" instruction.**

```bash
# Step 1: Make changes locally
cd ~/.hermes/plugins/secmon
# ... edit files ...

# Step 2: Show the diff to the user (don't commit yet)
git diff

# Step 3: Test the fix (trigger audit/tick job)
# Use cronjob tool to trigger the secmon-audit job
# The user will see the result in Telegram

# Step 4: WAIT for user confirmation before any git operations
# Only run when user says "commit and push":
git add <changed-files>
git commit -m "fix(audit): <description>"
git push origin main
```

**Pitfall:** Never assume user approval. A "looks better" or "works now" is NOT a "commit and push" signal. Wait for the explicit instruction.

### 5. Understand the Cron Delivery Pipeline

**CRITICAL — this determines what formatting actually renders in Telegram.**

The Hermes Telegram adapter (`adapter.py`) has two message-sending paths:

1. **Rich path** (Bot API 10.1+ `sendRichMessage`): Sends raw agent Markdown directly. Used when `_should_attempt_rich()` returns True. **Tables render natively.**

2. **Legacy path** (`sendMessage` with `parse_mode=MarkdownV2`): Before sending, the adapter runs `_wrap_markdown_tables(text)` (line 6062), which `convert_table_to_bullets` (line 228) — this **actively converts | table | syntax into bullet points** because MarkdownV2 doesn't recognize pipe tables.

The switch is controlled by `telegram.extra.rich_messages: true` in config.

#### Pipeline A: Agent Delivery (`no_agent: false`) — attempts tables but unreliable
- Script stdout → injected as agent context → agent processes → sends via `sendRichMessage`
- **Tables sometimes work** through the rich message path
- **Problem:** the agent may "helpfully" reformat tables into bullet points even with strict prompts
- Multiple iterations with "Do NOT reformat, do NOT wrap in code blocks" still failed
- Cost: uses LLM tokens every run
- **Not recommended** for reliable table output

#### Pipeline B: Plain-Text Delivery (`no_agent: true`) — legacy, only `*bold*`/`` `code` `` survive
- Script stdout captured raw → `_wrap_markdown_tables` converts tables to bullets → sent as plain text
- **Tables do NOT work** — raw | and dashes
- Only `*bold*`, `_italic_`, `` `code` `` survive
- Zero token cost
- **Replaced by Pipeline C** for secmon jobs — no jobs currently use this pipeline

#### Pipeline C: Direct Telegram API (`no_agent: true` + `deliver: local`) — structured blocks ✅
- **The ONLY reliably working approach for tables + headings + dividers in cron output.**
- Cron runs the script with `no_agent: true` and `deliver: local`
- Script captures the command output, then sends via Telegram Bot API `sendRichMessage`
- Uses `telegramify-markdown.richify(md, mode="html")` to convert Markdown into structured Rich HTML blocks (`<h1>`, `<h2>`, `<table>`, `<hr/>`)
- No Hermes adapter touches the message — no table-to-bullet conversion
- Zero token cost (no LLM involved)
- **Good for:** audit (every 6h), daily digest (once/day) — any job requiring rich formatting

**Two sendRichMessage approaches (both work, structured blocks preferred):**

**Approach 1 — Structured blocks via `telegramify-markdown` (recommended):**
```python
from telegramify_markdown import richify

md = f"""# 🔍 Secmon Audit
_{timestamp}_

---

## 🟠 HIGH — 2 findings

| Finding | Check | Action |
| :--- | :--- | :--- |
| Secret pattern | `secret_pattern` | Search credentials |

---

`secmon --audit`
"""

rich_msg = richify(md, mode="html")
payload = json.dumps({
    "chat_id": "557337160",
    "rich_message": rich_msg.to_dict()
})
# POST to: https://api.telegram.org/bot<TOKEN>/sendRichMessage
```

This produces `<h1>`, `<h2>`, `<table>`, `<hr/>` — all render as proper Telegram blocks.

**Approach 2 — Raw GFM markdown (works but has table-splitting pitfall):**
```python
payload = json.dumps({
    "chat_id": "557337160",
    "rich_message": {"markdown": "| A | B |\n| --- | --- |\n| test | cell |"}
})
```

**Pitfall with raw GFM:** Blank lines between `|`-prefixed rows break the table. Each blank line terminates the current table. Rows after the blank become literal escaped pipes (`\|`). **Always strip blank lines between table rows** or use `telegramify-markdown` which handles this.

**Installation:** `telegramify-markdown` must be installed in the **Hermes venv** (not just system Python), because cron jobs execute using the Hermes venv Python:
```bash
/usr/local/lib/hermes-agent/venv/bin/pip install telegramify-markdown
```

**Bot token access:** Scripts source `/root/.hermes/.env` to read `TELEGRAM_BOT_TOKEN`.

**Working script template** (save as `~/.hermes/scripts/secmon/audit.py`):
```python
#!/usr/bin/env python3
import json, os, subprocess, urllib.request
from datetime import datetime, timezone
from telegramify_markdown import richify

# 1. Run audit
proc = subprocess.run([CLI, "--audit"], capture_output=True, text=True, timeout=120)
raw = proc.stdout.strip()
if not raw: exit(0)

# 2. Read bot token from .env
with open("/root/.hermes/.env") as f:
    for line in f:
        if line.startswith("TELEGRAM_BOT_TOKEN="):
            token = line.split("=", 1)[1].strip("\"'")

# 3. Parse raw output into severity groups
# (see audit.py for full parsing logic — groups findings by severity into sections)

# 4. Build structured markdown with sections per severity
ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
md = f"# 🔍 Secmon Audit\n_{ts}_\n\n---\n\n## 🟠 HIGH — {high_count} finding(s)\n\n| Finding | Check | Action |\n| :--- | :--- | :--- |\n{high_rows}\n\n---\n\n## 🟡 MEDIUM — {med_count} finding(s)\n\n..."

# 5. Convert to Rich HTML and send
rich_msg = richify(md, mode="html")
payload = json.dumps({
    "chat_id": "557337160",
    "rich_message": rich_msg.to_dict()
}).encode()
req = urllib.request.Request(
    f"https://api.telegram.org/bot{token}/sendRichMessage",
    data=payload, headers={"Content-Type": "application/json"}
)
urllib.request.urlopen(req, timeout=15)
```

**To adopt Pipeline C for a cron job:** set `no_agent: true`, `deliver: local`, and `script` pointing to the Python script.

#### Formatting Style by File and Pipeline

| Job | Pipeline | Format Pattern | Notes |
|-----|----------|----------------|-------|
| audit | C (direct API) | Structured sections: H1 + tables per severity | `audit.py` — parses findings into severity groups, builds `<h1>`/`<h2>`/`<table>`/`<hr/>` via `telegramify-markdown` |\n| daily | C (direct API) | Compact metrics table + summary | `daily.py` — parses `--daily` output into compact `<h2>`/`<table>` via `telegramify-markdown` |\n| tick | C (direct API) | Compact H2 + finding list | `tick.py` — silent when no findings, compact `<h2>`/list format via `telegramify-markdown` |

#### Cost vs Capability Tradeoff

| Job | Freq | Pipeline | Recommendation |\n|-----|------|----------|----------------|\n| Audit (every 6h) | 4/day | C (direct API) | Pipeline C for structured blocks |\n| Daily (8am) | 1/day | C (direct API) | Pipeline C for structured blocks |\n| Tick (every 15min) | 96/day | C (direct API) | Pipeline C — compact format, silent when empty |

#### Thunderbolt Truth — Corrected

Tables DO render in Telegram through `sendRichMessage`. The `convert_table_to_bullets` in `adapter.py` line 228 only runs in the legacy path. **HOWEVER**, even with `no_agent: false` and a strict prompt ("Do NOT reformat, do NOT wrap in code blocks, forward as-is"), the agent STILL reformatted tables to bullet points after multiple attempts. The only reliably working fix was **Pipeline C** (direct API).

**Key lesson:** don't debug table rendering by changing `output.py`'s format, the cron prompt, or the agent instructions. The only reliable fix is to bypass Hermes delivery entirely by using `no_agent: true` + `deliver: local` + direct Telegram API call via `sendRichMessage`. This is the definitive solution for all three secmon jobs (audit, daily, tick) when tables are required.

### 5a. Suppress Routine Findings in Tick Output

**User preference (hard rule):** Routine SSH username enumeration is constant background noise on internet-facing servers. **Suppress it.** Only notify for anomalous findings (outbound connections, file changes, persistence changes, etc.).

**Implementation** in Python cron scripts (`~/.hermes/scripts/secmon/tick.py`):

```python
ROUTINE_PATTERNS = [
    "invalid_user", "username enumeration", "invalid users",
    "Invalid User", "Username enumeration",
]

def _is_routine(text: str) -> bool:
    lower = text.lower()
    return any(p.lower() in lower for p in ROUTINE_PATTERNS)

for finding in all_findings:
    if _is_routine(finding):
        suppressed += 1
        continue
    reportable.append(finding)

if not reportable:
    sys.exit(0)  # silent -- nothing anomalous
```

**Pitfall:** Put the suppressor in the **cron delivery script** (tick.py), not in core `output.py`. The core tool reports everything; the delivery layer handles noise filtering. This keeps the audit trail complete while keeping notifications clean.

**When to broaden:** If a new routine false positive emerges, add its pattern to `ROUTINE_PATTERNS`. Prefer broader suppression over tuning thresholds -- threshold changes can miss genuine spikes.

### 6. Verify Fixes
Confirm with user, then check Telegram for audit results (should no longer show the false positive).

## Plugin Skill Bundling

Hermes plugins can **bundle skill packs** — skills that ship with the plugin and live in the plugin's directory tree, not `~/.hermes/skills/`. They're git-tracked by default since they're inside the plugin repo.

### How it works

Create a `skills/` directory in the plugin with subdirectories per skill, each containing `SKILL.md`:

```
~/.hermes/plugins/secmon/
├── __init__.py
├── plugin.yaml
├── scripts/
└── skills/
    ├── audit-tuning/
    │   └── SKILL.md
    └── false-positives/
        └── SKILL.md
```

In `__init__.py`, register each skill during plugin load:

```python
from pathlib import Path

def register(ctx):
    skills_dir = Path(__file__).parent / "skills"
    for child in sorted(skills_dir.iterdir()):
        skill_md = child / "SKILL.md"
        if child.is_dir() and skill_md.exists():
            ctx.register_skill(child.name, skill_md)
```

### How the agent loads them

- `skill_view("secmon:audit-tuning")` → loads the plugin's version
- `skill_view("audit-tuning")` → loads any built-in skill with that name (unaffected by plugin namespace)
- **Opt-in only** — not auto-injected into the system prompt; explicit `skill_view()` call required
- When loaded, a bundle context banner lists sibling skills from the same plugin

### Benefits over the old shutil.copy2 pattern

| Aspect | Old pattern (copy to ~/.hermes/skills/) | `ctx.register_skill()` |
|--------|-----------------------------------------|------------------------|
| Collisions | Risk of name collision with built-ins | Namespaced: `plugin:name` |
| Git tracking | Separate from plugin repo | In the plugin repo |
| Deployment | Needs install/deploy step | Ships with the plugin |

### Live skills bundled in secmon

Three skills are now bundled in the plugin repo and deployed to `~/.hermes/skills/devops/`:

| Skill | Namespaced access | Purpose |
|-------|------------------|---------|
| `hermes-secmon` | `secmon:hermes-secmon` | Secmon overview, architecture, 19 reference files, 4 scripts |
| `secmon-maintenance` | `secmon:secmon-maintenance` | This skill — alert investigation, false positive triage |
| `secmon-audit-output-tuning` | `secmon:secmon-audit-output-tuning` | Audit report severity filtering and Telegram formatting |

### Dual-lifecycle: agent edits + git sync

```
  Agent creates/updates skill       Sync cron (every 6h)
  via skill_manage()                copies changes back
         │                                │
         ▼                                ▼
  ~/.hermes/skills/devops/  ──────►  Plugin repo skills/
  (auto-indexed, curator     rsync    (git add + commit + push)
   tracks usage)                      ▲
                                      │
                               install.sh deploys
                               skills on first install
```

**How it works:**
- Skills live in both `~/.hermes/skills/devops/` (agent-accessible, auto-indexed) AND the plugin repo `skills/` (git-tracked)
- The `secmon-skills-sync` cron job (every 6h, `secmon/sync-skills.sh`) copies any agent-made changes back to the plugin repo, commits, and pushes
- Plugin's `ctx.register_skill()` exposes them as `secmon:<name>` for namespaced access
- When loaded, a bundle context banner lists sibling skills from the same plugin
- After `git pull` on the plugin repo, re-run `install.sh` or manually run `sync-skills.sh` to update `~/.hermes/skills/devops/`

## Common False Positive Scenarios

### Port Removed — Transient Hermes Browser Ports
**Symptom:** `Listening port removed: 45123`, `Listening port removed: 39333`

**Root cause:** Hermes' own browser automation (`agent-browser-l` / `chromium`) binds random ephemeral ports that disappear when the browser session ends. Ports are randomly allocated from the kernel's ephemeral range — hardcoding numbers is fragile.

**Verification:** Check the baseline for what process owned the port:
```bash
python3 -c "import json; d=json.load(open('/var/lib/secmon/state.json')); print(d.get('audit_baseline',{}).get('known_ports',{}).get('45123',''))"
```

**Fix (prefer process-name matching over static ports):**

| Approach | When to use | Config |
|----------|-------------|--------|
| Process-name matching (preferred) | Ephemeral browser/agent ports that change every run | `whitelist.port_removed_processes: ["chromium"]` |
| Static port list | Truly fixed ports that appear/disappear on a known schedule | `whitelist.port_removed: [80, 443]` |

**`whitelist.port_removed`** suppresses alerts for specific port numbers. Useful for monitoring/backup tools that bind a fixed port during operation. But **ephemeral ports (browser, agent processes) must use process-name matching** — hardcoding random port numbers is fragile.

**Preferred approach — process-name matching:**
```yaml
# /etc/secmon/config.yaml
whitelist:
  port_removed_processes:
    - chromium
    - agent-browser-l
```

Corresponding code in `network.py` checks the known_ports baseline for the process name:
```python
transients = cfg.get("whitelist", {}).get("port_removed_processes", [])
if transients:
    line = known_ports.get(str(port), "")
    m = _re.search(r'"([^"]+)"', line)
    if m and m.group(1) in transients:
        continue  # skip — transient browser process
```

**Pitfall:** Use `port_removed_processes` for browser/agent ephemeral ports. Static `port_removed` works for truly fixed service ports, but ephemeral ports change every run — next session gets different numbers. Always use process-name matching for transient processes.

### SUID Binary Alerts
**Symptom:** "Unexpected SUID: /usr/bin/pkexec" or similar
**Root cause:** `DEBIAN_SUID_WHITELIST` in `file_integrity.py` missing legitimate binaries
**Fix:** Add binary path to whitelist (include both `/bin/` and `/usr/bin/` variants for usrmerge compatibility)

### Fail2ban Burst Alerts
**Symptom:** "SSH ban burst: X new bans" firing too frequently
**Root cause:** `fail2ban_min_new_bans` threshold too low for server's normal traffic
**Fix:** Increase threshold in `/etc/secmon/config.yaml` (typical busy server: 50+)

### Baseline Not Updating
**Symptom:** Alert keeps firing even after whitelist fix
**Root cause:** `suid_cache` in state stored old values
**Fix:** Run `sudo secmon --reset-baseline` or manually clear cache in `/var/lib/secmon/state.json`

## User Preferences

- **Direct action** - Just do the fix, don't explain at length
- **Fix at source** - Patch code and commit to public repo, not local workarounds
- **Verify then commit** - Make changes locally, test with user, commit & push only after user confirms
- **Minimal verbosity** - Skip lengthy explanations, show commands and results
- **Suppress INFO from audit reports** - The user does not want to see INFO-level findings (trend new/resolved/persistent, layer counts) in the audit table. Use the `secmon:secmon-audit-output-tuning` skill for the exact `output.py` patches.
- **Suppress routine findings from tick output** - Routine SSH username enumeration is constant background noise. Use `ROUTINE_PATTERNS` in tick.py to filter them out before notification.

## References

- `secmon:secmon-audit-output-tuning` — sibling skill for audit report severity filtering and Telegram table formatting
- Secmon repo: https://github.com/lyxtera/hermes-secmon
- Config location: `/etc/secmon/config.yaml`
- State location: `/var/lib/secmon/state.json`
- Install script: `~/.hermes/plugins/secmon/scripts/install.sh`
- Alert tuning reference: `references/alert-tuning.md` — SUID whitelist, threshold tuning, stale cache fixes
- Audit findings triage: `references/audit-findings-triage.md` — port_removed, secret_pattern, persist_modified, sec_updates, sysctl, and general triage workflow
