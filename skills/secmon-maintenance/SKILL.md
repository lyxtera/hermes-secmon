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
  - investigating NC-9-bpf-* watcher findings (persistent BPF programs)
  - promoting known-good BPF programs to baseline
  - configuring BPF watcher thresholds and systemd whitelist
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

**⚠️ Dual-location fix rule:** When editing a cron delivery script (tick.py, audit.py, daily.py), always patch **both** locations:
- `~/.hermes/plugins/secmon/scripts/<script>.py` — the **source** (git-tracked, installed via install.sh)
- `~/.hermes/scripts/secmon/<script>.py` — the **deployed copy** (what cron actually runs)

If you only patch the deployed copy, re-running install.sh or sync-cron.sh will silently overwrite your fix.

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
- Does the README's exclusion tuning table need a new row?

**Checklist — config.example.yaml sync:** Every time you add a new config key to `src/`, verify it also exists in `config.yaml.example` (the template users start from). The example is the canonical reference — `git diff HEAD -- config.yaml.example` should never show the example was forgotten. If the new key has a placeholder value distinct from production (e.g. `own_ip: 203.0.113.1` in example vs real IP in prod), note that the difference is deliberate and keep the placeholder.

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

**Config tuning (for thresholds):**\n- Edit `~/.hermes/secmon/config.yaml` (no sudo needed — inside Hermes home, auto-backed up via `hermes backup`)\n- Canonical config location: `~/.hermes/secmon/config.yaml`\n- Symlink: `/etc/secmon/config.yaml → ~/.hermes/secmon/config.yaml` for backwards compatibility\n- Config search path (priority order): `--config path` → `SECMON_CONFIG_PATH` env var → `/etc/secmon/config.yaml` (symlink) → `~/.hermes/secmon/config.yaml` → `config.yaml` (cwd)\n  - Note: `/etc/secmon/config.yaml` and `~/.hermes/secmon/config.yaml` point to the same file via symlink — no conflict\n- All three cron scripts (tick.py, audit.py, daily.py) use `SECMON_CONFIG_PATH` or fall back to `/etc/secmon/config.yaml` (symlink) — no code changes needed after consolidation\n- `/opt/secmon/config.yaml` and plugin-local copies (`/root/.hermes/plugins/secmon/config.yaml`) are orphan legacy — remove them whenever found\n- Old `/opt/secmon/config.yaml` had placeholder IPs (`1.1.1.1`) and different thresholds (`fail2ban_min_new_bans: 5`, `min_severity: MEDIUM`) — migrating to `~/.hermes/` config with real settings (`own_ip`, proper whitelists)\n\n**Config recovery from broken symlink / deleted file:**\n\nIf `~/.hermes/secmon/config.yaml` gets deleted and the symlink at `/etc/secmon/` becomes broken:\n\n1. Detect with `ls -la /etc/secmon/config.yaml` — shows broken symlink target\n2. Recreate from the plugin repo's template:\n   ```bash\n   cp /root/.hermes/plugins/secmon/config.yaml.example ~/.hermes/secmon/config.yaml\n   ```\n3. **Must customize** these values for the production server (the placeholder template has dummy IPs):\n\n   | Setting | Production value | Get from |\n   |---------|-----------------|----------|\n   | `own_ip` | Server's public IP | `curl -s ifconfig.me` or `secmon --check` output |\n   | `known_ssh_ips` | Trusted admin IPs | Your SSH client IPs |\n   | `fail2ban_min_new_bans` | 50+ for busy server | Old default 5 is too low |\n   | `min_severity` | `HIGH` | Changed from `MEDIUM` to suppress routine username enum noise |\n   | `port_removed` | Browser ephemeral ports | Check secmon alerts history |\n   | `port_removed_processes` | `[chromium, agent-browser-l]` | Hermes browser agent processes |\n   | `secret_exclude_paths` | Add state-snapshots dir | Directory prefix matching |\n\n4. Fix the symlink: `ln -sf ~/.hermes/secmon/config.yaml /etc/secmon/config.yaml`\n5. Verify: `readlink -f /etc/secmon/config.yaml` must resolve to the real file. Run `secmon --tick --verbose` — it should NOT timeout.\n6. **Pitfall:** Without a valid config file, `secmon --tick` hangs for 30s then times out (the tick.py wrapper catches this, but the cron job fails silently for hours). Always verify tick works after config recovery.\n\n**Production config reference (this server):**\n\n```yaml\nwhitelist:\n  own_ip: 188.130.207.113\n  known_ssh_ips:\n    - 203.0.113.1\n  port_removed:\n    - 45123\n    - 39333\n  port_removed_processes:\n    - chromium\n    - agent-browser-l\n  secret_exclude_paths:\n    - /root/.hermes/state-snapshots\n    - /root/.hermes/config.yaml\n    - /root/.hermes/.env\nrealtime:\n  fail2ban_min_new_bans: 50\nhermes:\n  min_severity: HIGH\n```

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

**Critical: `secmon --tick` outputs findings in TWO formats, not one**

The `dispatch()` function in `alerts.py` outputs findings in a **non-table format**:

```
🟡 *MEDIUM* — Enumeration: Invalid User: Username enumeration from 🤫.🤫.🤫.0/24: 5 users → `secmon --status`
```

This has **nothing to do with `|` table rows**. tick.py's original `_is_routine()` loop only checked lines starting with `|` — all dispatch-format lines fell through to the `else` branch which just dumped `raw` output with no suppression applied.

**Fix — add a second parsing path for dispatch-format lines:**

```python
DISPATCH_PATTERN = re.compile(
    r'^[🟡🟠🔴🔵ℹ️] \*([A-Z]+)\* — ([^:]+): (.+?) → `'
)

def _is_routine_dispatch(line: str) -> bool:
    m = DISPATCH_PATTERN.match(line)
    if not m:
        return False
    return _is_routine(m.group(3))  # group(3) is the message

for line in lines:
    s = line.strip()
    if not s:
        continue
    # Table format (from audit mode via audit.py send)
    if s.startswith("|") and s.endswith("|") and ":---" not in s and "Finding" not in s:
        cells = [c.strip().replace("*", "") for c in s.strip("|").split("|")]
        if len(cells) >= 2:
            finding_text = " · ".join(cell for cell in cells[:3] if cell)
            if _is_routine(finding_text):
                suppressed += 1
                continue
            findings.append(finding_text)
    # Dispatch format (from secmon --tick directly)
    elif DISPATCH_PATTERN.match(s):
        if _is_routine_dispatch(s):
            suppressed += 1
            continue
        findings.append(s)
```

Always test the regex against actual secmon output format after any secmon version update — the `→ hint` suffix pattern could change.

**When to broaden:** If a new routine false positive emerges, add its pattern to `ROUTINE_PATTERNS`. Prefer broader suppression over tuning thresholds -- threshold changes can miss genuine spikes.

### 6. Verify Fixes

**Manual cron script testing (before waiting for cron schedule):**
```bash
# Run each cron delivery script directly to verify
cd ~/.hermes/scripts/secmon
python3 tick.py    # exit 0 = silent (no findings or all suppressed)
python3 audit.py   # exit 0 = silent (no findings)
python3 daily.py   # exit 0 = silent (no findings)

# Check if findings are actually being produced (not exit 1)
/usr/local/bin/secmon --tick --verbose 2>&1

# Test config parsing
/usr/local/bin/secmon --tick --config /etc/secmon/config.yaml 2>&1
```

**Pitfall: tick.py subprocess timeout too short.** The cron wrapper at `tick.py` calls `subprocess.run(cmd, ..., timeout=30)`. `secmon --tick` can occasionally take >30s (e.g. during tick-gap detection after a long outage, or when multiple bpftool calls stack). This produces `subprocess.TimeoutExpired` errors in cron logs. Fix: `timeout=30` → `timeout=120`.

**Pitfall: internal shell.py defaults also too short.** Even with tick.py's wrapper timeout bumped, `secmon --tick` itself may time out internally before reaching `save_state()` if its subprocess helpers also default to 30s. The three functions in `shell.py` all had `timeout=30` as default — bump them all to 120s.

| Function | Default changed |
|---|---|
| `run_cmd(args, ..., timeout: int = 30)` → 120 |
| `run_cmd_safe(args, ..., timeout: int = 30)` → 120 |
| `run_cmd_json(args, ..., timeout: int = 30)` → 120 |

Per-command explicit timeouts (10s for iptables/dpkg, 30s for short journal queries, 60s for 24h journals) are intentional — leave them.

**Consequence of hitting the internal timeout mid-tick:** `secmon --tick` exits 0 with **empty stdout** but `save_state()` never ran, so `last_tick` stays stale. Tick.py sees empty stdout → `sys.exit(0)` → cron logs "silent (empty output)". The next tick detects a 30m gap → CRITICAL `self_prot:missed_tick` fires. This is a one-hop delay — the gap alert is the symptom, not the root cause. Always check whether the missed tick actually crashed before investigating other threats.

**Gap threshold formula:** `tick_threshold = max(cron_interval * 120, 600)` where `cron_interval` = 15 min → `1800s` = **30 min** (2× the interval). A single missed tick won't trigger — it takes two consecutive misses or a 30min+ gap.

**Concurrent cron contention at :00:** secmon-tick, secmon-skills-sync, and secmon-audit can all fire around HH:00. If a later check in run_tick crashes before `save_state()`, the state on disk remains stale. Ticks at :00 are more likely to fail than :15/:30/:45 for this reason. See `references/concurrent-state-file-race.md` for a documented case where the audit job overwrote the tick's `last_tick` update via the read-modify-write race.

**Critical: patch BOTH locations.** When fixing tick.py (or any cron delivery script), update:
1. The **deployed copy** at `~/.hermes/scripts/secmon/tick.py` — what cron runs
2. The **source file** at `~/.hermes/plugins/secmon/scripts/tick.py` — what `install.sh` copies. Patch only deployed = fix lost on reinstall.

**Pitfall:** `exit 1` from these scripts doesn't always mean failure — when tick.py/audit.py send findings via Telegram API directly (Pipeline C), they exit 0 but produce no stdout. The cron system records "silent (empty output)" even when a message was sent. Check the cron output dir for actual delivery records:
```bash
ls -lt ~/.hermes/cron/output/<job-id>/ | head -5
cat ~/.hermes/cron/output/<job-id>/latest.md
```

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

### BPF Watcher — Stable-Key Surveillance (replaces old NC-9-newprog)

**Context:** The old `NC-9-newprog` check flagged any new BPF program by numeric ID as HIGH immediately — false positive on every transient package install (Docker, Podman, any runtime that triggers systemd cgroup BPFs). **Replaced by a stable-key watcher** in commit `d5f665a` (47 files, 2647 insertions).

**Architecture:** The watcher lives in `src/secmon/bpf/` with these modules:

| Module | Role |
|--------|------|
| `collector.py` | Full BPF inventory via `bpftool -j prog/map/link/cgroup/net show` |
| `identity.py` | Stable keys: `prog:{type}:{tag}:{xlated_sha256}:{attach_fp}` — survives reboots |
| `classifier.py` | Risk scoring + systemd whitelist matching |
| `provenance.py` | /proc forensics on the loader PID (exe, dpkg owner, systemd unit, capabilities, parent chain) |
| `models.py` | WatchState FSM + data classes |
| `watchlist.py` | State persistence (baseline, watchlist) |
| `watcher.py` | Refresh + escalation loop |
| `audit.py` | Integration with `--audit` mode |
| `auditd.py` | Optional auditd bridge for `bpf()` syscall monitoring |

**Stable Identity:** Programs identified by `prog:{type}:{tag}:{xlated_sha256}:{attach_fingerprint}` instead of numeric IDs. Same program after a reboot reuses the same stable key. Maps use `map:{type}:{name}:{key_size}:{value_size}:{max_entries}:{flags}:{btf_hash}`.

**State Machine (WatchState):**

```
  IGNORED  ── systemd whitelist match (name + type + attach + loader)
  BASELINE_MATCH  ── known in baseline (promoted)
  SURVEILLANCE  ── new, score < 70, first seen
  ALERT_HIGH  ── score >= 70 (persistent or suspicious loader)
  ALERT_CRITICAL  ── score >= 100
  VANISHED  ── program disappeared since last scan
```

**Scoring factors (classifier.py):**
- **Loader risk** (+40 from /tmp, +30 (deleted) exe, +20 not in dpkg, +25 root without systemd unit, +35 suspicious comm)
- **Program type risk** (+40 for kprobe/lsm/fentry/raw_tracepoint/struct_ops)
- **Attach risk** (+50–60 for security_*, commit_creds, execve, vfs_read/write patterns)
- **Map type risk** (+30 for prog_array/ringbuf/sockmap/devmap/xskmap)

**Escalation:** Findings only emitted on *state transitions* — `SURVEILLANCE → ALERT_HIGH`, `SURVEILLANCE → ALERT_CRITICAL` — not on every audit cycle. Suppresses repeat alerts. A program that stays in SURVEILLANCE at low score sits forever, silent.

**Systemd whitelist (hardcoded in classifier.py):** `sd_fw_ingress`, `sd_fw_egress`, `sd_devices` are auto-`IGNORED` when all four conditions match: program name, prog_type (`cgroup_skb` / `cgroup_device`), attach type (`cgroup_ingress`/`cgroup_egress`/`cgroup_device`), and loader path (`/usr/lib/systemd/systemd`). Config in `/etc/secmon/config.yaml` provides `bpf.systemd_loader_paths` and `bpf.systemd_cgroup_prefixes` for the loader-match check.

**New CLI modes:**

| Command | Purpose |
|---------|---------|
| `secmon --bpf-watch` | Refresh watchlist + emit escalation alerts (standalone, no full audit) |
| `secmon --bpf-baseline list` | Show all promoted baseline entries |
| `secmon --bpf-baseline promote --key <stable_key>` | Promote a watchlist entry to baseline (permanently ignored) |
| `secmon --bpf-watchlist list` | Show current watchlist with states, scores, metadata |
| `secmon --bpf-watchlist clear --key <stable_key>` | Remove a watchlist entry (doesn't promote to baseline) |

**New check IDs:**

| Check ID | Severity | When |
|----------|----------|------|
| `NC-9-bpf-surveillance-started` | INFO | New BPF program entered watchlist (first observation) |
| `NC-9-bpf-critical-program` | CRITICAL | Program escalated to ALERT_CRITICAL (score ≥ 100) |
| `NC-9-bpf-high-risk-program` | HIGH | Program escalated to ALERT_HIGH (score ≥ 70) |
| `NC-9-bpf-high-risk-map` | HIGH | Map escalated to ALERT_HIGH |
| `NC-9-bpf-monitoring-gap` | HIGH | auditd lost/backlog counter increased |
| `NC-9-bpf-link-updated` | HIGH | BPF link attachment changed for a watched program |
| `NC-9-bpf-pinned-persistence` | MEDIUM | New pinned path detected for a watched program |
| `NC-9-bpf-loader-suspicious` | HIGH | Loader changed to suspicious path for a watched program |
| `NC-9-bpf-map-mutated` | HIGH | Watched map metadata changed (max_entries, flags, FD holders) |

**First-time setup — promote known systemd BPF programs:**

After a fresh `--audit` or `--bpf-watch`, systemd's `sd_devices` and `sd_fw_ingress`/`sd_fw_egress` may land in SURVEILLANCE (risk_score 0, never alerting). This happens when `bpftool` reports no FD holder PIDs, so loader provenance is empty and the systemd whitelist can't fully match. Promote them to baseline to clean the watchlist:

```bash
# 1. List the watchlist to see what's there
secmon --bpf-watchlist list

# 2. Run bpf-watch once to populate state
secmon --bpf-watch

# 3. Promote each known-good entry by stable key
secmon --bpf-baseline promote --key "prog:cgroup_device:...:<attach_fp>"
secmon --bpf-baseline promote --key "prog:cgroup_skb:...:<attach_fp>"

# 4. Verify
secmon --bpf-watchlist list   # should be empty
secmon --bpf-baseline list    # shows promoted entries
```

**Config reference (`~/.hermes/secmon/config.yaml`):**

```yaml
bpf:
  systemd_loader_paths:
    - "/usr/lib/systemd/systemd"
    - "/lib/systemd/systemd"
  systemd_cgroup_prefixes:
    - "/system.slice"
```

**Optional: auditd integration for BPF syscall monitoring:**

```bash
apt install auditd
systemctl enable --now auditd
# install.sh already places /etc/audit/rules.d/secmon-bpf.rules
augenrules --load
```

This enables `NC-9-bpf-monitoring-gap` detection. Without auditd, the gap check always passes (no false positives).

**How the Docker scenario plays out (before vs after):**

| Phase | Old behavior (removed) | New watcher |
|-------|----------------------|-------------|
| Docker install triggers systemd cgroup BPFs | HIGH immediately via NC-9-newprog | Enters SURVEILLANCE at score 0 — silent |
| Next audit while Docker still running | HIGH again (new ID each time?) | Still SURVEILLANCE — same stable key |
| Docker uninstall, BPFs cleaned up | HIGH on first audit (new non-baseline IDs) | Watchlist entry → VANISHED — absorbed, no alert |
| Permanent systemd programs | Repeated HIGH until baseline absorbs | Promoted to baseline once, IGNORED forever |

**New check IDs reference:** See `references/bpf-watcher.md` for a comprehensive listing of all BPF check IDs, their triggers, severities, and the corresponding classifier rules.

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
**Fix:** Increase threshold in config (typical busy server: 50+)

### Outbound Connections — Process-Based Whitelisting
**Symptom:** "Direct-IP HTTPS session to Cloudflare:443 (hermes)" or "New outbound from privileged process hermes"
**Root cause:** The Hermes agent makes API calls to providers (OpenRouter via Cloudflare, Telegram Bot API) that appear as direct-IP HTTPS connections to secmon's outbound monitor.
**Fix (prefer over IP ranges):** Add a **process-only** entry to `whitelist.outbound_destinations` — no hardcoded IPs needed:

```yaml
whitelist:
  outbound_destinations:
    - process: hermes   # whitelist ALL outbound from this process
```

This requires a **code change** in `_is_whitelisted()` (`src/secmon/checks/outbound.py`). Originally, process-only entries (no IP/CIDR) fell through and never matched. After the fix, a matched process with no IP/CIDR returns `True` — whitelisting all connections from that process.

**Why process-based is better than IP ranges:**
| Aspect | IP ranges | Process-based |
|--------|-----------|---------------|
| Cloudflare IPs | 1000+ ranges, change frequently | `{process: hermes}` — zero maintenance |
| Provider switch | Must audit and update all ranges | Works automatically |
| Other processes | Still affected | Targeted — caddy, sshd still monitored |

**Test in isolation:**
```python
from secmon.checks.outbound import _is_whitelisted
cfg = {'whitelist': {'outbound_destinations': [{'process': 'hermes'}]}}
assert _is_whitelisted('104.18.2.115', 443, 'hermes', cfg) == True
assert _is_whitelisted('104.18.2.115', 443, 'caddy', cfg) == False
```

**Why not CDN IP whitelisting?** Cloudflare uses AS13335 with thousands of ranges across their CDN. Hardcoding them is fragile — they add/remove ranges frequently. Process-name matching is the only solid approach.\n\n### Baseline Not Updating
**Symptom:** Alert keeps firing even after whitelist fix
**Root cause:** `suid_cache` in state stored old values
**Fix:** Run `sudo secmon --reset-baseline` or manually clear cache in `/var/lib/secmon/state.json`

### Secret Pattern — Directory Prefix Exclusion Required
**Symptom:** `secret_pattern` fires for files under an excluded directory (e.g., `/root/.hermes/state-snapshots/.../*.yaml`)
**Root cause:** The `secret_exclude_paths` whitelist uses exact file path match (`if fp in exclude_paths`). Excluding a directory does NOT exclude files inside it — only the directory path itself matches.
**Fix (patch threat_intel.py):** Replace the exact-match check with a prefix-matching helper:
```python
def _is_excluded(fp: str, exclude_paths: set[str]) -> bool:
    if fp in exclude_paths:
        return True
    for ex in exclude_paths:
        if fp.startswith(ex + "/") or fp.startswith(ex + os.sep):
            return True
    return False
```
Then change both exclusion lines in `_scan_secrets()` from `if fp in exclude_paths:` to `if _is_excluded(fp, exclude_paths):`. This makes excluding `/root/.hermes/state-snapshots` automatically cover everything under it.
**Prevention:** When adding a directory to `secret_exclude_paths`, always verify it actually excludes subfiles by running `--audit` after the change.

### Hidden tmp — BPF / Executable Investigation
**Symptom:** `hidden_tmp` fires for a hidden entry in `/dev/shm` or `/tmp` (e.g., `.bt`)
**Investigation pattern:**
```bash
# 1. Check file type and size
file /dev/shm/.bt
ls -la /dev/shm/.bt

# 2. Check if currently running
lsof /dev/shm/.bt
ps aux | grep .bt

# 3. Inspect strings for origin clues
strings /dev/shm/.bt | grep -iE "version|build|gcc|clang|bpftrace|bpf" | head -10
readelf -s /dev/shm/.bt 2>/dev/null | grep -E "main|bpf|trace|monitor" | head -10

# 4. Check hash for known signatures
sha256sum /dev/shm/.bt
```
**Assessment:** `.bt` files in `/dev/shm` are typically compiled BPF tracing tools (bpftrace, custom bpf tools) — 2.4 MB ELF, dynamic linked, references `libclang` and `bpf_*` syscall wrappers. If not currently running, it's likely a leftover from a previous experiment. Remove with `rm /dev/shm/.bt` and add to `hidden_tmp_entries` whitelist if it's expected to reappear.

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
- Config location: `~/.hermes/secmon/config.yaml` (auto-backed up via `hermes backup`; search fallback: `/etc/secmon/config.yaml`)
- State location: `/var/lib/secmon/state.json`
- Install script: `~/.hermes/plugins/secmon/scripts/install.sh`
- Alert tuning reference: `references/alert-tuning.md` — SUID whitelist, threshold tuning, stale cache fixes
- Audit findings triage: `references/audit-findings-triage.md` — port_removed, secret_pattern, persist_modified, sec_updates, sysctl, and general triage workflow
- BPF watcher reference: `references/bpf-watcher.md` — comprehensive check ID table, classifier rules, stable key format, state machine transitions
- Concurrent state-file race: `references/concurrent-state-file-race.md` — how concurrent secmon processes (--tick + --audit) can clobber last_tick via the read-modify-write pattern on state.json, and the fcntl.flock() fix
