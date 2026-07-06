# Cron Script Deployment & Repository Layout

## Three-Script Layout

Secmon uses three wrapper scripts (Hermes cron no-agent entry points):

| Script | Job | Schedule | Output |
|--------|-----|----------|--------|
| `tick.sh` | `secmon-tick` | Every 15 min | Alert lines in Markdown |
| `audit.sh` | `secmon-audit` | Every 6 hours | Full JSON audit in code fence + summary table |
| `daily.sh` | `secmon-daily` | 08:00 UTC | Human-readable daily digest |

All scripts:
- Emit **Markdown-formatted output** (Telegram rendering: `**bold**`, `` `code` ``, `## headings`, `| tables |`)
- Exit silently (empty stdout) when there's nothing to report
- Use a `▶ \`command\`` CTA footer with a copy-paste-ready fix command
- Include a `### 🛠️ What to do` / `### 📋 Next steps` section with bullet lists showing exact shell commands

## Symlink-Based Deployment (critical)

**Scripts in `~/.hermes/scripts/secmon/` are symlinks, not copies.**

```
~/.hermes/scripts/secmon/tick.sh → /opt/secmon/scripts/tick.sh
~/.hermes/scripts/secmon/audit.sh → /opt/secmon/scripts/audit.sh
~/.hermes/scripts/secmon/daily.sh → /opt/secmon/scripts/daily.sh
```

This means:
- **Editing the plugin scripts automatically propagates** to cron runtime — no manual `cp` needed
- `git pull` in the plugin directory immediately updates the next cron execution
- The `chmod +x` is set on the symlink target (the plugin script), not the symlink itself

### install.sh creates the symlinks

```bash
ln -sf "${SOURCE_DIR}/scripts/tick.sh"   "${HERMES_SCRIPTS_DIR}/tick.sh"
ln -sf "${SOURCE_DIR}/scripts/audit.sh"  "${HERMES_SCRIPTS_DIR}/audit.sh"
ln -sf "${SOURCE_DIR}/scripts/daily.sh"  "${HERMES_SCRIPTS_DIR}/daily.sh"
```

**Pitfall:** If you ever replace these symlinks with `cp`, script updates stop propagating. Always use `ln -sf`.

## Repository Layout (current)

```
/opt/secmon/  (→ ~/.hermes/plugins/secmon/)
├── src/secmon/              # Python package
├── tests/                   # Test suite (95%+ coverage)
├── scripts/                 # Hermes cron wrappers + installer
│   ├── tick.sh              → secmon --tick (Markdown output)
│   ├── audit.sh             → secmon --audit (Markdown output)
│   ├── daily.sh             → secmon --daily (Markdown output)
│   ├── install.sh           # First-time setup (symlinks, venv, cron)
│   └── uninstall.sh         # Reversible removal
├── config.yaml.example      # Documented config with all whitelist/hardening keys
├── SECURITY-AUDIT-SPEC.MD
└── README.md
```

## Cron Job Registration

Hermes cron jobs reference scripts as `secmon/tick.sh` (relative to `~/.hermes/scripts/`):

```bash
hermes cron add "*/15 * * * *" --no-agent \
  --script "secmon/tick.sh" \
  --name "secmon-tick" \
  --deliver "telegram"
```

**Key constraint:** `--no-agent` mode requires the script path to be resolvable from `~/.hermes/scripts/`. The subdirectory `secmon/` is created by `install.sh`.

## Markdown Output Format (all three scripts)

### Tick (with findings)
```
## 🔔 Secmon Tick
*2026-07-02 04:25 UTC*

**HIGH** `self_protection`: Secmon state permissions too open: /var/lib/secmon/state.json (0o644) → `chmod 600 <path>`

### 🛠️ What to do

- `chmod 600 /var/lib/secmon/state.json` — Fix permissions
- `secmon --status` — Verify

▶ `chmod 600 /var/lib/secmon/state.json`
```

### Audit
```
## 🔍 Secmon Audit
*2026-07-02 04:25 UTC*

```json
{...full JSON...}
```

### 📊 Summary
| Metric | Value |
|--------|-------|
| **Score** | 4 |
| **Findings** | 8 |
| **🔴 CRITICAL** | 0 |
| **🟠 HIGH** | 0 |

### 📋 Next steps
- Review layers with **CRITICAL** or **HIGH** findings
...

▶ `secmon --audit`
```

### Daily
```
## 📅 Secmon Daily Digest
*2026-07-02 08:00 UTC*

```
{...digest text...}
```

### 📋 Next steps
- Compare metrics and anomalies against baselines
...

▶ `secmon --audit`
```

## Silent Tick Rule

If the secmon CLI produces no output, the wrapper script exits 0 with empty stdout. Hermes cron delivers nothing — the user sees no notification.

## Development Workflow

1. Edit scripts in `/opt/secmon/scripts/` (the plugin checkout)
2. No need to sync — symlinks handle propagation
3. Commit from the plugin directory:
   ```bash
   cd /opt/secmon
   git add scripts/tick.sh scripts/audit.sh scripts/daily.sh
   git commit -m "fix: ..."
   git push
   ```
4. Test directly:
   ```bash
   /opt/secmon/scripts/tick.sh   # or:
   ~/.hermes/scripts/secmon/tick.sh  # same thing via symlink
   ```
