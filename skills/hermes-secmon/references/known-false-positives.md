# Known Chronic False Positives

Documented patterns that fire on every audit cycle and are safe to ignore (or
need config changes to suppress). Kept here so each audit run doesn't require
re-investigation from scratch.

## 1. `persist_modified` — `systemd_timers`

**Status:** Design limitation, pending code fix.

**Root cause:** The persistence baseline stores `sha256sum` of `systemctl list-timers --all` output.
The output includes dynamic time columns (`NEXT`, `LEFT`, `LAST`, `PASSED`) that update on every timer
fire — so the hash is **guaranteed to differ** between any two runs, even when no actual timer config
changed.

**Workaround:** Add `systemd_timers` to an exclusion list in the persistence check, or normalize the
timer output (e.g. `systemctl list-timers --all | sed 's/[0-9]\+ [a-z]\+ ago//g'`) before hashing.

**Current timer set (expected):**
| Timer | Purpose | Frequency |
|---|---|---|
| `systemd-tmpfiles-clean.timer` | Temp file cleanup | Daily |
| `apt-daily.timer` | APT cache update | ~12h |
| `dpkg-db-backup.timer` | dpkg database backup | Daily |
| `e2scrub_all.timer` | Filesystem scrub | Weekly |
| `apt-daily-upgrade.timer` | APT unattended upgrade | ~12h |
| `fstrim.timer` | SSD trim | Weekly |

## 2. `secret_pattern` — `/root/.hermes/state-snapshots/`

**Status:** Config fix needed.

**Root cause:** Hermes' pre-update migration script creates snapshots under
`/root/.hermes/state-snapshots/<timestamp>-*/` containing the full `.env` and `config.yaml`.
These files contain real API keys (OPENROUTER_API_KEY, GEMINI_API_KEY, etc.) but are
owner-only readable (`-rw-------`). The secret pattern scanner treats any `.env` file
with `api_key=` as a credential leak, not recognizing this as a legitimate backup.

**Fix:** Add to `/etc/secmon/config.yaml`:
```yaml
whitelist:
  secret_exclude_paths:
    - "/root/.hermes/state-snapshots"
    - "/root/.hermes/.env"
    - "/root/.hermes/config.yaml"
```

## 3. `secret_pattern` — `/root/.hermes/config.yaml` and `/root/.hermes/.env`

**Status:** Config fix needed.

**Root cause:** Same as above — these are the live config files that define Hermes' providers.
They match `api_key=` patterns by design.

**Fix:** Add the paths above to `whitelist.secret_exclude_paths`.

## 4. `sec_updates` — Kernel package (`linux-image-amd64`)

**Status:** Actionable but requires reboot.

**Root cause:** The security update check finds a newer kernel via apt. After `apt-get install`,
the new kernel is installed on disk but the **running kernel** (`uname -r`) doesn't change until
a full reboot. This finding will persist across audit cycles until the server is rebooted.

**Audit context:** In a cron-delivered report, always note whether the kernel has been installed
but not yet rebooted. This is not a "resolved" event — it's a "deferred action" event.

## 5. `invalid_users` — SSH enumeration

**Status:** Expected behavior, internet-facing server.

**Root cause:** Routine bot/script-kiddie SSH enumeration against known usernames
(admin, ubuntu, user, oracle, ansible, root, postgres, etc.). This is normal background
noise for any server with SSH exposed on port 22.

**Fix:** None needed — fail2ban handles the actual remediation. Escalate only if the
enumeration volume spikes 2.5σ above the rolling baseline (>2000 unique invalid users/24h)
or if a new username appears that suggests targeted attack (e.g. system usernames on this
specific server).
