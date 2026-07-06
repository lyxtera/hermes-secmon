# Audit Remediation Workflow

Procedure for investigating and fixing secmon audit findings, derived from real sessions.

## Step 1: Classify findings

Not every finding is actionable. Sort into three buckets:

| Bucket | Signal | Action |
|--------|--------|--------|
| **Investigate** | Unknown process, unknown PID, unexpected file | Check what it is, then fix |
| **Benign / false positive** | X11 sockets in /tmp, intended DNS config, systemd tmpfs, known runtime processes | Note and skip |
| **Unfixable at runtime** | INPUT chain default DROP (lockout risk), kernel.modules_disabled (needs boot param) | Note and explain why |

## Step 2: Triage unknown findings

Batch parallel investigations:

| Finding | Investigation command | Typical outcome |
|---------|----------------------|-----------------|
| `proc_hollow_anon` pid N | `cat /proc/{N}/cmdline \| tr '\0' ' '` | pid 449 = unattended-upgrades-shutdown (benign Python) |
| `NC-3-dns` / unexpected NS | `cat /etc/resolv.conf` + `nmcli dev show \| grep DNS` | Cloudflare/Google DNS intentionally configured |
| `NC-6-tmpfs` unexpected tmpfs | `mount \| grep /var/tmp` | systemd tmpfs with noexec — more secure than disk |
| `secret_pattern` in file | `grep -n 'KEY\|key\|secret\|api_key'` | Determine if real secret or placeholder doc |
| `systemd_failed` unit | `systemctl status {unit}` | Often dead path from removed script |
| `persist_modified` / `persist_removed` | `ls /etc/systemd/system/{unit}` | Expected if secmon was redeployed |

## Step 3: Batch fixes by layer

Fix independent items in parallel (they don't depend on each other):

| Layer | Common fixes |
|-------|-------------|
| Network / iptables | Create missing protection chains (SCANS, BAD_FLAGS, ANTI_SCAN, PORT_SCAN), persist with `iptables-save > /etc/iptables/rules.v4` |
| Systemd | `systemctl disable --now {failed-unit}`, `rm /etc/systemd/system/{unit}`, `systemctl daemon-reload`, `systemctl reset-failed {unit}` |
| Files / secrets | `rm -f` backup files with leaked keys, `sed -i '/KEY/d'` to scrub bash_history, codex snapshots, config stubs |
| Compliance / certs | `rm -f /etc/ssl/certs/{expired}.pem`, `c_rehash /etc/ssl/certs/` |
| Kernel | `sysctl -w key=value`, persist to `/etc/sysctl.d/99-hardening.conf` |
| Secret-bearing source configs | `config.yaml`, `.env` — do NOT delete; these are the real config files. Accept the alert. |

## Step 4: Verify

Re-run `secmon --audit` after all fixes. Check:

- Score dropped significantly
- Previously flagged findings appear in `trend_resolved`
- No new critical findings introduced by your changes
- Only truly unfixable items remain

## Step 5: Present results

Deliver as:

1. Score change (before → after, % drop)
2. ✅ Fixed section with per-layer table of what was done
3. ⏭️ Skipped (user preference)
4. ℹ️ Remaining with reason for each (benign / false positive / unfixable)

## Common false positive triage

| Finding | Why FP |
|---------|--------|
| `hidden_tmp: .font-unix, .XIM-unix, .ICE-unix` | X11 Unix sockets from VNC desktop — normal |
| `fw_policy: INPUT not DROP` | Cannot DROP on remote server (lockout on next SSH) |
| `proc_hollow_anon: pid 449 rwxp` | Python's `unattended-upgrades-shutdown` — JIT/mmap |
| `NC-3-dns` with Cloudflare/Google | Intentionally configured public DNS |
| `NC-6-tmpfs` on /var/tmp | Systemd tmpfs — more secure than disk mount |
| `kernel_modules_enabled` | Can only disable via kernel cmdline at boot |
| `secret_pattern` in config.yaml / .env | Real config files — removing breaks the system |
| `secret_pattern` in README docs | Placeholder values like `STITCH_API_KEY=""` |
| `kptr_restrict=2` vs expected 1 | 2 is strictly more secure (hides all kernel pointers) |
| `persist_modified` systemd timers | Secmon's own scheduled tasks — expected |
