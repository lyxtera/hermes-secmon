# Tuning secmon Audit Findings

## Philosophy

Prefer **config-level whitelisting** over code patches. The audit system reads from `/etc/secmon/config.yaml` — most "expected value" knobs are config-driven. This keeps tuning reversible, auditable, and survivable across secmon updates.

## Config-Driven Tuning Keys

All live under `whitelist:`, `hardening:`, `dns:`, or `sysctl:` in `/etc/secmon/config.yaml`. Defaults are in `src/secmon/config.py` → `default_config()`.

| Config path | Purpose | Example |
|-------------|---------|---------|
| `dns.expected_nameservers` | Whitelist DNS resolvers the audit won't flag | `["1.1.1.1", "2001:4860:4860::8844"]` |
| `whitelist.hidden_tmp_entries` | Ignore known benign hidden files in /tmp (VNC X11 sockets) | `[".font-unix", ".XIM-unix", ".ICE-unix"]` |
| `whitelist.tmpfs_mounts` | Whitelist expected tmpfs mounts beyond hard-coded list | `["/var/tmp"]` |
| `whitelist.secret_exclude_paths` | Skip operational config files in secret pattern scan | `["/root/.hermes/config.yaml", "/root/.hermes/.env"]` |
| `whitelist.proc_hollow_exclude_pids` | Exclude specific PIDs from anonymous mapping checks | `[449]` |
| `whitelist.proc_hollow_exclude_comms` | Exclude processes by comm name (handles changing PIDs) | `["node"]` |
| `whitelist.outbound_destinations` | Suppress outbound connection alerts for known-good destinations (by CIDR, IP, and/or process name) | `[{cidr: 149.154.160.0/20, process: hermes, reason: Telegram MTProto API}]` |
| `whitelist.persist_exclude_prefixes` | Ignore secmon/hermes own systemd units in persistence diff | `["/etc/systemd/system/secmon-", "/etc/systemd/system/hermes-"]` |
| `realtime.fail2ban_min_new_bans` | Batch threshold for fail2ban alerts — individual bans are suppressed below this count per tick | `5` |
| `hardening.skip_root_login_check` | Allow root SSH login without audit warning | `True` |
| `hardening.skip_fw_policy_check` | Don't flag INPUT ACCEPT on remote servers (lockout risk) | `True` |
| `hardening.skip_kernel_modules_check` | Don't flag modules enabled (can't disable at runtime) | `True` |
| `sysctl.expected_values` | Accept multiple valid sysctl values | `kernel.kptr_restrict: ["1", "2"]` |

## When a Config Key Doesn't Exist Yet

If a check is hard-coded and you need to make it config-aware:

1. **Add the key to `default_config()` in `src/secmon/config.py`** with a sensible default.
2. **Patch the relevant audit module** (`src/secmon/audit/<layer>.py`) to `cfg.get(...)` instead of hard-coding.
3. **Update `/etc/secmon/config.yaml`** with the actual value.
4. **Update `config.yaml.example`** with the documented default.
5. **Commit and push** to both repos.

### Example pattern (Python):

```python
# In config.py default_config():
"whitelist": {
    ...
    "my_new_exclusion": [],
}

# In audit module:
exclusions = set(cfg.get("whitelist", {}).get("my_new_exclusion", []))
if entry in exclusions:
    continue
```

### Full add-a-key checklist

| File | What to add |
|------|-------------|
| `src/secmon/config.py` | Default value in `default_config()` |
| `src/secmon/audit/<layer>.py` | `cfg.get(...)` fallback logic |
| `/etc/secmon/config.yaml` | Actual runtime value |
| `config.yaml.example` | Documented example |
| `README.md` | Brief entry in audit exclusion tuning table |

## Hardening Workflow

1. Run `secmon --audit` → get findings by severity
2. For each CRITICAL/HIGH: fix the issue, tune false positives via config, or accept
3. Re-run audit to verify score dropped
4. Persist fixes, then commit to git

## Common False Positives & Fixes

| Finding | Why false positive | Fix |
|---------|-------------------|-----|
| `Unexpected nameservers: [1.1.1.1]` | Cloudflare DNS intentional | Add to `dns.expected_nameservers` |
| `Unexpected tmpfs: /var/tmp` | systemd tmpfs with noexec | Add to `whitelist.tmpfs_mounts` |
| `proc_hollow_anon: pid 449` | unattended-upgrades-shutdown (Python) | Add to `whitelist.proc_hollow_exclude_pids` |
| `proc_hollow_anon: pid N` (node/Python) | JIT allocators (Pyright LSP, etc.) | Add to `whitelist.proc_hollow_exclude_comms` |
| `secret_pattern` in config.yaml / .env | Real config files | Add to `whitelist.secret_exclude_paths` |
| `hidden_tmp: .font-unix` (et al.) | X11 sockets from VNC | Add to `whitelist.hidden_tmp_entries` |
| `fw_policy: INPUT not DROP` | Lockout risk on remote server | `hardening.skip_fw_policy_check: True` |
| `kernel_modules_enabled` | Can only disable at boot | `hardening.skip_kernel_modules_check: True` |
| `kptr_restrict=2` vs expected 1 | 2 is stricter than 1 | `sysctl.expected_values: {kptr_restrict: ["1", "2"]}` |
| `persist_modified: systemd_timers` | Secmon's own tasks | Add to `whitelist.persist_exclude_prefixes` |
| `Long-lived outbound to 149.154.x.x (hermes)` | Hermes persistent Telegram MTProto connection — expected `hermes` behavior | Add to `whitelist.outbound_destinations`: `{cidr: 149.154.160.0/20, process: hermes}` (CIDR + process must both match) |
| `New SSH ban: X.X.X.X` (per-IP) | Routine brute-force under constant attack — individual bans are noise | Set `realtime.fail2ban_min_new_bans: 5` to batch alerts on bursts; anomaly detection on `f2b_banned_count` catches statistical surges |

### Persistence Checklist

| Fix | Persistence |
|-----|-------------|
| sysctl | `/etc/sysctl.d/99-hardening.conf` + `sysctl --system` |
| iptables | `iptables-save > /etc/iptables/rules.v4` |
| config exclusions | `/etc/secmon/config.yaml` |
| sshd config | `sshd -t` then `systemctl reload sshd` |

## Pitfall: Don't Just Silence

Resist suppress-lists without understanding the finding. Either fix the issue or consciously accept via config and **document why**.