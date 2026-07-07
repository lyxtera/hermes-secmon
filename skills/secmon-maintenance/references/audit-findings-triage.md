# Audit Findings Triage — Common False Positive Patterns

Systematic approach for investigating and resolving secmon audit findings. Run `secmon --audit` first, then triage each HIGH/MEDIUM finding.

## 1. port_removed — Transient Hermes Browser Ports

**Symptom:** `Listening port removed: 45123`, `Listening port removed: 39333`

**Root cause:** These are ports from Hermes' own browser automation agent (`agent-browser-l` / `chromium`). They appear when the browser tool runs and disappear when the session ends. Ports are **randomly allocated** from the kernel's ephemeral range (32768–60999 on Linux) — hardcoding specific numbers is fragile and won't catch future ports.

**Verification:** Check what process owned the port from the state file baseline:
```bash
python3 -c "import json; d=json.load(open('/var/lib/secmon/state.json')); print(d.get('audit_baseline',{}).get('known_ports',{}).get('45123',''))"
```

**Fix — process-name matching (preferred):**

Ports are ephemeral — the correct approach is to match by **process name**, not port number. The code in `network.py` reads `whitelist.port_removed_processes` and checks the baseline's process name:

*Step 1: Add to config (`/etc/secmon/config.yaml`)*
```yaml
whitelist:
  port_removed_processes:
    - chromium
    - agent-browser-l
```

*Step 2: The code in `network.py` checks the baseline entry for the process name:*
```python
transients = cfg.get("whitelist", {}).get("port_removed_processes", [])
if transients:
    line = known_ports.get(str(port), "")
    m = re.search(r'"([^"]+)"', line)
    if m and m.group(1) in transients:
        continue  # skip — transient browser process
```

**Pitfall:** Do NOT use `whitelist.port_removed` with hardcoded port numbers. Ports 45123, 39333 were just one session's random assignment. Browser agents will get different ports next time, and static port numbers in the config will miss them. Process-name matching catches all ephemeral ports regardless of number.

## 2. secret_pattern — Hermes Config & .env Files

**Symptom:** `Secret material pattern in /root/.hermes/...`

**Root cause:** The secrets scan walks `/root/` and finds:
- `/root/.hermes/config.yaml` — legitimately contains `api_key` values
- `/root/.hermes/.env` — legitimately contains API keys
- `/root/.hermes/state-snapshots/` — backup copies of the above
- Skill README files mentioning API key env vars (e.g. `STITCH_API_KEY` in docs)

These are **false positives** — Hermes config is supposed to hold credentials.

**Verification:** The scan uses these patterns:
```python
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*="),
    re.compile(r"api[_-]?key\s*[:=]", re.I),
]
```

Check what files matched by running the scan locally:
```python
import os, re
patterns = [re.compile(p) for p in [
    r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
    r"AWS_SECRET_ACCESS_KEY\s*=",
    r"api[_-]?key\s*[:=]",
]]
for root in ['/root', '/tmp']:
    for dirpath, _, files in os.walk(root):
        if dirpath.count(os.sep) > 3: continue
        for fname in files:
            fp = os.path.join(dirpath, fname)
            try:
                sample = open(fp, errors='replace').read(8000)
                for pat in patterns:
                    if pat.search(sample):
                        print(f"[MATCH] {pat.pattern[:40]} -> {fp}")
            except: pass
```

**Fix (two options):**

**Option A — Whitelist (best for files that must exist):** Add false positive paths to `whitelist.secret_exclude_paths` in `/etc/secmon/config.yaml`:
```yaml
whitelist:
  secret_exclude_paths:
    - /root/.hermes/config.yaml
    - /root/.hermes/.env
    - /root/.hermes/state-snapshots/
    - /root/.hermes/skills/stitch-design/README.md
    # Add any other false-positive paths
```

**Option B — Remove the folder (user's preferred approach for temp/cache dirs):** If the folder is a temporary backup that doesn't need to persist (e.g. `state-snapshots/`), just delete it:
```bash
rm -rf /root/.hermes/state-snapshots/
```
This is cleaner than whitelisting — no maintainance burden.

**Pitfall:** The check is `fp in exclude_paths` (exact match), not prefix match. Filenames like `config.yaml` and `.env` inside `state-snapshots/*/` are exact-match, so whitelisting works. But new files under that prefix won't be caught without adding them.

## 3. persist_modified systemd_timers — Dynamic Hash

**Symptom:** `Modified persistence entry: systemd_timers`

**Root cause:** The `_collect_persistence_entries()` function in `threat_intel.py` hashes the full output of `systemctl list-timers --all --no-pager`, which includes columns `NEXT`, `LEFT`, `LAST`, `PASSED` that change every time a timer fires. Every audit flags a "modification".

**Verification:** Compare current and previous hashes:
```bash
systemctl list-timers --all --no-pager | sha256sum
python3 -c "import json; d=json.load(open('/var/lib/secmon/state.json')); print(d.get('audit_baseline',{}).get('persistence',{}).get('systemd_timers',''))"
```

**Fix applied in this session:** Strip dynamic timing columns before hashing, keeping only stable UNIT and ACTIVATES columns:

```python
timers = run_cmd_safe(["systemctl", "list-timers", "--all", "--no-pager"])
if timers.strip():
    stable = set()
    for line in timers.splitlines():
        if line.strip() and not line.startswith("NEXT"):
            parts = line.rsplit(None, 2)  # split from right: UNIT | ACTIVATES
            if len(parts) >= 2:
                stable.add(f"{parts[-2]} {parts[-1]}")
    hash_input = "\n".join(sorted(stable))
    entries["systemd_timers"] = hashlib.sha256(hash_input.encode()).hexdigest()
```

The hash is now deterministic across runs (same timer units = same hash). Runs twice produces identical output.

**Common timer baseline:** Standard Debian: `apt-daily.timer`, `apt-daily-upgrade.timer`, `dpkg-db-backup.timer`, `e2scrub_all.timer`, `fstrim.timer`, `systemd-tmpfiles-clean.timer`.

## 4. modified_bin — /sbin/ → /usr/sbin/ Symlink False Positive

**Symptom:** `Recent binary not in dpkg: /sbin/bpftool` (or any file in `/sbin/`)

**Root cause:** On Debian 12 (usrmerge), `/sbin` is a symlink to `/usr/sbin`. The audit code runs `dpkg -S /sbin/bpftool`, which fails because dpkg tracks the canonical path (`/usr/sbin/bpftool`), not the symlink path (`/sbin/bpftool`). Any recently-upgraded package in `/sbin/` will appear as "not in dpkg".

**Verification:**
```bash
# Is /sbin a symlink to usr/sbin?
ls -la /sbin | head -3

# Check if the real path is in dpkg
dpkg -S "$(readlink -f /sbin/bpftool)" 2>&1

# Are the two paths the same file?
md5sum /sbin/bpftool /usr/sbin/bpftool 2>/dev/null
```

**Fix:** Resolve symlinks before passing to `dpkg -S` in `threat_intel.py`:

```python
# Before (fails on /sbin/ symlinks):
dpkg = run_cmd_safe(["dpkg", "-S", fp])

# After (resolves /sbin → /usr/sbin first):
real_fp = os.path.realpath(fp)
dpkg = run_cmd_safe(["dpkg", "-S", real_fp])
```

**Pitfall:** This also fires temporarily right after applying kernel security upgrades — the upgraded binary's mtime falls within the 7-day recency window. After fixing the symlink resolution, it resolves immediately (next audit cycle).

## 5. sec_updates — Security Upgrades Pending

**Symptom:** `X security upgrades pending`

**Root cause:** The audit runs `apt list --upgradable` and counts lines containing "security". Standard Debian kernel security updates are common and expected.

**Verification:**
```bash
apt list --upgradable 2>/dev/null | grep -i security
```

**Fix:** Apply the upgrades:
```bash
apt update && apt upgrade -y bpftool linux-image-amd64 linux-libc-dev
```

**Side-effect:** Applying security upgrades temporarily triggers a `modified_bin` finding on any binary whose mtime falls within the 7-day recency window. This self-resolves after the next audit cycle once the recency window passes. To eliminate it immediately, patch the symlink resolution in `threat_intel.py` (see section 4).

**Common packages:** `linux-image-amd64`, `linux-libc-dev`, `bpftool` (kernel security updates), `chromium`, `chromium-common` (browser security updates).

## 6. sysctl — Expected Value Mismatches

**Symptom:** `sysctl: key=value (expected expected_value)`

**Root cause:** System hardening parameters differ from secmon's defaults. Some values have configurable overrides via `sysctl.expected_values`.

**Fix:** Add overrides to `/etc/secmon/config.yaml`:
```yaml
sysctl:
  expected_values:
    kernel.kptr_restrict:
      - '1'
      - '2'
```

This allows `kernel.kptr_restrict=2` (Ubuntu default) instead of requiring `=1`.

## 7. NC-10-supply — Missing debsums

**Symptom:** `debsums not installed (recommended)`

**Root cause:** The `debsums` package is not installed. This is LOW severity and can be deferred.

**Fix:**
```bash
apt install -y debsums
```

## 8. NC-9-newprog — BPF Programs from Transient Package Installs (Docker, etc.)

**Symptom:** `New BPF program: 684`, `New BPF program: 685`, `New BPF program: 686`

**Root cause:** Installing Docker (or any container runtime) triggers systemd to load cgroup BPF programs — specifically `cgroup_skb` (firewall, `sd_fw_egress`/`sd_fw_ingress`) and `cgroup_device` (device control, `sd_devices`) programs. These are **kernel-level artifacts**, not files — `apt purge` does not remove them. They persist in kernel memory until the cgroup hierarchy reorganizes or the system reboots.

**Verification:**
```bash
# List all BPF programs, look for Docker/systemd cgroup programs
bpftool prog list

# Check if a program is from systemd (cgroup type, sd_* name)
bpftool prog show id 684

# Check when it was loaded
bpftool prog show id 684 | grep loaded_at
```

**Resolution:** These are **self-resolving after one audit cycle**. The secmon baseline auto-updates on line 144 of `process.py` — the BPF IDs are saved after each audit, so the next run absorbs them. No config or code change needed:

```
Initial run:  baseline=[644-653],    current=[644-653,684-686]  → 3 HIGH findings reported
Run 2:        baseline=[644-653,684-686],  current=[644-653]     → no findings (Docker was removed)
```

Wait for one more audit cycle and the finding disappears. If Docker is **still installed** (not uninstalled), the finding self-resolves on the *next* audit (baseline auto-updates).

**Immediate cleanup (when Docker is uninstalled and you want zero traces):** Detach BPF programs or reboot:
```bash
# Option A: Reboot (clears all BPF programs, let systemd reload its own)
reboot

# Option B: Detach cgroup programs (less disruptive — systemd self-heals)
bpftool cgroup detach /sys/fs/cgroup/unified/ cgroup_device pinned /sys/fs/cgroup/unified/ 2>/dev/null || true
```
In practice, waiting for the next audit cycle is sufficient — the baseline absorbs the change automatically.

**Prevention:** If you regularly install/uninstall container runtimes, pre-prune the BPF state before the audit runs. The uninstall script should include a BPF baseline reset:
```bash
# After purging Docker, reset secmon BPF baseline so next audit doesn't flag stale IDs
python3 -c "
import json
s = json.load(open('/var/lib/secmon/state.json'))
s.get('audit_baseline', {}).pop('bpf_programs', None)
json.dump(s, open('/var/lib/secmon/state.json', 'w'))
"
```

**Key distinction:** This is different from SUID or port_removed false positives:
- SUID: filesystem-level, needs a whitelist entry
- Port removed: process-level, needs process-name whitelisting
- BPF programs: kernel-level artifacts, self-resolving via baseline auto-update

## General Triage Workflow

When investigating any HIGH/MEDIUM finding:

```bash
# 1. Run the audit and save JSON output
secmon --audit > /tmp/audit_latest.txt

# 2. Read the source code for the specific check
grep -r "check_id\|port_removed\|secret_pattern\|persist_modified" ~/.hermes/plugins/secmon/src/ --include="*.py"

# 3. Check the state file for baselines
python3 -c "import json; d=json.load(open('/var/lib/secmon/state.json')); import pprint; pprint.pprint(d.get('audit_baseline',{}))"

# 4. Run the specific check manually to reproduce
# (varies by check — see the source for exact commands)

# 5. Apply fix (prefer config whitelist over code patch, prefer code patch over workaround)
# 6. Verify by re-running the audit
secmon --audit | head -20
```

## References

- State file: `/var/lib/secmon/state.json`
- Config: `/etc/secmon/config.yaml` (requires sudo)
- Source: `~/.hermes/plugins/secmon/src/secmon/`
- Tests: `cd ~/.hermes/plugins/secmon && bash -c "source venv/bin/activate && python -m pytest tests/ -v --tb=short --no-cov"`