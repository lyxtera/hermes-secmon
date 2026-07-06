# Outbound Connection Check (TC-8)

## Source

`src/secmon/checks/outbound.py` — runs every tick from `ss -tnp state established`.

## How It Works

1. Runs `ss -tnp state established` to get all current TCP connections
2. Parses each line with `re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)`
3. Takes **pairs[1]** (index 1) as the **peer/remote** address — the actual destination
4. Skips private/loopback destinations
5. Checks against `whitelist.outbound_destinations` config
6. If not whitelisted, runs 5 checks:
   - **New privileged** — new outbound from root/www-data/nginx/apache
   - **Long-lived** — same connection tracked >1 hour
   - **Suspicious port** — matches configurable `suspicious_ports` list
   - **Direct-IP HTTPS** — HTTPS (443/8443) to a raw IP, not a hostname (C2 pattern)
   - **C2 port + privileged** — common C2 port × privileged process

## The Regex Bug (Fixed)

**Before:** `r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s"` — `re.search` finds the FIRST IP:port, which is the **local** address. This caused false alerts like:
```
"Long-lived outbound connection to 188.130.207.113:22 (sshd)"
```
(188.130.207.113 is the server's own IP, and :22 is the local SSH listen port — not a destination.)

**After:** `re.findall(...)` captures ALL IP:port pairs. `pairs[1]` is the peer address — the actual remote destination.

## Whitelist System

Config key: `whitelist.outbound_destinations`

Each entry supports optional:
- `cidr` — CIDR range (e.g. `149.154.160.0/20`)
- `ip` — exact IP (e.g. `203.0.113.5`)
- `process` — process name to match (e.g. `hermes`, `sshd`)

A connection matches if ALL specified fields match. Omitted fields are wildcards.

### Default Entries

```yaml
whitelist:
  outbound_destinations:
    - cidr: "149.154.160.0/20"
      process: "hermes"
      reason: "Telegram MTProto API"
    - cidr: "91.108.56.0/22"
      process: "hermes"
      reason: "Telegram MTProto API"
```

## Testing Pattern

Test mock output must include BOTH local and peer columns to match realistic `ss` format:

```python
# WRONG — only one IP:port, regex can't find peer:
mock_commands(["ss", "-tnp", "state", "established"], "1.2.3.4:4444 users:((")

# RIGHT — local + peer, regex takes 2nd pair:
mock_commands(
    ["ss", "-tnp", "state", "established"],
    "0.0.0.0:50000        1.2.3.4:4444      users:((",
)
```

Run tests via the venv:
```bash
cd ~/.hermes/plugins/secmon
bash -c "source venv/bin/activate && python -m pytest tests/test_checks.py -v --tb=short --no-cov -k 'outbound'"
```