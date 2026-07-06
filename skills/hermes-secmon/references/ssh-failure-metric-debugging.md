# SSH Failure Metric Debugging

## Problem Pattern

`ssh_failed_24h` metric stuck at 0 despite visible SSH attack activity (fail2ban bans, "Invalid user" entries, etc.).

## Root Cause

The metric collector only counts `"Failed password"` strings from `journalctl`. On hardened servers with `PasswordAuthentication no`, attackers never reach the password authentication stage. SSH rejects them earlier, generating different log signals:

| Signal | Source | Meaning |
|--------|--------|---------|
| `Failed password` | sshd | Traditional password rejection |
| `Invalid user` | sshd | Username not found / not allowed |
| `Disconnected from authenticating user` | sshd | Preauth rejection (password auth disabled, key mismatch) |
| `maximum authentication attempts exceeded` | sshd | Hit MaxAuthTries limit |
| `error: PAM: Authentication failure` | PAM | Backend auth module failure |

## Diagnosis Steps

1. **Check journal directly:**
   ```bash
   journalctl --since "24 hours ago" | grep -c "Failed password"
   journalctl --since "24 hours ago" | grep -c "Invalid user"
   journalctl --since "24 hours ago" | grep -c "Disconnected from authenticating user"
   ```

2. **Check auth.log (rsyslog bypasses journal):**
   ```bash
   grep "Failed password" /var/log/auth.log | tail -5
   grep "Invalid user" /var/log/auth.log | tail -5
   ```

3. **Check SSH config to understand which signals exist:**
   ```bash
   sshd -T | grep -E "passwordauthentication|pubkeyauthentication|permitrootlogin"
   ```
   - `PasswordAuthentication no` → expect 0 "Failed password", many "Disconnected from authenticating user"
   - `PasswordAuthentication yes` → expect both "Failed password" and "Invalid user"

4. **Check fail2ban backend** — fail2ban reads auth.log directly (`backend = polling`), so it bans even when journal doesn't have "Failed password":
   ```bash
   grep "backend" /etc/fail2ban/jail.local
   ```

## Fix Pattern

Update `_collect_ssh_metrics()` to count ALL auth-failure signals:

```python
_AUTH_FAILURE_PATTERNS = (
    "Failed password",
    "Invalid user",
    "Disconnected from authenticating user",
    "maximum authentication attempts exceeded",
    "error: PAM: Authentication failure",
)

metrics["ssh_failed_24h"] = sum(out.count(p) for p in _AUTH_FAILURE_PATTERNS)
```

## Test Fix Pattern

When changing metric counting, update test mock data to include all signal types:

```python
mock_commands(["journalctl", "--since", "24 hours ago"],
    "Failed password\nInvalid user\nDisconnected from authenticating user 1.2.3.4\n")
# Expected: 3 (one of each pattern)
assert m["ssh_failed_24h"] == 3
```

## Related Pitfall: CHECKS List Monkeypatching

The `CHECKS` list in `checks/__init__.py` captures function references at import time. `monkeypatch.setattr("secmon.checks.fail2ban.check", boom)` replaces the module attribute but NOT the reference already in `CHECKS`. To patch checks for exception-testing:

```python
from secmon.checks import CHECKS
patched = [(name, boom if name == "fail2ban" else fn) for name, fn in CHECKS]
monkeypatch.setattr("secmon.checks.CHECKS", patched)
```
