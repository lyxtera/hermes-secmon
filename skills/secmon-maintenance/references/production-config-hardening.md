# Production Config Hardening — This Server

Applied 2026-07-12 during the `parent_process` outbound whitelist upgrade.

## Files Made Immutable (`chattr +i`)

| File | Flag | Why |
|------|------|-----|
| `/etc/secmon/config.yaml` | `----i---------e--` | Whitelist — attacker could whitelist own processes |
| `src/secmon/checks/outbound.py` | `----i---------e--` | Parent-tree logic — attacker could bypass process ancestry check |
| `src/secmon/audit/file_integrity.py` | `----i---------e--` | Detects tampering — attacker could remove itself from CRITICAL_FILES |
| `src/secmon/modes/audit_mode.py` | `----i---------e--` | Audit entrypoint — attacker could suppress integrity checks |
| `src/secmon/audit/__init__.py` | `----i---------e--` | Audit orchestrator |
| `src/secmon/checks/__init__.py` | `----i---------e--` | Check runner — attacker could disable outbound check entirely |

## Integrity Monitoring

All above paths added to `CRITICAL_FILES` in `file_integrity.py`. SHA-256 baseline computed on first `--audit` after the change. Any modification detected as `🔴 CRITICAL — file_changed`.

## Unlock Helper

`/usr/local/bin/secmon-unlock` — temporarily removes immutable flags, runs command, re-locks.

## Parent-Process Outbound Whitelist

```yaml
outbound_destinations:
  - process: git-remote-http
    parent_process: hermes
  - process: git-remote-https
    parent_process: hermes
  - process: hermes
```

This allows git operations only when spawned by Hermes (ancestor chain includes `hermes` PID). A standalone `git push` by an attacker will alert because the process tree has no `hermes` ancestor.

## Current Production Config

```yaml
whitelist:
  own_ip: 188.130.207.113
  outbound_destinations:
    - process: git-remote-http
      parent_process: hermes
    - process: git-remote-https
      parent_process: hermes
    - process: hermes
```
