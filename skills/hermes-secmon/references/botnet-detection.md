# Botnet Detection & Subnet Blocking

## Concept

When auth logs show many similar IPs hitting SSH, they're often botnets using multiple IPs from the same /24 subnet at bulletproof hosting providers. fail2ban alone is too slow — block the entire /24 at iptables level.

## Detection Algorithm

1. Extract all IPs from `journalctl --since '{lookback_hours} hours ago'` auth output
2. Count hits per IP, group by /24 subnet
3. For each /24:
   - **Botnet trigger:** ≥ `min_ips_per_subnet` (default 3) unique IPs AND ≥ `min_hits_per_subnet` (default 100) total hits
   - **Heavy scanner trigger:** ≥ `solo_min_hits` (default 500) total hits from any number of IPs
4. If triggered:
   - Check whitelist (own IP prefix, RFC 1918). Skip if whitelisted.
   - Check if already in iptables BOTNET chain. Skip if already blocked.
   - Add: `iptables -A BOTNET -s {subnet} -j DROP`
   - Log to botnet log file
5. Persist: `iptables-save > /etc/iptables/rules.v4`

## iptables Chain Setup

```bash
iptables -N BOTNET 2>/dev/null       # Create chain (idempotent)
iptables -I INPUT -j BOTNET 2>/dev/null  # Insert as first rule
```

## Whitelist (NEVER block these)

- Server's own public IP prefix
- RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Loopback: 127.0.0.0/8

## Known Bulletproof Hosting ASNs

Maintain a configurable list of /24 prefixes from known bulletproof ASNs:
- AS48090 / AS47890 (DMZHOST / UNMANAGED LTD)
- AS214472 (PFCLOUD / Storm Industries)
- AS197170 (TechTies)
- AS200730 (ISAEV)
- AS209588 (GLOBALHOST)
- AS215929 (DATACAMPUS)

The prefix list should be in the config file, not hardcoded, since it changes periodically.

## Boot Persistence

Two mechanisms:
1. **iptables-persistent:** `netfilter-persistent save` after each block
2. **Systemd oneshot service:** Restores from `/etc/iptables/rules.v4` on boot

## Unblocking Utility

Provide a utility to:
- List all blocked subnets with rule numbers
- Unblock a specific subnet
- Flush entire BOTNET chain (emergency recovery)

## Pitfalls

- **Whitelist first:** Always add own public IP before bulk-blocking. Losing SSH requires console/VNC recovery.
- **RIPE API too slow:** `curl stat.ripe.net` often times out from server IPs. Hardcode known prefixes.
- **ipset empty chain:** Don't add iptables rule referencing empty ipset — matches nothing, gives false confidence.
- **IPv6:** These examples use iptables (IPv4) only. If IPv6 is enabled, create ip6tables BOTNET chain too.
- **journalctl scope:** `--since "24 hours ago"` may not cover full 24h if log rotation is aggressive. Use `--since "yesterday"` as fallback.
