# Firewall Protection Chains Setup

Creates the iptables port-scan protection chains that `secmon --audit` checks for (SCANS, PORT_SCAN, ANTI_SCAN, BAD_FLAGS). Run when audit shows "Missing protection chain: SCANS / PORT_SCAN / ANTI_SCAN / BAD_FLAGS" (LOW, layer 2).

## One-shot Setup

```bash
# Create chains
for chain in SCANS PORT_SCAN ANTI_SCAN BAD_FLAGS; do
  iptables -N "$chain" 2>/dev/null || echo "$chain exists"
done

# SCANS — NULL + XMAS scan detection
iptables -A SCANS -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL_SCAN:"
iptables -A SCANS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A SCANS -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS_SCAN:"
iptables -A SCANS -p tcp --tcp-flags ALL ALL -j DROP

# PORT_SCAN — SYN+RST + FIN+SYN detection
iptables -A PORT_SCAN -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "SYN_RST:"
iptables -A PORT_SCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A PORT_SCAN -p tcp --tcp-flags FIN,SYN FIN,SYN -j LOG --log-prefix "FIN_SYN:"
iptables -A PORT_SCAN -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP

# ANTI_SCAN — FIN + PSH scan detection
iptables -A ANTI_SCAN -p tcp --tcp-flags FIN,ACK FIN -j LOG --log-prefix "FIN_SCAN:"
iptables -A ANTI_SCAN -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A ANTI_SCAN -p tcp --tcp-flags PSH,ACK PSH -j LOG --log-prefix "PSH_SCAN:"
iptables -A ANTI_SCAN -p tcp --tcp-flags PSH,ACK PSH -j DROP

# BAD_FLAGS — invalid flag combinations
iptables -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-prefix "BAD_FLAGS:"
iptables -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "BAD_FLAGS_ALL:"
iptables -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Wire into INPUT chain (insert before any ACCEPT rules)
iptables -I INPUT 1 -j SCANS
iptables -I INPUT 2 -j PORT_SCAN
iptables -I INPUT 3 -j ANTI_SCAN
iptables -I INPUT 4 -j BAD_FLAGS
```

## Persist Across Reboots

```bash
iptables-save > /etc/iptables/rules.v4
```

On Debian, `netfilter-persistent` auto-loads this on boot. Verify with `systemctl status netfilter-persistent`.

## Verification

```bash
for chain in SCANS PORT_SCAN ANTI_SCAN BAD_FLAGS; do
  count=$(iptables -L "$chain" -n | wc -l)
  echo "$chain: $((count - 3)) rules"  # subtract header lines (3)
done
```

Expected: each chain has 4+ rules (2 LOG + 2 DROP pairs).