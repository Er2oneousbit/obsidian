# rpcclient

**Tags:** `#rpcclient` `#rpc` `#smb` `#lateral` `#enumeration` `#activedirectory` `#userenumeration`

Linux RPC client for interacting with Windows MS-RPC services over SMB. Enumerates users, groups, shares, password policies, and domain info. Especially useful for null session enumeration on older systems and targeted user/group lookups when LDAP isn't available. Pre-installed on Kali.

**Source:** Pre-installed on Kali (`samba-common-bin`)

```bash
# Null session
rpcclient -U '' -N 192.168.1.10

# Authenticated
rpcclient -U 'user%Password' 192.168.1.10
```

---

## Connecting

```bash
# Null session (anonymous)
rpcclient -U '' -N 192.168.1.10
rpcclient -U '%' 192.168.1.10        # alternate null session syntax

# Authenticated
rpcclient -U 'Administrator%Password' 192.168.1.10
rpcclient -U 'DOMAIN\user%Password' 192.168.1.10

# Pass the Hash
rpcclient -U 'Administrator%NTLMhash' 192.168.1.10 --pw-nt-hash

# Kerberos
KRB5CCNAME=ticket.ccache rpcclient -U 'DOMAIN\user' --use-kerberos=required 192.168.1.10

# Run single command (non-interactive)
rpcclient -U 'user%Password' 192.168.1.10 -c "enumdomusers"
```

---

## Server & Domain Info

```bash
# In rpcclient session:
srvinfo                    # server info (OS, domain, hostname)
enumdomains                # list all domains
querydominfo               # domain info (users, groups, policy)
lsaquery                   # LSA policy info
```

---

## User Enumeration

```bash
# List all domain users
enumdomusers

# User info by RID
queryuser 0x1f4            # RID 500 = Administrator
queryuser 0x44f            # convert decimal: 1103 = 0x44F

# User info by username
lookupnames Administrator
lookupnames "Domain Admins"

# RID brute force — enumerate users by incrementing RID
# (useful when direct enumdomusers is blocked)
for i in $(seq 500 1100); do
    rpcclient -U 'user%Password' 192.168.1.10 -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | \
    grep -i "User Name\|user_rid\|group_rid" | tr '\n' ' '
    echo
done
```

---

## Group Enumeration

```bash
# List all domain groups
enumdomgroups

# List group members by RID
querygroupmem 0x200        # Domain Admins (RID 512)
querygroupmem 0x201        # Domain Users (RID 513)

# Local groups
enumalsgroups domain
enumalsgroups builtin
```

---

## Share Enumeration

```bash
# List all shares
netshareenumall

# Info on specific share
netsharegetinfo C$
netsharegetinfo SYSVOL
```

---

## Password Policy

```bash
# Domain password policy
getdompwinfo

# User password info
getusrdompwinfo 0x1f4      # Administrator's password info
```

---

## Printer Enumeration (PrinterBug / coercion check)

```bash
# List printers (also used to test PrinterBug coercion path)
enumprinters

# Remote print request (triggers auth — use Responder to catch hash)
# Not directly via rpcclient — use impacket's printerbug.py instead
```

---

## Useful One-Liners

```bash
# Enumerate all users non-interactively
rpcclient -U 'user%Password' 192.168.1.10 -c "enumdomusers" | \
  grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]'

# Get all user RIDs then query each
rpcclient -U 'user%Password' 192.168.1.10 -c "enumdomusers" 2>/dev/null | \
  grep -oP 'rid:\[0x[0-9a-f]+\]' | grep -oP '0x[0-9a-f]+' | while read rid; do
    rpcclient -U 'user%Password' 192.168.1.10 -c "queryuser $rid" 2>/dev/null | \
    grep "User Name\|Description"
  done

# Null session user enum
rpcclient -U '' -N 192.168.1.10 -c "enumdomusers"
```

---

## Common RPC Commands Reference

| Command | Description |
|---|---|
| `srvinfo` | Server info |
| `enumdomains` | List domains |
| `querydominfo` | Domain info |
| `enumdomusers` | List all users |
| `queryuser <RID>` | User details by RID |
| `lookupnames <name>` | Resolve name to SID/RID |
| `enumdomgroups` | List domain groups |
| `querygroupmem <RID>` | Group members |
| `netshareenumall` | List all shares |
| `netsharegetinfo <share>` | Share details |
| `getdompwinfo` | Password policy |
| `enumprinters` | List printers |
| `enumprivs` | List privileges |

---

## OPSEC Notes

- RPC over SMB generates Event ID **4624** (logon type 3) on the target
- Null session attempts against modern systems (Server 2016+) mostly fail — generates **4625**
- User enumeration via `enumdomusers` generates SAMR audit events if SAMR auditing is enabled
- RID brute force generates many RPC calls — noisy on monitored networks

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
