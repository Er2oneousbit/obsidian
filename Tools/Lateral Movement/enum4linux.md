# enum4linux-ng

**Tags:** `#enum4linux` `#smb` `#lateral` `#enumeration` `#samba` `#activedirectory` `#userenumeration`

Rewrite of the classic enum4linux — automated SMB/Samba enumeration tool. Wraps smbclient, rpcclient, net, and nmblookup into one tool for bulk enumeration of users, groups, shares, password policies, and OS info. The `-A` flag runs everything. Use for quick initial enumeration of Windows/Samba targets. Pre-installed on Kali.

**Source:** https://github.com/cddmp/enum4linux-ng — pre-installed on Kali as `enum4linux-ng`
**Legacy:** Original `enum4linux` also available — `enum4linux-ng` preferred.

```bash
# Full enumeration (all checks)
enum4linux-ng 192.168.1.10 -A

# With credentials
enum4linux-ng 192.168.1.10 -A -u user -p Password
```

---

## Usage

```bash
# Full enumeration — null session
enum4linux-ng 192.168.1.10 -A

# Full enumeration — authenticated
enum4linux-ng 192.168.1.10 -A -u Administrator -p Password
enum4linux-ng 192.168.1.10 -A -u 'DOMAIN\user' -p Password

# Pass the Hash
enum4linux-ng 192.168.1.10 -A -u Administrator -p '' --pw-nt-hash NTLMhash

# Include service enumeration
enum4linux-ng 192.168.1.10 -A -C

# Export results
enum4linux-ng 192.168.1.10 -A -oJ results.json
enum4linux-ng 192.168.1.10 -A -oY results.yaml
```

---

## Targeted Enumeration Flags

```bash
# Users only
enum4linux-ng 192.168.1.10 -U -u user -p Password

# Groups only
enum4linux-ng 192.168.1.10 -G -u user -p Password

# Shares only
enum4linux-ng 192.168.1.10 -S -u user -p Password

# Password policy
enum4linux-ng 192.168.1.10 -P -u user -p Password

# OS info
enum4linux-ng 192.168.1.10 -O

# RID brute force (user enum without SAMR)
enum4linux-ng 192.168.1.10 -R -u user -p Password
enum4linux-ng 192.168.1.10 -R 500-2000 -u user -p Password   # custom RID range

# Workgroup / NetBIOS info
enum4linux-ng 192.168.1.10 -N
```

---

## What Gets Enumerated (`-A`)

| Check | What's Found |
|---|---|
| NetBIOS info | Hostname, workgroup, MAC |
| OS info | Windows version, build |
| SMB dialect | SMBv1/2/3 support |
| Shares | All accessible shares + permissions |
| Users | Username, RID, account flags |
| Groups | Domain groups + membership |
| Password policy | Min length, lockout threshold, complexity |
| RID brute | Additional users via RID cycling |

---

## Legacy enum4linux

```bash
# Original enum4linux (Python 2 — less reliable but still works)
enum4linux -a 192.168.1.10
enum4linux -a -u user -p Password 192.168.1.10
enum4linux -U 192.168.1.10     # users only
enum4linux -S 192.168.1.10     # shares only
enum4linux -P 192.168.1.10     # password policy
enum4linux -r 192.168.1.10     # RID brute
```

---

## OPSEC Notes

- enum4linux-ng generates multiple SMB/RPC connections in rapid succession — obvious in traffic analysis
- RID brute (`-R`) makes many SAMR calls — generates significant RPC traffic
- Null session attempts generate **4625** (failed logon) on hardened targets
- Authenticated runs generate **4624** and multiple SAMR/MSRPC audit events

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
