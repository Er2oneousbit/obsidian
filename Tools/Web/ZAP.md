# ZAP (Zed Attack Proxy)

**Tags:** `#zap` `#proxy` `#webappsec` `#owasp` `#scanner` `#web`

OWASP's open-source web application security testing platform. Combines an intercept proxy, active/passive scanner, spider, fuzzer, and scripting engine. Free alternative to Burp Pro — the active scanner is unrestricted. Particularly strong for API testing with OpenAPI/SOAP/GraphQL support and CI/CD pipeline integration.

**Source:** https://www.zaproxy.org
**Install:** `sudo apt install zaproxy` or download from zaproxy.org

```bash
zaproxy
```

> [!note]
> ZAP vs Burp: ZAP is fully free with an unrestricted active scanner; Burp Community is free but the scanner requires Pro ($450/yr). ZAP has better native API/OpenAPI support and CI/CD integration. Burp has a better UI, more extensions, and is the industry standard for manual testing. Use both if possible — ZAP for automated scanning, Burp for manual work.

---

## Setup as Proxy

```bash
# Launch ZAP GUI
zaproxy &

# Default proxy: 127.0.0.1:8080

# Configure browser: 127.0.0.1:8080
# Import ZAP CA cert (one-time):
# Tools → Options → Dynamic SSL Certificates → Save
# Import into browser certificate store

# Headless (for automation)
zaproxy -daemon -port 8080 -host 127.0.0.1 \
  -config api.key=YOUR_API_KEY \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

---

## Quick Start — GUI Workflow

```
1. Automated Scan:
   Quick Start tab → Automated Scan
   Enter URL → Attack → runs spider + active scan

2. Manual Explore:
   Quick Start → Manual Explore → Launch Browser
   Browse the app → ZAP captures all traffic

3. Review in Sites Tree (left panel):
   - All discovered URLs
   - Active scan findings (colored flags)
   - Spider results
```

---

## Spider / Crawl

```
# GUI: Right-click site in Sites tree → Spider Site
# or: Tools → Spider

# Ajax Spider (for JavaScript-heavy apps — requires browser)
Tools → Ajax Spider
# Much better for SPAs than the traditional spider

# CLI/API:
# POST /JSON/spider/action/scan/?url=http://target.com
```

---

## Active Scan

```
# GUI: Right-click site → Active Scan
# or: Tools → Active Scan

# Scan Policy Manager (Tools → Scan Policy Manager):
# Configure which checks to run:
# - SQL Injection, XSS, Path Traversal, Remote File Inclusion
# - Command Injection, SSTI, XXE, SSRF
# - Authentication bypass, CSRF
# - Headers, cookies, SSL/TLS issues

# Strength: Low/Medium/High/Insane (more requests = more thorough)
# Threshold: Low/Medium/High (sensitivity of findings)
```

---

## Fuzzer

```
# Right-click any request in History → Fuzz
# Highlight parameter value → Add
# Select payload type:
#   - File (wordlist)
#   - Numberzz (numeric range)
#   - Strings (manual list)
#   - Regex
#   - Script (custom generator)

# Add processors (encode/decode payload):
# URL Encode, HTML Encode, Base64, SHA256, etc.

# Similar to Burp Intruder — no rate limiting in ZAP
```

---

## API Testing

```bash
# Import OpenAPI/Swagger spec
# Tools → OpenAPI/Definition File

# Or via API:
curl "http://localhost:8080/JSON/openapi/action/importFile/" \
  --data "file=/path/to/swagger.json&target=http://target.com"

# SOAP/WSDL
# Tools → Import → Import a WSDL File

# GraphQL
# Tools → Graphql → Import GraphQL Schema from URL
```

---

## Authentication Handling

```
# Form-based authentication:
# Sites → right-click target → Context → Include in Context
# Context → Authentication → Form-based Auth
# Set login URL, username/password params
# Set "logged-in indicator" (text visible when logged in)
# Set "logged-out indicator" (text visible when logged out)

# Script-based auth (for complex flows):
# Authentication → Script-based Auth
# Write JavaScript/Python script for login

# Session management:
# Context → Session Management → Cookie-based (default)
```

---

## ZAP CLI (Command Line)

```bash
# Baseline scan (passive only — for CI)
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://target.com

# Full scan (active)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t http://target.com

# API scan (OpenAPI spec)
docker run -t owasp/zap2docker-stable zap-api-scan.py \
  -t http://target.com/api/openapi.json \
  -f openapi

# Save report
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://target.com \
  -r report.html
```

---

## ZAP REST API

```bash
# ZAP exposes REST API when running (daemon or GUI)
API_KEY="your-key"
ZAP="http://localhost:8080"

# Spider
curl "$ZAP/JSON/spider/action/scan/?apikey=$API_KEY&url=http://target.com"

# Get spider status
curl "$ZAP/JSON/spider/view/status/?scanId=0"

# Active scan
curl "$ZAP/JSON/ascan/action/scan/?apikey=$API_KEY&url=http://target.com"

# Get alerts
curl "$ZAP/JSON/alert/view/alerts/?baseurl=http://target.com"

# Generate report
curl "$ZAP/OTHER/core/other/htmlreport/" -o report.html
```

---

## Alerts & Reporting

```
# Alerts tab (bottom panel) — all findings
# Filter by: Risk (High/Med/Low/Info), Confidence, URL

# Generate report:
Report → Generate Report
# Formats: HTML, JSON, XML, MD

# Risk levels:
# High (Red)    — SQLi, XSS, RCE, etc.
# Medium (Orange)— CSRF, Clickjacking, outdated libs
# Low (Yellow)  — Information disclosure, weak headers
# Informational  — Tech fingerprinting, debug info
```

---

## Key Features vs Burp

| Feature | ZAP | Burp Community | Burp Pro |
|---|---|---|---|
| Price | Free | Free | $450/yr |
| Active scanner | Full (free) | None | Full |
| Proxy + Repeater | Yes | Yes | Yes |
| Intruder/Fuzzer | Yes (no limit) | Yes (rate limited) | Yes (no limit) |
| OpenAPI support | Native | Extension | Extension |
| CI/CD integration | Strong (Docker) | Limited | Moderate |
| Extensions | Growing | Extensive | Extensive |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
