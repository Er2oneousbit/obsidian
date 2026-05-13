# JavaScript Deobfuscation

#JavaScript #Deobfuscation #Encoding #Recon #WebAppAttacks

## What is this?

Techniques for locating, deobfuscating, and analyzing obfuscated JavaScript — useful when hunting hidden functionality in web apps, analyzing malicious scripts, or reversing client-side logic. Pairs with [[Web Requests]], [[Web Fuzzing]].

---

## Tools

| Tool | Purpose |
|---|---|
| Browser DevTools | View/pretty-print JS (F12 → Debugger → `{ }` button); CTRL+U for source |
| [Beautifier.io](https://beautifier.io/) | Format minified JS |
| [UnPacker](https://matthewfl.com/unPacker.html) | Deobfuscate packed JS (function(p,a,c,k,e,d) style) |
| [obfuscator.io](https://obfuscator.io) | Obfuscate JS (for testing/analysis) |
| [JSConsole](https://jsconsole.com) | Run JS in browser sandbox to verify behavior |
| [JSFuck Decoder](https://enkhee-osiris.github.io/Decoder-JSFuck/) | Decode JSFuck-obfuscated code |
| [JJEncode Decoder](https://utf-8.jp/public/jjencode.html) | Decode JJEncode-obfuscated code |
| [AAEncode Decoder](https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html) | Decode AAEncode-obfuscated code |
| [Cipher Identifier](https://www.dcode.fr/cipher-identifier) | Fingerprint unknown encoding type |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Extract hidden endpoints and params from JS files — `pip3 install linkfinder` |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | Scan JS for API keys, tokens, hardcoded creds — `git clone https://github.com/m4ll0k/SecretFinder` |
| [subjs](https://github.com/lc/subjs) | Enumerate all JS file URLs from a target — `go install github.com/lc/subjs@latest` |
| [getJS](https://github.com/003random/getJS) | Collect JS URLs via crawling — `go install github.com/003random/getJS@latest` |
| `node` | Run deobfuscated JS locally to verify behavior without hitting target |
| `base64` | CLI encode/decode |
| `xxd` | Hex encode/decode |
| `tr` | ROT13 encode/decode |
| `wasm2wat` / `wasm-decompile` | WABT toolkit — disassemble `.wasm` binaries to WAT text format |
| [Ghidra](https://ghidra-sre.org/) | NSA reverse engineering tool — imports WASM for deeper analysis |

---

## Locating JavaScript

```bash
# View page source in browser
# CTRL+U → look for <script src="..."> or inline <script> blocks

# Fetch source with curl
curl -s "http://<target>/" | grep -i "<script"

# Download external JS file
curl -s "http://<target>/secret.js"

# Check for JS files via content-type
curl -s -I "http://<target>/secret.js" | grep -i content-type
```

JS can be:
- **Inline** — `<script>...</script>` in HTML
- **External** — `<script src="secret.js"></script>` → fetched separately

Check HTML comments too — devs sometimes leave credentials or endpoint hints.

---

## JS File Discovery

Enumerate all JS files on a target before diving into analysis.

```bash
# Collect JS file URLs via crawling
echo "http://<target>" | subjs
echo "http://<target>" | getJS --complete

# Fuzz for JS files with ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://<target>/FUZZ -e .js -mc 200 -o js_files.txt

# Pull all script src values from page source
curl -s "http://<target>/" | grep -oP 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'

# Download and analyze all found JS files
while read url; do
  fname=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "/tmp/js/$fname"
done < js_urls.txt
```

> [!tip]
> Check for source maps alongside JS files — see [[#Deobfuscation]] for details.

---

## Obfuscation Types

### Minification

All code collapsed to one line, whitespace stripped. Functionally identical, just harder to read. Files often end in `.min.js`.

```javascript
function foo(){var a="bar";console.log(a)}
```

Deobfuscate with Beautifier.io or browser DevTools `{ }` button.

### Packing (p,a,c,k,e,d)

Recognizable by the `function(p,a,c,k,e,d)` wrapper — maps symbols to a dictionary and rebuilds on execution.

```javascript
eval(function(p,a,c,k,e,d){...}('original|code|here'.split('|'),0,{}))
```

Deobfuscate with [UnPacker](https://matthewfl.com/unPacker.html). Alternatively, replace `eval(` with `console.log(` to print instead of execute.

### Advanced (obfuscator.io / hex variable names)

Uses `_0x1234` variable names, base64 string arrays, and shuffling functions. Harder to auto-deobfuscate.

```javascript
var _0x1ec6=['Bg9N','sfrciePH...'];
(function(_0x13249d,_0x1ec6e5){...})(_0x1ec6,0xb4);
```

### JSFuck / JJEncode / AAEncode

Encodes all JS using only `[]!+` characters (JSFuck) or other minimal symbol sets. Extremely slow execution but functionally valid.

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+...
```

Run in JSConsole to see output, or use online decoders:
- [JSFuck Decoder](https://enkhee-osiris.github.io/Decoder-JSFuck/)
- [JJEncode Decoder](https://utf-8.jp/public/jjencode.html)
- [AAEncode Decoder](https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html)

---

## Deobfuscation

### Step 1 — Beautify

Format minified/packed code into readable structure first.

- Browser: F12 → Debugger → click script → `{ }` (Pretty Print)
- Online: [Beautifier.io](https://beautifier.io/) or [Prettier](https://prettier.io/playground/)

### Step 2 — Unpack

If code uses `eval(function(p,a,c,k,e,d)...)` packing:

- [UnPacker](https://matthewfl.com/unPacker.html) — paste packed code, click UnPack
- No empty lines before the script or results may be inaccurate
- Manual: replace `eval(` with `console.log(` and run in JSConsole to see the unpacked string

### Step 3 — Decode Encoded Strings

See the [[#Encoding / Decoding]] section below.

### Source Maps

If a `.map` file exists alongside the JS, you get the full original unminified source — zero effort.

```bash
# Check if source map exists
curl -s -o /dev/null -w "%{http_code}" "http://<target>/secret.js.map"

# Download and read it
curl -s "http://<target>/secret.js.map" | python3 -m json.tool | grep -E '"sources"|"sourcesContent"'

# Extract source files from map
curl -s "http://<target>/secret.js.map" | python3 -c "
import json, sys
m = json.load(sys.stdin)
for i, src in enumerate(m.get('sourcesContent', [])):
    print(f'--- {m[\"sources\"][i]} ---')
    print(src[:500])
    print()
"
```

> [!tip]
> Source maps are almost always present in dev/staging environments and accidentally left in production builds. Check before spending time on manual deobfuscation.

### Browser Console Tricks

Quick analysis without downloading or decoding manually.

```javascript
// Paste obfuscated code in DevTools console (F12), inspect vars after run
// Replace eval() with console.log() to print the unpacked string instead of executing it

// Set breakpoint on eval — DevTools → Sources → Event Listener Breakpoints → Script → eval
// Execution pauses before eval fires; inspect the argument

// Intercept fetch/XHR calls
const _fetch = fetch;
fetch = function(...args) { console.log('fetch:', args); return _fetch(...args); };
```

### Conditional Breakpoints

Break only when a specific condition is true — avoids stepping through high-frequency code paths manually.

```text
DevTools → Sources → open JS file → click line number → "Add conditional breakpoint"
Enter condition: username === 'admin'
               : response.status !== 200
               : data.token !== undefined
               : i === 1000        // break on Nth iteration of a loop
```

```javascript
// Alternative: programmatic conditional breakpoint in console
// Patch the function you want to intercept:
const _orig = SomeObject.someMethod;
SomeObject.someMethod = function(...args) {
    if (args[0] === 'admin') { debugger; }  // pause when condition met
    return _orig.apply(this, args);
};
```

> [!tip] Conditional breakpoints are essential for functions called hundreds of times per second (animation loops, event handlers). Without a condition, you'd hit the breakpoint on every call.

### localStorage / sessionStorage Inspection

Apps frequently store tokens, API keys, user roles, and session data in browser storage -- readable without intercepting requests.

```javascript
// Run in DevTools console (F12 → Console)

// List all localStorage keys and values
for (let i = 0; i < localStorage.length; i++) {
    let key = localStorage.key(i);
    console.log(key, ':', localStorage.getItem(key));
}

// List sessionStorage
for (let i = 0; i < sessionStorage.length; i++) {
    let key = sessionStorage.key(i);
    console.log(key, ':', sessionStorage.getItem(key));
}

// Get specific item
localStorage.getItem('token')
localStorage.getItem('user')
sessionStorage.getItem('authToken')

// Pretty-print JSON stored values
JSON.parse(localStorage.getItem('currentUser'))
```

```text
GUI path: DevTools → Application → Storage → Local Storage / Session Storage → select origin
```

**What to look for:**
- `token`, `access_token`, `jwt` -- auth tokens for direct API calls
- `role`, `isAdmin`, `permissions` -- client-side role flags (may be trusted server-side)
- API base URLs, feature flags, internal config blobs
- Cached user objects with PII or privilege data

### Local node Execution

```bash
# Run deobfuscated code locally to verify behavior
node -e "console.log('test')"

# Replace network calls with stubs to run without a live target
node -e "
const XMLHttpRequest = function(){};
XMLHttpRequest.prototype.open = (m,u) => console.log('XHR:', m, u);
XMLHttpRequest.prototype.send = () => {};
// paste deobfuscated code below:
function generateSerial() {
  var xhr = new XMLHttpRequest;
  var url = '/serial.php';
  xhr.open('POST', url, true);
  xhr.send(null);
}
generateSerial();
"
```

---

## Encoding / Decoding

### Base64

Recognized by: alphanumeric + `+` `/` characters, padded with `=` to multiple of 4.

```bash
# Encode
echo "https://www.hackthebox.eu/" | base64
# aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K

# Decode
echo "aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K" | base64 -d
# https://www.hackthebox.eu/
```

### Hex

Recognized by: only chars `0-9` and `a-f`.

```bash
# Encode
echo "https://www.hackthebox.eu/" | xxd -p
# 68747470733a2f2f7777772e6861636b746865626f782e65752f0a

# Decode
echo "68747470733a2f2f7777772e6861636b746865626f782e65752f0a" | xxd -p -r
# https://www.hackthebox.eu/
```

### ROT13

Each letter shifted 13 positions. `http://www` → `uggc://jjj`. Apply same transform to decode.

```bash
# Encode
echo "https://www.hackthebox.eu/" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# uggcf://jjj.unpxgurobk.rh/

# Decode (same command)
echo "uggcf://jjj.unpxgurobk.rh/" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# https://www.hackthebox.eu/
```

### URL Encoding

Recognized by: `%xx` sequences. `%20` = space, `%2F` = `/`, `%3A` = `:`.

```bash
# Decode URL-encoded string
python3 -c "from urllib.parse import unquote; print(unquote('%68%74%74%70%73%3A%2F%2F'))"
# https://

# Or with node
node -e "console.log(decodeURIComponent('%68%74%74%70%73%3A%2F%2F'))"
```

### Unicode Escapes

Recognized by: `\uXXXX` sequences in JS strings. `H` = `H`, `T` = `T`.

```bash
# Decode in node
node -e 'console.log("HTB")'
# HTB

# Decode with Python
python3 -c 'print("\\u0048\\u0054\\u0042".encode().decode("unicode_escape"))'
```

### Unknown Encoding

Use [Cipher Identifier](https://www.dcode.fr/cipher-identifier) to fingerprint the encoding method automatically.


---

## WebAssembly (WASM)

Modern apps move security-sensitive logic (license checks, crypto, auth token generation) into `.wasm` binaries instead of JS. DevTools handles basic inspection; WABT gives full disassembly.

### Find and Download

```bash
# Detect WASM requests in DevTools → Network → filter by "wasm"
# Or search page source for .wasm references
curl -s "http://<target>/" | grep -oP '[^"]+\.wasm'

# Download
curl -s "http://<target>/app.wasm" -o app.wasm
file app.wasm    # WebAssembly (wasm) binary module
xxd app.wasm | head   # magic bytes: 00 61 73 6d (asm)
```

### Disassemble with WABT

```bash
# Install WABT
sudo apt install wabt

# Convert binary WASM → WAT text format (readable S-expressions)
wasm2wat app.wasm -o app.wat
cat app.wat | grep -A5 "func"    # find function definitions

# Decompile to pseudo-C (more readable than WAT)
wasm-decompile app.wasm -o app.dcmp
cat app.dcmp
```

### Browser DevTools

```text
DevTools → Sources → find .wasm file → click it
→ Automatically disassembled to WAT format
→ Can set breakpoints directly on WAT instructions
→ Step through execution, inspect locals/stack
```

### Deeper Analysis

```bash
# Ghidra — import wasm file, use WASM plugin for decompilation
# File → Import File → app.wasm → analyze → Decompiler view

# radare2 with r2ghidra
r2 -A app.wasm
> pdf @ sym.checkLicense    # disassemble a function

# strings — quick win for hardcoded values
strings app.wasm | grep -iE "key|token|secret|pass|admin"
```

> [!note] WASM functions are exported by name when compiled with debug symbols — `wasm2wat` output will show `(export "checkLicense" (func $checkLicense))`. Target exported functions first.

---

## Code Analysis

After deobfuscating, read through the code for:

- **Endpoints** — hardcoded URLs, `/api/`, `/admin/`, `.php` paths
- **Parameters** — POST data keys, query string params
- **Functions never called** — dev left unreleased functionality in client JS
- **Auth tokens / API keys** — sometimes embedded in JS
- **XMLHttpRequest / fetch calls** — reveals what requests the app makes behind the scenes

Example deobfuscated output:

```javascript
function generateSerial() {
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
}
```

This tells us: there's a POST endpoint at `/serial.php` that the UI doesn't visibly use — worth probing manually.

---

## Secrets Hunting

After finding JS files, scan for hardcoded credentials, API keys, and tokens before investing time in deobfuscation.

```bash
# SecretFinder — scan a single JS file
python3 SecretFinder.py -i "http://<target>/app.js" -o cli

# Scan a local file
python3 SecretFinder.py -i /tmp/js/app.js -o cli

# Manual grep patterns
curl -s "http://<target>/app.js" | grep -oP '(?i)(api_key|apikey|secret|token|password|passwd|aws_access|private_key)["\s:=]+["\047]?\K[A-Za-z0-9_/+=.-]{8,}'

# AWS key pattern
curl -s "http://<target>/app.js" | grep -oP 'AKIA[0-9A-Z]{16}'

# JWT in JS source
curl -s "http://<target>/app.js" | grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

# Bearer token
curl -s "http://<target>/app.js" | grep -oP 'Bearer\s+\K[A-Za-z0-9._-]+'

# Scan all downloaded JS files at once
find /tmp/js -name "*.js" -exec python3 SecretFinder.py -i {} -o cli \;
```

> [!tip]
> Run secrets hunting before deobfuscation — keys are often in cleartext even in obfuscated files because they need to be readable at runtime.

---

## HTTP Requests

Replicate JS behavior found in deobfuscated code using curl.

```bash
# GET request
curl -s "http://<target>/"

# POST request (no data)
curl -s "http://<target>/serial.php" -X POST

# POST with data
curl -s "http://<target>/serial.php" -X POST -d "param1=sample"

# POST with JSON
curl -s "http://<target>/api/endpoint" -X POST -H "Content-Type: application/json" -d '{"key":"value"}'

# Include auth cookie
curl -s "http://<target>/serial.php" -X POST -b "session=<token>"
```


---

*Created: 2026-05-13*
*Updated: 2026-05-14*
*Model: claude-sonnet-4-6*
