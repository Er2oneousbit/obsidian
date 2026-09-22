# JavaScript Deobfuscation

#CWES #JavaScript #Deobfuscation #Encoding #Recon #WebAppAttacks #obfuscatorio #StringArray #AntiDebugging #WASM #SourceMaps

## What is this?

Techniques for locating, deobfuscating, and analyzing obfuscated JavaScript — useful when hunting hidden functionality in web apps, analyzing malicious scripts, or reversing client-side logic. Pairs with [[API Attacks]], [[Web Fuzzing]].

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
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Extract hidden endpoints and params from JS files — `git clone …/LinkFinder && cd LinkFinder && pip3 install -r requirements.txt` |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | Scan JS for API keys, tokens, hardcoded creds — `git clone https://github.com/m4ll0k/SecretFinder` |
| [subjs](https://github.com/lc/subjs) | Enumerate all JS file URLs from a target — `go install github.com/lc/subjs@latest` |
| [getJS](https://github.com/003random/getJS) | Collect JS URLs via crawling — `go install github.com/003random/getJS/v2@latest` (**`/v2`** — the unversioned path installs the old release) |
| `node` / `npm` | Run deobfuscated JS locally to verify behavior without hitting target — **not installed on Kali by default**: `sudo apt install nodejs npm` |
| [webcrack](https://github.com/j4k0xb/webcrack) | Deobfuscate obfuscator.io, unminify, and unpack webpack/browserify bundles — `npm install -g webcrack@latest` |
| [synchrony](https://github.com/relative/synchrony) | obfuscator.io-specific cleaner — `npm install --global deobfuscator` (**package is `deobfuscator`, command is `synchrony`**) |
| [box-js](https://github.com/CapacitorSet/box-js) | Sandbox for *malicious* JS — analyse a dropper without running it for real — `npm install box-js --global` |
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
getJS -url http://<target> --complete        # v2 takes -url; --complete resolves relative paths

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

The `_0x1234` identifiers and a big array at the top of the file are the fingerprint of **javascript-obfuscator** (the engine behind obfuscator.io) — by far the most common real-world obfuscator.

```javascript
var _0x1ec6=['Bg9N','sfrciePH...'];
(function(_0x13249d,_0x1ec6e5){...})(_0x1ec6,0xb4);
```

It is not one transform but a stack of them, and knowing which are in play tells you what you're up against (option names below are verbatim from javascript-obfuscator's own docs):

| Transform | What you see | Undoing it |
|---|---|---|
| `stringArray` | Every literal replaced by `_0x1ec6[0x1a]` lookups | Evaluate the array + accessor, then substitute back |
| `stringArrayEncoding` | Array entries are base64/RC4, not plaintext | Decoder function sits right above the array — run *it*, not the whole file |
| `stringArrayRotate` / `stringArrayShuffle` | An IIFE reorders the array at load time before any lookup resolves | The rotation must be *executed* to get the right offsets — this is why pure regex/string search fails |
| `stringArrayWrappersCount` | Lookups go through several wrapper functions, not the array directly | Inline the wrappers first |
| `identifierNamesGenerator: hexadecimal` | `_0x13249d` names everywhere | Cosmetic — rename for readability, semantics unchanged |
| `controlFlowFlattening` | Logic rebuilt as a `while(true)` + `switch` state machine with a shuffled dispatch order | The main reason output stays unreadable after beautifying; needs AST-level work |
| `deadCodeInjection` | Plausible-looking branches that never execute | Dead branches are gated on constants — constant-fold and they vanish |
| `numbersToExpressions` | `0x1a` becomes `0x5 * 0x2 + ...` | Constant-fold |
| `splitStrings` | `"admin"` becomes `'ad' + 'mi' + 'n'` | Constant-fold (defeats naive grep for strings) |
| `selfDefending` | Code detects reformatting and breaks itself | **Do not beautify first** — see below |
| `debugProtection` | `debugger` statement loops that freeze DevTools | Strip statically, or "Never pause here" |

> [!warning] **Do not pretty-print `selfDefending` code.** It fingerprints its own formatting (via `Function.prototype.toString`), so beautifying it makes it silently misbehave or bail — the opposite of Step 1. When you see `selfDefending`, go straight to a static deobfuscator, which removes the guard instead of tripping it.

> [!note] `stringArrayRotate` is why "just grep the array for the flag" usually fails: the array's order at rest is not its order at runtime. Any reliable approach has to *run* the rotation IIFE (or let a tool that emulates it do the work).

### JSFuck / JJEncode / AAEncode

Encodes all JS using only `[]!+` characters (JSFuck) or other minimal symbol sets. Extremely slow execution but functionally valid.

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+...
```

Run in JSConsole to see output, or use online decoders:
- [JSFuck Decoder](https://enkhee-osiris.github.io/Decoder-JSFuck/)
- [JJEncode Decoder](https://utf-8.jp/public/jjencode.html)
- [AAEncode Decoder](https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html)

> [!warning] **"Run it and see" means executing code you haven't read.** Fine for a CTF's own obfuscated snippet; not fine for a script pulled off a live target or out of a phishing page — that's the payload running with your browser/session or your shell. These encodings all end in an `eval`-equivalent, so the safe move is to make it **print instead of execute**:
> ```javascript
> // JSFuck/JJEncode/AAEncode all resolve to a function call — get the source, don't invoke it
> console.log([]["filter"]["constructor"]("…")+"")   // .toString() the built function
> // or, for the common eval(...) tail: swap eval → console.log and run only that expression
> ```

### Analysing Hostile JS Safely

For a sample you believe is malicious (dropper, skimmer, phishing kit), use an instrumented sandbox instead of your own browser or a bare `node`:

```bash
npm install box-js --global
box-js sample.js --output-dir ./analysis/

# box-js emulates Windows Script Host, so browser globals are missing by default.
# Prepend its stubs (document, window, …) when the sample expects a browser:
box-js sample.js --prepended-code=default
box-js sample.js --prepended-code=show-default   # print the path to the boilerplate to customise
```

box-js reports the URLs fetched, files dropped, and commands attempted without letting any of it happen for real. Run it in a disposable VM with no network you care about — a sandbox is a containment measure, not a guarantee.

> [!note] box-js targets WSH-style `.js` malware. For browser-resident code (skimmers, injected page scripts), the **static** tools above are the safer analysis path, since they never execute the sample at all.

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

### Step 4 — Undo String Arrays & Control Flow

Beautifying gets you readable *formatting*; it does nothing about string arrays or a flattened control flow. These tools work on the AST, so they resolve the array, inline the wrappers, constant-fold, and strip the guards — the step that turns `_0x1ec6[0x1a]` back into `"admin"`.

```bash
sudo apt install nodejs npm          # neither is on Kali by default

# webcrack — the general-purpose one: obfuscator.io + unminify + bundle unpacking
npm install -g webcrack@latest
webcrack obfuscated.js > clean.js
webcrack bundle.js -o out-dir/       # splits a webpack/browserify bundle into its modules

# synchrony — narrower, but often cleaner output on javascript-obfuscator specifically
npm install --global deobfuscator    # NB: package name is 'deobfuscator'…
synchrony deobfuscate ./obfuscated.js   # …but the command is 'synchrony'
```

| Tool | Best at | Watch out for |
|---|---|---|
| `webcrack` | obfuscator.io, minified code, **and unpacking webpack/browserify bundles** into per-module files | Depends on `isolated-vm`, which upstream advises against on **odd-numbered Node releases** (they break V8 ABI) — use an LTS (even) Node |
| `synchrony` | javascript-obfuscator output specifically | Its README warns that artifacts from *old* javascript-obfuscator versions may not deobfuscate correctly — try an older synchrony or another tool rather than filing a bug |
| [de4js](https://github.com/lelinhtinh/de4js) | One-stop browser UI for Packer / JSFuck / JJEncode / obfuscator.io | **Archived since 2021** — the hosted page still works, but expect gaps on modern output |

```bash
# Sanity-check that the tool didn't change behaviour: both should produce the same output
node original.js > a.txt 2>&1 ; node clean.js > b.txt 2>&1 ; diff a.txt b.txt
```

> [!tip] Order that actually works on obfuscator.io output: **(1)** run the static deobfuscator *first* (never beautify first — `selfDefending`), **(2)** beautify the result, **(3)** rename the remaining `_0x…` identifiers by hand as you work out what they do. Steps 1 and 2 are the reverse of the order the note's earlier steps imply, and it matters.

> [!note] If the tools fail (custom or layered obfuscation), fall back to letting the script build its own strings and reading them out — put a breakpoint after the rotation IIFE, then dump the resolved array from the console: `copy(JSON.stringify(_0x1ec6))`.

### Anti-Debugging — When DevTools Freezes

`debugProtection` (and `debugProtectionInterval`) plant `debugger` statements inside loops or on a timer, so opening DevTools traps you in an endless pause. Options, cheapest first:

```text
1. Right-click the line number holding the `debugger` → "Never pause here"
2. Deactivate all breakpoints  (Ctrl+F8 / ⌘+F8) — the debugger statements still fire but don't hold
3. DevTools → Sources → uncheck "Pause on exceptions"
```

```javascript
// 4. Neuter the mechanism before the script runs (paste first, or in a pre-load override):
//    debugProtection commonly re-arms itself through Function constructors and timers.
const _F = Function;
Function = function (...a) { return a.join('').includes('debugger') ? function () {} : _F(...a); };
setInterval = function () {};     // kills debugProtectionInterval's re-arm
```

> [!tip] The robust answer is to remove it statically rather than fight it at runtime — `webcrack`/`synchrony` drop the `debugger` payloads along with the rest of the guards, after which DevTools behaves normally.

### Bundles & DevTools Local Overrides

Most real apps ship a webpack/vite bundle, not one hand-written file. `webcrack bundle.js -o out-dir/` splits it back into modules, which makes the app's own source tree (and its module names) readable.

To *change* client-side behaviour and keep the change across reloads — bypass a client-side check, unhide a UI path, log a value — use **Local Overrides** rather than re-pasting console patches:

```text
DevTools → Sources → Overrides → "Select folder for overrides" → allow access
→ Network (or Sources) → right-click the JS file → "Save for overrides"
→ edit the local copy (it's now editable) → reload
The overridden file is served from disk on every load, including hard reloads.
```

> [!warning] Overrides change **only your browser**. A client-side check you delete this way proves nothing about server-side authorization — it's for understanding the app and reaching hidden functionality, after which the finding has to be demonstrated against the server (replay the request with `curl`, see [[#HTTP Requests]]).

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

Recognized by: `\uXXXX` sequences in JS strings. `\u0048` = `H`, `\u0054` = `T`.

```bash
# Decode in node
node -e 'console.log("\u0048\u0054\u0042")'
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

### LinkFinder — Automated Endpoint Extraction

Reading every bundle by hand doesn't scale. LinkFinder regexes endpoints and paths out of JS so you have a target list before you start analysing:

```bash
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip3 install -r requirements.txt

# Single file, output to terminal
python3 linkfinder.py -i http://<target>/app.js -o cli

# Every JS file on the page/domain at once (-d crawls the domain for scripts)
python3 linkfinder.py -i http://<target>/ -d -o results.html

# A folder of files you already downloaded (wildcards allowed)
python3 linkfinder.py -i '/tmp/js/*.js' -o cli

# Only endpoints matching a pattern — cuts CDN/library noise hard
python3 linkfinder.py -i '/tmp/js/*.js' -r '^/api/' -o cli

# Parse a saved Burp export instead of fetching
python3 linkfinder.py -i burpfile -b -o cli
```

| Flag | Use |
|---|---|
| `-i` | Input: URL, file, or folder (`'/*.js'` wildcard) |
| `-o` | `cli` for terminal, or an `.html` report |
| `-d` | Crawl the domain for JS rather than taking one file |
| `-r` | Regex filter on the results (e.g. `^/api/`) |
| `-b` | Treat the input as a Burp export |

> [!tip] Pair the two passes: **LinkFinder** for routes and **SecretFinder** for credentials, both across `/tmp/js/*.js`, then deobfuscate only the files whose hits look interesting. Deobfuscating a 2 MB vendor bundle that turns out to be jQuery is the classic time sink.

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

# -e walks every JS file linked from a page — one command instead of the loop above
python3 SecretFinder.py -i http://<target>/ -e -o cli

# Cut third-party noise (jQuery/bootstrap/CDN) so the hits are the app's own code
python3 SecretFinder.py -i http://<target>/ -e -o cli -g 'jquery;bootstrap;api.google.com'

# Authenticated scan, through Burp, with an extra pattern of your own
python3 SecretFinder.py -i http://<target>/ -e -o cli \
  -c 'PHPSESSID=<token>' -H 'Authorization: Bearer <jwt>' -p 127.0.0.1:8080 -r 'internal_key=[A-Za-z0-9]+'
```

| Flag | Use |
|---|---|
| `-e` | Scan every JS file linked from the given page |
| `-g` | Ignore-list of substrings (drop library/CDN files) |
| `-n` | Exclude specific hosts |
| `-r` | Additional custom regex |
| `-c` / `-H` | Cookie / headers — required for JS only served to authenticated users |
| `-p` | Proxy (route through Burp for evidence) |
| `-b` | Parse a Burp export |

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

## Quick Reference

| Goal | Command |
|---|---|
| Enumerate JS files (crawl) | `echo "http://<target>" \| subjs` |
| Fuzz for JS files | `ffuf -w raft-large-files.txt -u http://<target>/FUZZ -e .js -mc 200` |
| Pretty-print minified JS | Browser DevTools → Debugger → `{ }` (Pretty Print) |
| Unpack `function(p,a,c,k,e,d)` | Paste into [UnPacker](https://matthewfl.com/unPacker.html), or swap `eval(` → `console.log(` |
| Decode JSFuck/JJEncode/AAEncode | Run in [JSConsole](https://jsconsole.com) or matching online decoder |
| Check for source map | `curl -s -o /dev/null -w "%{http_code}" "http://<target>/secret.js.map"` |
| Extract source-map original files | `curl -s ".../secret.js.map" \| python3 -c "import json,sys; ..."` (see Source Maps section) |
| Set conditional breakpoint | DevTools → Sources → line number → "Add conditional breakpoint" |
| Dump localStorage | `for (let i=0;i<localStorage.length;i++){let k=localStorage.key(i); console.log(k, localStorage.getItem(k));}` |
| Run deobfuscated code locally | `node -e "..."` with `XMLHttpRequest`/`fetch` stubbed out |
| Decode base64 | `echo "<b64>" \| base64 -d` |
| Decode hex | `echo "<hex>" \| xxd -p -r` |
| Decode/encode ROT13 | `echo "<text>" \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| Decode URL encoding | `python3 -c "from urllib.parse import unquote; print(unquote('...'))"` |
| Decode JS unicode escapes | `node -e 'console.log("\u0048\u0054\u0042")'` |
| Deobfuscate obfuscator.io output | `webcrack obfuscated.js > clean.js` |
| Unpack a webpack/browserify bundle | `webcrack bundle.js -o out-dir/` |
| obfuscator.io-specific cleaner | `synchrony deobfuscate ./obfuscated.js` (pkg `deobfuscator`) |
| Escape a `debugger` trap | Right-click the line → "Never pause here", or Ctrl+F8 to deactivate breakpoints |
| Persist a patched JS file | DevTools → Sources → Overrides → right-click file → "Save for overrides" |
| Dump the resolved string array | Breakpoint after the rotation IIFE, then `copy(JSON.stringify(_0x1ec6))` |
| Extract endpoints from all JS | `python3 linkfinder.py -i http://<target>/ -d -o results.html` |
| Endpoints matching a pattern only | `python3 linkfinder.py -i '/tmp/js/*.js' -r '^/api/' -o cli` |
| Scan a whole site's JS for secrets | `python3 SecretFinder.py -i http://<target>/ -e -o cli` |
| Sandbox a malicious JS sample | `box-js sample.js --output-dir ./analysis/` |
| Fingerprint unknown encoding | [Cipher Identifier](https://www.dcode.fr/cipher-identifier) |
| Find/download WASM | `curl -s "http://<target>/" \| grep -oP '[^"]+\.wasm'` |
| Disassemble WASM | `wasm2wat app.wasm -o app.wat` |
| Decompile WASM to pseudo-C | `wasm-decompile app.wasm -o app.dcmp` |
| Scan JS for hardcoded secrets | `python3 SecretFinder.py -i "http://<target>/app.js" -o cli` |
| Grep for AWS keys | `grep -oP 'AKIA[0-9A-Z]{16}'` |
| Grep for JWTs | `grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'` |
| Replay discovered endpoint | `curl -s "http://<target>/serial.php" -X POST -d "param1=sample"` |

---

*Created: 2026-05-13*
*Updated: 2026-09-21*
*Model: claude-opus-5*
