# Burp Suite

**Tags:** `#burpsuite` `#proxy` `#webappsec` `#interceptproxy` `#web` `#scanning`

The standard web application security testing platform. Intercepts and manipulates HTTP/HTTPS traffic between browser and server. Core tools: Proxy (intercept/modify), Repeater (manual replay), Intruder (fuzzing/brute force), Scanner (automated vulnerability discovery), Decoder, Comparer, and the Extender ecosystem. Community edition is free; Pro adds the active scanner and advanced Intruder attack types.

**Source:** https://portswigger.net/burp
**Install:** Pre-installed on Kali — `burpsuite`

```bash
burpsuite &
```

> [!note]
> Always configure browser proxy to `127.0.0.1:8080` before launching. Import Burp's CA cert into the browser to intercept HTTPS without SSL warnings: browse to `http://burp` → CA Certificate → import into browser trust store.

---

## Proxy Setup

```bash
# Start Burp
burpsuite &

# Browser proxy: 127.0.0.1:8080

# Install CA cert (one-time):
# 1. Browse to http://burp (while proxied)
# 2. Click "CA Certificate" → download cacert.der
# 3. Import into browser: Firefox → Settings → Privacy → Certificates → Import

# Firefox proxy shortcut (FoxyProxy extension — recommended)
# Set profile: Burp = 127.0.0.1:8080

# CLI proxy (curl, other tools)
curl -x http://127.0.0.1:8080 http://target.com/
curl -x http://127.0.0.1:8080 --insecure https://target.com/
```

---

## Proxy Tab

```
Intercept ON/OFF       — toggle request interception
Forward                — send intercepted request as-is
Drop                   — drop intercepted request
Action → Send to ...   — send to Repeater, Intruder, Scanner, etc.

HTTP History           — log of all requests (searchable, filterable)
WebSockets History     — WebSocket frames log

Options:
  - Intercept rules: filter by host, method, extension
  - Match/Replace: auto-modify requests/responses (add headers, strip HSTS, etc.)
  - SSL Pass Through: bypass interception for specific hosts
```

---

## Repeater

```
# Send request from Proxy history → Repeater (Ctrl+R)
# Manually modify and replay requests
# Diff responses with Comparer

# Tips:
# - Use Ctrl+Space for autocomplete in request editor
# - Right-click → Send to Comparer to diff two responses
# - Organize tabs by target/function
# - Change method: right-click → Change request method (GET↔POST)
```

---

## Intruder

```
# Send to Intruder: Ctrl+I from Proxy history

# Attack types:
# Sniper        — one wordlist, one position at a time (credential testing)
# Battering Ram — one wordlist, all positions get same value simultaneously
# Pitchfork     — multiple wordlists, one per position (user:pass pairs)
# Cluster Bomb  — multiple wordlists, all combinations (brute force)

# Payload positions: highlight parameter value → Add §
# Example: username=§admin§&password=§password§

# Payload sets:
# Simple list      — wordlist
# Runtime file     — read from file at runtime
# Character frobber — character substitution
# Recursive grep  — use previous response value (CSRF token extraction)
# Numbers         — sequential/random number ranges

# Grep match: Settings → Grep - Match → add "incorrect" or "invalid"
# Grep extract: Settings → Grep - Extract → extract token from response

# Community edition: rate-limited (1 req/sec for Sniper)
# Pro: unlimited speed, all attack types unrestricted
```

---

## Scanner (Pro)

```
# Active scan: right-click request → Scan
# Passive scan: automatic, runs on all proxied traffic

# Scan configuration:
# Audit checks → select issue types (SQLi, XSS, etc.)
# Crawl settings → depth, scope, auth

# Issue Activity tab → view findings
# Export: Report → HTML/XML

# Crawl + Audit: Target → right-click scope item → Scan
```

---

## Decoder

```
# Decode/encode: Ctrl+Shift+D or Decoder tab
# Paste encoded value → select decode method

# Supported:
# URL encode/decode        (%xx)
# HTML encode/decode       (&#xx;)
# Base64 encode/decode
# Hex encode/decode
# ASCII Hex
# Gzip compress/decompress
# SHA1/SHA256/MD5 hash
# Smart decode             (auto-detect)

# Chained: decode → encode → decode (for nested encoding)
```

---

## Comparer

```
# Compare two requests or responses
# Useful for: finding differences between authenticated/unauthenticated responses,
#             spotting blind SQLi (response length difference), comparing error messages

# Send from Repeater/Proxy: right-click → Send to Comparer
# Comparer tab → Compare words / Compare bytes
```

---

## Match & Replace Rules

```
# Proxy → Options → Match and Replace → Add rule

# Common rules:
# Remove X-Forwarded-For header
# Add X-Forwarded-For: 127.0.0.1 (IP restriction bypass attempt)
# Replace User-Agent
# Add Authorization header to all requests
# Remove HSTS header from responses
# Replace "admin=false" → "admin=true" in responses
# Strip CSP headers (Content-Security-Policy)
```

---

## Target & Scope

```
# Set scope: Target → right-click host → Add to Scope
# Scope limits what gets logged/scanned

# Site map: Target → Site Map
# - Spider: right-click → Spider this host (Community: manual crawl)
# - Engagement Tools (Pro): analyze/discover content

# Filter HTTP history by scope: "Show only in-scope items"
```

---

## Useful Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+S` | Send to Scanner |
| `Ctrl+Shift+D` | Send to Decoder |
| `Ctrl+Shift+C` | Send to Comparer |
| `Ctrl+F` | Forward intercepted request |
| `F12` | Toggle intercept |
| `Ctrl+Z` | Undo in editor |
| `Ctrl+A` | Select all in editor |
| `Ctrl+U` | URL encode selection |
| `Ctrl+Shift+U` | URL decode selection |
| `Ctrl+B` | Base64 encode selection |
| `Ctrl+Shift+B` | Base64 decode selection |

---

## Extensions (BApp Store)

```
# Notable free extensions:
# Logger++ — advanced request logging with grep/filter
# Turbo Intruder — fast custom Intruder (Python scripts, no rate limit)
# Param Miner — hidden parameter discovery (better than Arjun for some cases)
# JWT Editor — JWT manipulation (replace key-tool)
# Autorize — automatic auth bypass testing
# Active Scan++ — extra scan checks (Pro)
# CSRF Scanner
# Retire.js — detect vulnerable JS libraries
# Hackvertor — encoding/transformation engine

# Install: Extender → BApp Store → Install
```

---

## Common Workflows

```
# 1. SQLi testing
# - Proxy request through Burp
# - Send to Repeater
# - Add ' to parameter → check error
# - Add ' OR 1=1-- - → check behavior
# - Send to sqlmap via "Copy as curl command" or save request file

# 2. Auth bypass
# - Capture login request → Repeater
# - Test: remove token, replay old token, modify role/admin params
# - Compare authenticated vs unauthenticated responses in Comparer

# 3. IDOR
# - Find request with user ID in param/path
# - Repeater → change ID to other values
# - Autorize extension automates this across all requests

# 4. CSRF token extraction (Intruder)
# Payload: Recursive grep — extract token from login page response
# Use extracted token in next request

# 5. Brute force login (Intruder)
# Attack type: Pitchfork
# Position 1: §username§ → usernames.txt
# Position 2: §password§ → passwords.txt
# Grep: "invalid credentials" → failures have this, success doesn't
```

---

## CLI / Headless

```bash
# Run Burp in headless mode with REST API (Pro)
java -jar burpsuite_pro.jar --headless --config-file=config.json

# Use Burp REST API to start scans
curl -X POST http://localhost:1337/v0.1/scan \
  -d '{"urls":["http://target.com"]}'

# Save/restore state
File → Save state (Community)
File → Project file (Pro — saves everything)
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
