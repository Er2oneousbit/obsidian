# Web Fuzzing

#CWES #WebFuzzing #ffuf #gobuster #feroxbuster #wenum #DirectoryEnum #ParameterFuzzing #VHostFuzzing #APIFuzzing

## What is this?

Automated technique for discovering hidden directories, files, parameters, vhosts, and API endpoints by systematically sending wordlist entries as inputs and analyzing server responses. Use throughout recon and vuln discovery phases. Pairs with [[API Attacks]], [[Web Requests]], [[Information Gathering - Web Edition]].

---

## Key Concepts

| Term | Description |
|---|---|
| `Wordlist` | Dictionary of paths, params, or values fed to the fuzzer |
| `Payload` | The actual data sent per request (wordlist entry + any mutations) |
| `Response Analysis` | Comparing status codes, size, words, lines to filter noise from signal |
| `False Positive` | Result flagged as interesting that isn't (e.g., 404 for non-existent path) |
| `False Negative` | Real vulnerability the fuzzer missed (e.g., logic flaw requiring auth context) |
| `Fuzzing Scope` | Which endpoints/params you're targeting — define before starting |

---

## Tools

| Tool | Install | Primary Use |
|---|---|---|
| `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` | Dir/file/param fuzzing, POST bodies |
| `gobuster` | `go install github.com/OJ/gobuster/v3@latest` | Dir, vhost, DNS subdomain enum |
| `feroxbuster` | `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \| sudo bash -s $HOME/.local/bin` | Recursive forced browsing |
| `wenum` | `pipx install git+https://github.com/WebFuzzForge/wenum && pipx runpip wenum install setuptools` | Parameter/value fuzzing (wfuzz fork) |
| `dirsearch` | `pip3 install dirsearch` | Directory/file enum with smart defaults, no tuning required |
| `arjun` | `pip3 install arjun` | HTTP parameter discovery — smarter than wordlist fuzzing for params |
| `kiterunner` | `go install github.com/assetnote/kiterunner/cmd/kr@latest` | API-aware route fuzzing using real Swagger/API wordlists |
| `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Crawler-based endpoint discovery via JS parsing and form submission |
| `Param Miner` | BApp Store → Param Miner | Burp extension — passive hidden parameter discovery while browsing |
| `Turbo Intruder` | BApp Store → Turbo Intruder | Burp extension — high-speed fuzzing with session/macro context |
| `CeWL` | pre-installed on Kali | Spider target and extract words for a domain-specific wordlist |

> [!note]
> `wenum` is a drop-in replacement for `wfuzz` — same syntax, actively maintained. wfuzz has install issues on modern systems; prefer wenum.

---

## Wordlists

| Wordlist | Use Case |
|---|---|
| `Discovery/Web-Content/common.txt` | General-purpose starting point |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Deep directory enum |
| `Discovery/Web-Content/raft-large-directories.txt` | Thorough directory campaigns |
| `Discovery/Web-Content/big.txt` | Wide net — both dirs and files |
| `Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain enumeration |
| `Discovery/Web-Content/raft-large-files.txt` | File-specific enum — use instead of directory lists when targeting files |
| `Discovery/Web-Content/burp-parameter-names.txt` | Parameter name fuzzing — purpose-built, better than common.txt for params |
| `Discovery/Web-Content/api/api-endpoints.txt` | API endpoint fuzzing — REST-focused paths |

> [!note]
> SecLists path on Kali/Pwnbox: `/usr/share/seclists/` (lowercase). Some systems use `/usr/share/SecLists/`. Check if a command errors on the wordlist path itself.

### CeWL — Custom Wordlists from Target

Spider the target site and extract words to build a domain-specific wordlist. Often finds paths that generic lists miss.

```bash
# Spider and extract words (min length 5, depth 3)
cewl http://<TARGET_IP>:<PORT> -m 5 -d 3 -w custom_wordlist.txt

# Include email addresses
cewl http://<TARGET_IP>:<PORT> -m 5 -d 3 -e -w custom_wordlist.txt

# Use with ffuf
ffuf -w custom_wordlist.txt -u http://<TARGET_IP>:<PORT>/FUZZ -ac
```

---

## Directory Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ
```

| Flag | Description |
|---|---|
| `-w` | Wordlist path |
| `-u` | Target URL — `FUZZ` is the insertion point |
| `-mc` | Match status codes (default: `200-299,301,302,307,401,403,405,500`) |
| `-fc` | Filter (exclude) status codes |
| `-fs` / `-ms` | Filter/match by response size (bytes) |
| `-fw` / `-mw` | Filter/match by word count |
| `-fl` / `-ml` | Filter/match by line count |
| `-mt` | Match by time-to-first-byte (e.g., `-mt >500`) |
| `-o` | Save results to file — `-o results.json -of json` or `-of all` |
| `-k` | Skip TLS certificate verification (self-signed certs on HTTPS targets) |
| `-t` | Threads (default 40) — increase for speed, decrease to avoid detection/rate limits |
| `-p` | Delay between requests in seconds — `-p 0.1` for WAF avoidance |
| `-ac` | Auto-calibrate — send test requests to learn baseline response, auto-filter noise |
| `-ic` | Ignore comment lines in wordlist (lines starting with `#`) |
| `-x` | Proxy URL — route traffic through Burp: `-x http://127.0.0.1:8080` |

```bash
# Filter common noise manually
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -fc 404,401,302

# Auto-calibrate — ffuf learns baseline and filters automatically
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -ac

# Increase threads + route through Burp for real-time inspection
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -t 100 -x http://127.0.0.1:8080

# Replay only matched results through Burp (speed of ffuf, Burp visibility on hits)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -ac -replay-proxy http://127.0.0.1:8080

# Slow down for rate-limited targets; bypass IP-based rate limiting
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -t 5 -p 0.2 -ac -H "X-Forwarded-For: 127.0.0.1"

# Save results + post-process with jq
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -ac -o results.json -of json
jq '.results[] | {url, status, length}' results.json
```

> [!tip]
> Start with `-ac` on every run. It eliminates most false positives automatically and is faster than figuring out `-fs`/`-fw` filters from scratch.

---

## File Extension Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/DIRECTORY/FUZZ -e .php,.html,.txt,.bak,.js -v
```

| Flag | Description |
|---|---|
| `-e` | Extensions to append to each wordlist entry — multiplies requests by count |
| `-v` | Verbose — shows full URL in output |

---

## Recursive Fuzzing

```bash
# ffuf — manual recursion
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://<TARGET_IP>:<PORT>/FUZZ -e .html -recursion -recursion-depth 2 -rate 500

# feroxbuster — auto-recursive with smart filtering
feroxbuster -u http://<TARGET_IP>:<PORT> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --depth 2 --rate-limit 100 -x php,html,txt
```

| Flag (ffuf) | Description |
|---|---|
| `-recursion` | Auto-fuzz newly discovered directories |
| `-recursion-depth` | Max depth — always set this, default is unlimited |
| `-rate` | Requests per second — throttle to avoid overwhelming target |

| Flag (feroxbuster) | Description |
|---|---|
| `--depth` | Recursion depth limit |
| `--rate-limit` | Requests per second |
| `-x` | File extensions to append |
| `-k` | Skip TLS cert verification |
| `-o` | Save output to file |

> [!warning]
> Uncapped recursive fuzzing on a deep app generates millions of requests. Always set `-recursion-depth` / `--depth`. Check RoE for rate limits before running.

---

## dirsearch

Good defaults out of the box — no flag tuning required for a basic run.

```bash
# Basic run (uses built-in wordlist)
dirsearch -u http://<TARGET_IP>:<PORT>

# Custom wordlist
dirsearch -u http://<TARGET_IP>:<PORT> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Specific extensions
dirsearch -u http://<TARGET_IP>:<PORT> -e php,html,txt,bak

# Recursive
dirsearch -u http://<TARGET_IP>:<PORT> -r --max-recursion-depth 2

# HTTPS + proxy
dirsearch -u https://<TARGET_IP>:<PORT> --no-tls-errors --proxy http://127.0.0.1:8080
```

---

## GET Parameter Fuzzing

```bash
# Fuzz parameter VALUE (known parameter name)
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://<TARGET_IP>:<PORT>/page.php?x=FUZZ"

# Fuzz parameter NAME (discover hidden params)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<TARGET_IP>:<PORT>/page.php?FUZZ=value" -ac
```

| Flag | Description |
|---|---|
| `--hc` / `--sc` | Hide/show by status code |
| `--hw` / `--sw` | Hide/show by word count |
| `--hl` / `--sl` | Hide/show by line count |
| `--hs` / `--ss` | Hide/show by size (bytes) |
| `--hr` / `--sr` | Hide/show by regex match on body |

```bash
# Probe manually first to understand baseline response
curl "http://<TARGET_IP>:<PORT>/page.php?x=test"

# Show only short responses (likely the valid hit)
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --sc 200 --sw 1-5 -u "http://<TARGET_IP>:<PORT>/page.php?x=FUZZ"
```

### arjun — Smart Parameter Discovery

arjun uses heuristics to detect parameter existence by analyzing response differences, not just matching status codes.

```bash
# GET parameter discovery
arjun -u "http://<TARGET_IP>:<PORT>/page.php"

# POST parameter discovery
arjun -u "http://<TARGET_IP>:<PORT>/page.php" -m POST

# JSON body
arjun -u "http://<TARGET_IP>:<PORT>/api/endpoint" -m JSON

# With custom headers (auth)
arjun -u "http://<TARGET_IP>:<PORT>/page.php" -H "Authorization: Bearer <token>"

# Specify wordlist
arjun -u "http://<TARGET_IP>:<PORT>/page.php" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

## POST Parameter Fuzzing

```bash
ffuf -u http://<TARGET_IP>:<PORT>/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```

| Flag | Description |
|---|---|
| `-X POST` | HTTP method |
| `-H` | Set request header |
| `-d "y=FUZZ"` | POST body — `FUZZ` is the value under test |
| `-mc 200` | Match only 200 responses |
| `-fc` | Filter (exclude) status codes |
| `-fs` | Filter by response size |

```bash
# Probe manually first
curl -d "" http://<TARGET_IP>:<PORT>/post.php
```

### Multi-Position Fuzzing

Use `W1`/`W2` keywords with multiple `-w` flags to fuzz two positions simultaneously.

```bash
# Fuzz username + password (credential stuffing)
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:W1 -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:W2 -u http://<TARGET_IP>:<PORT>/login -X POST -d "username=W1&password=W2" -fc 302 -ac

# Fuzz two path segments
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:W1 -w /usr/share/seclists/Discovery/Web-Content/common.txt:W2 -u http://<TARGET_IP>:<PORT>/api/W1/W2 -mc 200,201
```

---

## Authenticated Fuzzing

Add auth context to any fuzz command when the target requires a session.

```bash
# Session cookie (grab from Burp/browser after login)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -H "Cookie: PHPSESSID=<session_token>" -fc 302

# Bearer token (API)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/api/FUZZ -H "Authorization: Bearer <token>" -mc 200,201,204,403

# Basic auth
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ -H "Authorization: Basic $(echo -n 'user:pass' | base64)"

# HTTPS with self-signed cert
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://<TARGET_IP>:<PORT>/FUZZ -k
```

> [!note]
> If the app redirects unauthenticated requests to `/login` (302), filter `-fc 302` to drop the noise and surface anything that actually responds.

---

## VHost Fuzzing

```bash
echo "<TARGET_IP> inlanefreight.htb" | sudo tee -a /etc/hosts
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```

| Flag | Description |
|---|---|
| `-u` | Base URL — the server receiving requests |
| `--append-domain` | Appends base domain to each word (e.g., `admin.inlanefreight.htb`) |
| `-s` | Include only these status codes |
| `-b` | Exclude these status codes |
| `--exclude-length` | Exclude by response size (supports ranges) |

Focus on `Status: 200` results. `400` responses are usually malformed wordlist entries, not valid vhosts.

```bash
# Exclude noise
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain -b 400,404
```

---

## Subdomain DNS Fuzzing

```bash
gobuster dns --domain inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

| Flag | Description |
|---|---|
| `--domain` | Target domain for subdomain enum |
| `-t` | Threads (default 10) |

> [!note]
> Newer gobuster versions changed `-d` to set request delay. Use `--domain` to specify the target domain.

---

## Validating Findings

1. **Reproduce with curl or Burp** — not the fuzzer
2. **Check headers first** — confirms file type and size without pulling the body
3. **PoC only** — don't extract data; header evidence is enough for a report

```bash
# Confirm directory listing
curl http://<TARGET_IP>:<PORT>/backup/

# Header-only check — no data pulled
curl -I http://<TARGET_IP>:<PORT>/backup/password.txt
```

Key headers:
- `Content-Type` — confirms file type (`application/sql`, `text/plain`, etc.)
- `Content-Length` — non-zero means file has content; zero = likely empty

> [!tip]
> Directory listing + non-empty sensitive filename in headers = sufficient evidence. You don't need to read the file to prove the vuln.

---

## API Endpoint Discovery

| API Type | Endpoint Style | Params Location | How to Discover |
|---|---|---|---|
| REST | `/users`, `/items/{id}` | URL path, query string, body | Swagger/OpenAPI docs, Burp, ffuf |
| SOAP | Single endpoint (e.g., `/service`) | XML SOAP envelope body | WSDL file — append `?wsdl` to URL |
| GraphQL | Single endpoint (e.g., `/graphql`) | Query/mutation body | Introspection query, GraphiQL UI |

```bash
# Fuzz for undocumented REST endpoints
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ -mc 200,201,204,301,302,307,401,403,405

# GraphQL introspection
curl -s -X POST http://<TARGET_IP>:<PORT>/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

Check these paths first before fuzzing: `/docs`, `/swagger`, `/api-docs`, `/openapi.json`

### katana — Crawler-Based Discovery

Finds endpoints through JS parsing, form submission, and crawling rather than brute force — surfaces routes that wordlists miss.

```bash
# Basic crawl
katana -u http://<TARGET_IP>:<PORT>

# JavaScript parsing mode (finds endpoints in JS files)
katana -u http://<TARGET_IP>:<PORT> -js-crawl

# Depth + output
katana -u http://<TARGET_IP>:<PORT> -d 3 -o endpoints.txt

# With auth cookie
katana -u http://<TARGET_IP>:<PORT> -H "Cookie: session=<token>" -js-crawl -d 3
```

### kiterunner — API Route Fuzzing

Uses real Swagger/API spec wordlists with correct HTTP methods per route — smarter than generic path fuzzing for APIs.

```bash
# Install wordlists (assetnote)
# https://wordlists.assetnote.io/ — download routes-large.kite or swagger-wordlist

# Scan with kiterunner
kr scan http://<TARGET_IP>:<PORT> -w routes-large.kite

# With auth header
kr scan http://<TARGET_IP>:<PORT> -w routes-large.kite -H "Authorization: Bearer <token>"

# Replay a hit through Burp
kr scan http://<TARGET_IP>:<PORT> -w routes-large.kite --proxy http://127.0.0.1:8080
```

---

## API Parameter Fuzzing

```bash
# Fuzz REST query parameter value
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://<TARGET_IP>:<PORT>/api/v1/items?id=FUZZ" -mc 200

# Fuzz POST JSON body value
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/api/v1/items -X POST -H "Content-Type: application/json" -d '{"name":"FUZZ"}' -mc 200,201
```

Use `-mc`/`-fc`/`-fs` to filter — same flags as [[#Directory Fuzzing]].

---

## API Vuln Classes

| Vuln | How to Fuzz |
|---|---|
| BOLA/IDOR | Fuzz object IDs in path — `/items/FUZZ` — look for other users' data |
| Broken Function-Level Auth | Fuzz HTTP methods (`-X DELETE`, `-X PUT`) on GET-only documented endpoints |
| SSRF | Inject internal IPs/URLs into parameters that accept URLs or hostnames |
| Hidden endpoints | Undocumented routes often have no auth — high value targets |

See [[API Attacks]] for full exploitation methodology.

---

*Created: 2026-05-12*
*Updated: 2026-05-14*
*Model: claude-sonnet-4-6*