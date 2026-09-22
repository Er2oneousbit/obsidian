# Web Fuzzing

#CWES #WebFuzzing #ffuf #gobuster #feroxbuster #wenum #DirectoryEnum #ParameterFuzzing #VHostFuzzing #APIFuzzing #GitExposure #BackupFiles #SoftFourOhFour #BFLA

## What is this?

Automated technique for discovering hidden directories, files, parameters, vhosts, and API endpoints by systematically sending wordlist entries as inputs and analyzing server responses. Use throughout recon and vuln discovery phases. Pairs with [[API Attacks]], [[Server-Side Attacks]].

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
| `git-dumper` | `pipx install git-dumper` | Reconstruct a full git repo from an exposed `/.git/` — the highest-value fuzzing hit |

> [!warning] **`wenum` is a fork, not a drop-in — the filter flags diverge.** Kali ships `wfuzz`, *not* wenum, so know which one you're actually driving (verified against both, 2026-09-21):
>
> | Purpose | wenum | wfuzz |
> |---|---|---|
> | Filter by size/chars | `--hs` / `--ss` | `--hh` / `--sh` |
> | Filter by regex | `--hr` / `--sr` | `--hs` / `--ss` |
> | Value list syntax | space-separated (`--hc 302 404`) | comma-separated (`--hc 302,404`) |
> | Iterator mode | `-i product\|zip\|chain` | `-m product\|zip\|chain` |
>
> The overlap is the trap: `--hs 4242` **hides by size** in wenum but **hides by regex `4242`** in wfuzz — no error, just silently different results. wenum also *removes* some wfuzz features by design (its README says so), so it is not a superset either. wfuzz is still fine for one-off value fuzzing; just use its own flag names.

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
| `-mr` / `-fr` | Match/filter by **regex against the body** — the only way to catch a soft 404 that returns HTTP 200 with "not found" in the page |
| `-mmode` / `-fmode` | Combine multiple matchers/filters with `and` instead of `or` (default `or`) |
| `-acc` / `-acs` / `-ach` | Auto-calibration tuning: custom probe string / custom strategy / per-host baseline (each implies `-ac`) |
| `-rate` | Global requests-per-second cap (`-p` is a per-request delay; `-rate` caps throughput) |
| `-maxtime` / `-maxtime-job` | Wall-clock cap for the whole run / per recursion job — stops a runaway scan |
| `-sf` | Auto-stop once >95% of responses are 403 (you've been blocked; stop burning requests) |
| `-ignore-body` | Don't download response bodies — faster, and safe against huge files |
| `-json` / `-s` | Newline-delimited JSON records / silent output — for piping into other tools |
| `-od` | Write the matched response **bodies** to a directory (evidence capture) |

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

### Soft 404s — When Every Path Returns 200

`-ac` calibrates on size/words/lines, so it fails against an app that answers every bad path with a **200 and a friendly "page not found" body** whose length varies (a rendered template with the path echoed into it). Filter on the body text instead of its shape:

```bash
# Drop anything whose body says it wasn't found, whatever the status code or size
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -mc all -fr "(?i)not found|doesn't exist|no such"

# Require the response to REFLECT your payload — proves it reached a real handler
ffuf -w params.txt:PARAM -w values.txt:VAL -u "http://<TARGET_IP>:<PORT>/?PARAM=VAL" -mr "VAL"

# Or tighten calibration: probe with strings shaped like your wordlist, per host
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ -acc admin -acc .htaccess -ach

# AND-combine filters — drop only responses that are BOTH 200 and exactly 4242 bytes
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ -fc 200 -fs 4242 -fmode and
```

> [!note]
> A regex filter costs you the body download, so `-fr`/`-mr` and `-ignore-body` are mutually exclusive in practice. Use the regex pass to *find* the soft-404 signature once, then switch to the cheap `-fs`/`-fw` filter it implies.

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
| `-recursion-depth` | Max depth — **always set this**; the default of `0` means unlimited |
| `-recursion-strategy` | `default` recurses on redirect-based directory hints; `greedy` recurses on **every** match (finds more, costs far more) |
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

## feroxbuster — Auto-Discovery Features

Used as above, feroxbuster is just "recursive ffuf" and most of the tool goes to waste. Its actual edge is **acting on what it finds mid-scan** rather than only reporting it — it rewrites its own wordlist and extension list as the scan runs (verified against feroxbuster 2.13.1).

```bash
# --smart = --auto-tune + --collect-words + --collect-backups
feroxbuster -u http://<TARGET_IP>:<PORT> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --smart --depth 2

# --thorough = --smart + --collect-extensions + --scan-dir-listings — the "just find everything" button
feroxbuster -u http://<TARGET_IP>:<PORT> --thorough --depth 3 -o ferox.txt

# One flag for Burp (sets --proxy and --insecure together)
feroxbuster -u https://<TARGET_IP>:<PORT> --burp --depth 2
```

| Flag | What it does |
|---|---|
| `-B`, `--collect-backups` | For every hit, auto-requests backup variants (default `~`, `.bak`, `.bak2`, `.old`, `.1`) — finds `config.php.bak` you never put in a wordlist |
| `-E`, `--collect-extensions` | Learns the extensions actually in use on the target and adds them to `-x` mid-scan |
| `-g`, `--collect-words` | Harvests words out of response bodies into the live wordlist — a [[#CeWL — Custom Wordlists from Target|CeWL]] pass running inline |
| `--scan-dir-listings` | Actually walks open directory-listing pages instead of just flagging them |
| `--auto-tune` | Lowers the rate automatically when errors spike — better than guessing a fixed `--rate-limit` |
| `--auto-bail` | Aborts the scan outright on excessive errors (use when you must not hammer a fragile target) |
| `--filter-similar-to` | Fuzzy-hash filter against a known-bad page (`--filter-similar-to http://target/soft404`) — kills soft 404s that differ by a few bytes each time |
| `-D`, `--dont-filter` | Turns OFF automatic wildcard filtering — use when you suspect it swallowed a real hit |
| `-L`, `--scan-limit` | Caps how many directory scans run concurrently |
| `--burp` / `--burp-replay` | Proxy everything / only matches to `127.0.0.1:8080` |

> [!warning] **`--rate-limit` is per directory, not global.** With recursion running several directory scans at once, real throughput is roughly `--rate-limit × concurrent scans`. When RoE fixes a request rate, cap the scans with `-L` as well — or use `--auto-tune` and let it find the ceiling.

> [!note] `--depth 0` means **infinite** recursion in feroxbuster, the same trap as ffuf's `-recursion-depth 0`. Always pass an explicit depth.

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

# Show only short responses (likely the valid hit).
# Values are a SPACE-separated list of exact counts — NOT a range.
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --sc 200 --sw 1 2 3 4 5 -u "http://<TARGET_IP>:<PORT>/page.php?x=FUZZ"
```

> [!warning] **These filters take a list of exact values, not a range.** `--sw 1-5` is rejected — wfuzz fails outright with *"Filter must be specified in the form of [int, ... , int, BBB, XXX]"* (verified). Pass the counts individually (`--sw 1 2 3 4 5` in wenum, `--sw 1,2,3,4,5` in wfuzz), or use the expression filter (`--filter` in wenum, `--filter`/`BBB` baseline in wfuzz) when you genuinely need a range or comparison.

### wenum's Plugin Pipeline

Filters aside, wenum's real advantage over plain path fuzzing is that it **parses what it finds** instead of only reporting a status code:

```bash
wenum -u "http://<TARGET_IP>:<PORT>/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  --plugins default,sourcemap,backups,robots,listing,linkparser,headers,errors,title \
  --auto-filter --hard-filter --hc 404 -R 2 -f json -o out.json
```

| Flag | Why it matters |
|---|---|
| `--plugins` | Response-parsing plugins — `sourcemap` (recovers original source from `.map` files), `backups` (probes backup variants of every hit), `robots`, `listing`, `linkparser`, `errors`, `title` |
| `--auto-filter` | Filters out a response shape that recurs too often — wenum's answer to ffuf `-ac`, and its soft-404 defence |
| `--hard-filter` | Filtered responses skip plugin post-processing too, not just the output |
| `-R` / `-r` | Recursion depth / plugin-driven recursion |
| `--limit-requests` | Hard cap on total requests — RoE safety |
| `--ip` | Send to a specific IP while keeping the `Host` header — vhost-scoped fuzzing |
| `-i` | Iterator: `product` (cartesian), `zip` (lockstep), `chain` (concatenate) — wenum's `-mode` equivalent |

> [!tip] The `sourcemap` and `backups` plugins overlap with feroxbuster's `--collect-backups`; between them, "fuzz, then automatically probe every hit for a leftover copy" is a two-flag habit worth having on every engagement. What they find lands in [[#High-Value Leftovers]].

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

### Multi-Position Fuzzing & `-mode`

Keywords are arbitrary — `-w list.txt:W1` just declares `W1` as an insertion point. With two or more wordlists, **`-mode` decides how they combine**, and the default is not what you want for paired data.

| Mode | Behaviour | Use for |
|---|---|---|
| `clusterbomb` *(default)* | Every combination — cartesian product, `|A| × |B|` requests | **Password spraying**: every password against every user |
| `pitchfork` | Lockstep — 1st of A with 1st of B, 2nd with 2nd… (stops at the shorter list) | **Credential stuffing**: replaying known `user:pass` pairs from a dump |
| `sniper` | One position at a time from a single wordlist, the others held at their template value | Probing many positions of one request without a combinatorial blowup |

```bash
# Password spray — every password × every user (clusterbomb, the default)
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:W1 -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:W2 \
  -u http://<TARGET_IP>:<PORT>/login -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=W1&password=W2" -fc 302 -ac

# Credential stuffing — PAIRED creds, line 1 with line 1. Needs pitchfork.
ffuf -w users.txt:W1 -w passwords.txt:W2 -mode pitchfork \
  -u http://<TARGET_IP>:<PORT>/login -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=W1&password=W2" -fc 302 -ac

# Fuzz two path segments — here the cartesian product IS what you want
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:W1 -w /usr/share/seclists/Discovery/Web-Content/common.txt:W2 -u http://<TARGET_IP>:<PORT>/api/W1/W2 -mc 200,201
```

> [!warning] **Credential stuffing in the default mode is a cross-product, not a stuffing run.** `clusterbomb` turns 1,000 leaked `user:pass` pairs into 1,000,000 requests — slower, far noisier, and it tries passwords against accounts they never belonged to, which is exactly how you trip account lockout and burn the engagement. Paired lists need `-mode pitchfork`. Sanity-check the planned request count in ffuf's startup banner before you let it run.

---

## Fuzzing a Captured Request (`-request`)

Rebuilding a complex authenticated request out of `-X`/`-H`/`-d` flags is where fuzzing usually falls apart — multipart bodies, a CSRF token, a dozen cookies, nested JSON. Don't. Save the raw request out of Burp (right-click → *Copy to file*) and put `FUZZ` anywhere inside it — path, any header, or the body.

```http
POST /api/v2/account/update HTTP/1.1
Host: target.com
Cookie: session=eyJ0eXAi...
Content-Type: application/json
X-CSRF-Token: 9f2c...

{"display_name":"bob","FUZZ":"test"}
```

```bash
# Hunt hidden JSON parameters inside a fully authenticated request
ffuf -request req.txt -request-proto http -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac
```

| Flag | Description |
|---|---|
| `-request` | File containing the raw HTTP request; `FUZZ` is honoured in any part of it |
| `-request-proto` | `http` or `https` — **defaults to `https`** |
| `-enc` | Per-keyword encoding, e.g. `-enc FUZZ:urlencode` or `FUZZ:b64encode` — reaches filters that decode before they validate |
| `-input-cmd` | Generate payloads from a command instead of a wordlist (requires `-input-num`) |
| `-D` | DirSearch-style wordlist compatibility, used with `-e` |

```bash
# Encode on the way out (WAF, or a parameter the app base64-decodes)
ffuf -request req.txt -request-proto http -w payloads.txt -enc FUZZ:urlencode

# No wordlist on disk — pipe a generator. Numeric ID sweep for BOLA/IDOR:
ffuf -u http://<TARGET_IP>:<PORT>/api/v1/orders/FUZZ -input-cmd 'seq 1 5000' -input-num 5000 -mc 200 -ac

# Method fuzzing — the command the BOLA/BFLA table below is missing
printf 'GET\nPOST\nPUT\nPATCH\nDELETE\nOPTIONS\n' > methods.txt
ffuf -w methods.txt:FUZZ -u http://<TARGET_IP>:<PORT>/api/v1/users/1 -X FUZZ -mc all -v
```

> [!warning] `-request-proto` defaults to **https**. Point it at a plain-HTTP lab target without setting `-request-proto http` and every request dies in the TLS handshake — which looks exactly like a dead host or a wrong port.

> [!note]
> A raw request captured after login carries the session, so this is also the cleanest way to do [[#Authenticated Fuzzing|authenticated fuzzing]] — no re-typing cookies per command. Re-export the file when the session expires.

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
| `--append-domain`, `--ad` | Appends base domain to each word (e.g., `admin.inlanefreight.htb`) |
| `--domain`, `--do` | Domain to append when `-u` is a bare IP |
| `--exclude-status`, `--xs` | Exclude status codes — ranges OK (`200,300-400,404`) |
| `--exclude-length`, `--xl` | Exclude by content length — ranges OK (`203-206`) |
| `--exclude-hostname-length`, `--xh` | Auto-adjusts the length filter for the hostname echoed back in the body |
| `-d`, `--delay` | Per-thread delay between requests (**`-d` is not the domain flag**) |
| `--force` | Run even when gobuster warns the result isn't guaranteed |

Focus on `Status: 200` results. `400` responses are usually malformed wordlist entries, not valid vhosts.

```bash
# Exclude noise — NOT -b/-s, which gobuster vhost does not define
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain --xs 400,404
```

> [!warning] **`-s` and `-b` do not exist in `vhost` mode** (verified, gobuster 3.8.2 — `flag provided but not defined: -b`). They are `dir`-mode flags. In `vhost` mode the equivalents are `--exclude-status`/`--xs` and `--exclude-length`/`--xl`, and they are exclude-only — there is no include-status flag.

> [!tip] **The classic vhost false positive:** every invalid vhost returns the same page, but its *length* differs by a few bytes because the server echoes the hostname into it — so a fixed `--xl` misses them all. `--exclude-hostname-length`/`--xh` adjusts the length filter per hostname and collapses that whole class of noise.

---

## Subdomain DNS Fuzzing

```bash
gobuster dns --domain inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

| Flag | Description |
|---|---|
| `--domain`, `--do` | Target domain for subdomain enum |
| `-t` | Threads (default 10) |
| `--resolver` | Query a specific DNS server (`--resolver 10.10.10.1`) |
| `--wildcard`, `--wc` | Keep going when a wildcard record is detected (gobuster aborts by default) |
| `--check-cname`, `-c` | Also resolve CNAMEs |
| `-p`, `--pattern` | File of mutation patterns applied to every word, using the `{GOBUSTER}` placeholder |
| `--discover-pattern`, `--pd` | Same patterns, but applied only to words that already resolved |
| `--wordlist-offset`, `--wo` | Resume from a wordlist position after an interruption |
| `--no-fqdn`, `--nf` | Don't append the trailing dot — lets the resolver apply its search domain |

> [!note]
> Newer gobuster versions changed `-d` to set request delay. Use `--domain` to specify the target domain.

> [!warning] **Wildcard DNS makes every word a hit.** If `*.target.com` resolves, subdomain brute force returns the entire wordlist as "found." Probe a guaranteed-junk label first, and if it resolves, only `--wildcard` plus filtering on the *resolved address* will tell you anything:
> ```bash
> dig +short definitelynotreal12345.target.com    # answers = wildcard in play
> gobuster dns --domain target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --wildcard -o dns.txt
> # then keep only names NOT pointing at the wildcard's IP
> ```

> [!tip] **Pattern mutation finds the hosts wordlists don't.** Once you know `api.target.com` exists, environment prefixes/suffixes are the usual next win — `--pd` applies them only to confirmed names, so it costs almost nothing:
> ```bash
> printf '{GOBUSTER}-dev\n{GOBUSTER}-staging\n{GOBUSTER}-uat\n{GOBUSTER}-test\ndev-{GOBUSTER}\n' > patterns.txt
> gobuster dns --domain target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --pd patterns.txt
> ```
> Non-production instances of a known-good app are the highest-value subdomain findings: same code, weaker auth, debug modes on, and real data.

---

## High-Value Leftovers

Fuzzing only pays off if you recognise which hits are jackpots. These convert straight into source code or credentials, and generic directory lists routinely miss them because they are *files* — often dotfiles — not directories.

```bash
# Probe the high-value set directly — cheaper and faster than any wordlist
for p in .git/HEAD .git/config .env .env.bak .svn/entries .DS_Store .htpasswd \
         config.php.bak index.php~ web.config.bak backup.zip db.sql id_rsa; do
  printf '%-20s ' "$p"
  curl -s -o /dev/null -w '%{http_code}  %{size_download} bytes\n' "http://<TARGET_IP>:<PORT>/$p"
done

# Or sweep with a file-oriented list plus backup extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://<TARGET_IP>:<PORT>/FUZZ \
  -e .bak,.old,.swp,.zip,.tar.gz,.sql,~ -ac
```

| Leftover | Why it matters |
|---|---|
| `/.git/` | The whole repo — source, commit history, and secrets deleted in later commits |
| `/.env` | Framework env file — DB creds, `APP_KEY`, API tokens, SMTP creds |
| `file~`, `.bak`, `.old`, `.1` | Editor/deploy copies served as **plain text** |
| `file.swp`, `.swo` | Vim crash artifacts — recover with `vim -r file.swp` |
| `/.DS_Store` | macOS directory index — leaks filenames no wordlist would guess |
| `/.svn/entries`, `/.hg/` | Same story as `.git` for older VCSes |
| `/.htpasswd` | Basic-auth hashes — crack offline |

> [!warning] **`config.php.bak` is the whole game.** The server maps `.php` to the interpreter, so `config.php` returns rendered output with the credentials hidden. Rename it `.bak`, `.old` or `file~` and the extension no longer matches the handler — so the server serves the **raw source as text/plain**, credentials and all. This is why [[#feroxbuster — Auto-Discovery Features|feroxbuster's --collect-backups]] and wenum's `backups` plugin are worth running on every hit.

### Exposed `.git` → Full Source Recovery

A `200` on `/.git/HEAD` means the repository was deployed along with the app. Reconstruct it locally and you have the source, the history, and anything that was committed then "removed":

```bash
git-dumper http://<TARGET_IP>:<PORT>/.git/ ./loot_repo      # usage: git-dumper URL DIR
cd ./loot_repo && git log --oneline --all | head

# The payoff is usually in the HISTORY, not the working tree —
# credentials "removed" in a later commit are still in the objects
git log -p --all -S 'password' | head -50
git log --diff-filter=D --name-only --all | head          # files deleted along the way
```

| Flag | Use |
|---|---|
| `-j`, `--jobs` | Parallel requests — speeds up large repos |
| `-r`, `--retry` | Retry attempts before giving up on an object |
| `--proxy` | Route through Burp for logging/evidence |

> [!tip] If `/.git/` has directory listing disabled, git-dumper still works — it walks the repo's own index and object references rather than the directory tree. Test `/.git/HEAD` (not `/.git/`) to decide whether it's exposed: `curl -s http://<TARGET>/.git/HEAD` returning `ref: refs/heads/main` is the tell.

> [!warning] **Scope check before dumping.** Pulling a full repo retrieves far more than a PoC needs, and may include data outside engagement scope. Confirming `/.git/HEAD` responds is enough to *evidence* the finding — clear the full dump against RoE first (same principle as the header-only validation below).

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

## Quick Reference

| Goal | Command |
|---|---|
| Dir fuzz (auto-calibrate) | `ffuf -w directory-list-2.3-medium.txt -u http://<TARGET>/FUZZ -ac` |
| Recursive dir fuzz | `feroxbuster -u http://<TARGET> -w directory-list-2.3-medium.txt --depth 2 --rate-limit 100` |
| File extension fuzz | `ffuf -w common.txt -u http://<TARGET>/DIR/FUZZ -e .php,.html,.bak -v` |
| Quick default-wordlist scan | `dirsearch -u http://<TARGET>` |
| GET param value fuzz | `wenum -w common.txt --hc 404 -u "http://<TARGET>/page.php?x=FUZZ"` |
| GET param name discovery | `ffuf -w burp-parameter-names.txt -u "http://<TARGET>/page.php?FUZZ=value" -ac` |
| Smart param discovery | `arjun -u "http://<TARGET>/page.php" -m POST` |
| POST body fuzz | `ffuf -u http://<TARGET>/post.php -X POST -d "y=FUZZ" -w common.txt -mc 200` |
| Password spray (every combo) | `ffuf -w users.txt:W1 -w passwords.txt:W2 -u http://<TARGET>/login -X POST -d "username=W1&password=W2" -fc 302` |
| Credential stuffing (**paired**) | add `-mode pitchfork` — the default `clusterbomb` makes a cross-product |
| Fuzz a captured Burp request | `ffuf -request req.txt -request-proto http -w burp-parameter-names.txt -ac` |
| HTTP method fuzz (BFLA) | `ffuf -w methods.txt:FUZZ -u http://<TARGET>/api/v1/users/1 -X FUZZ -mc all` |
| Payload sweep with no wordlist | `ffuf -u http://<TARGET>/api/v1/orders/FUZZ -input-cmd 'seq 1 5000' -input-num 5000` |
| Encode payloads on the way out | `ffuf -request req.txt -w payloads.txt -enc FUZZ:urlencode` |
| Soft-404 filter by body text | `ffuf -w list.txt -u http://<TARGET>/FUZZ -mc all -fr "(?i)not found"` |
| feroxbuster "find everything" | `feroxbuster -u http://<TARGET> --thorough --depth 3` |
| Auto-probe backups of every hit | `feroxbuster -u http://<TARGET> --smart --depth 2` (`-B`) |
| wenum plugin sweep | `wenum -u http://<TARGET>/FUZZ -w list.txt --plugins default,sourcemap,backups --auto-filter` |
| Check for exposed git repo | `curl -s http://<TARGET>/.git/HEAD` → `ref: refs/heads/main` |
| Dump an exposed `.git` | `git-dumper http://<TARGET>/.git/ ./loot_repo` |
| Mine dumped repo history for creds | `git log -p --all -S 'password' \| head -50` |
| Authenticated fuzz (cookie) | `ffuf -w directory-list-2.3-medium.txt -u http://<TARGET>/FUZZ -H "Cookie: PHPSESSID=<token>" -fc 302` |
| VHost fuzz | `gobuster vhost -u http://target.htb -w common.txt --append-domain --xs 400,404 --xh` |
| Subdomain DNS fuzz | `gobuster dns --domain target.com -w subdomains-top1million-5000.txt` |
| Subdomain fuzz, internal resolver | `gobuster dns --domain target.com -w list.txt --resolver 10.10.10.1 --wc` |
| Subdomain pattern mutation | `gobuster dns --domain target.com -w list.txt --pd patterns.txt` (`{GOBUSTER}-dev`) |
| Validate a hit without pulling body | `curl -I http://<TARGET>/backup/password.txt` |
| GraphQL introspection | `curl -s -X POST http://<TARGET>/graphql -d '{"query":"{__schema{types{name}}}"}'` |
| Crawler-based endpoint discovery | `katana -u http://<TARGET> -js-crawl -d 3` |
| API-aware route fuzzing | `kr scan http://<TARGET> -w routes-large.kite` |
| BOLA/IDOR probe | Fuzz object IDs in path: `/items/FUZZ`, check for other users' data |
| Custom wordlist from target | `cewl http://<TARGET> -m 5 -d 3 -w custom_wordlist.txt` |

---

*Created: 2026-05-12*
*Updated: 2026-09-21*
*Model: claude-opus-5*
