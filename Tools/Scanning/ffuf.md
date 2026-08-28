# ffuf

**Tags:** `#ffuf` `#webenumeration` `#fuzzing` `#bruteforce` `#dirbusting`

Fast web fuzzer written in Go. Place `FUZZ` anywhere in the request — URL, headers, POST body, Host header. Supports multiple wordlists with named keywords, advanced filtering, and rate limiting. The most flexible web fuzzing tool for CTFs and pentests.

**Source:** https://github.com/ffuf/ffuf
**Install:** `sudo apt install ffuf`

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -v
```

> [!note]
> Always add `-v` for full URLs and `-debug-log error.log` to catch errors. Filter noise with `-fs` (size), `-fc` (code), or `-fw` (words) — get the baseline response size first with a known-bad request, then filter it out.

---

## Directory / File Fuzzing

```bash
# Basic directory brute force
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -v

# File extension fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://10.129.14.128/indexFUZZ -v

# Filename fuzzing (known extension)
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
  -u http://10.129.14.128/FUZZ.php -v

# Recursive scan (-recursion-depth 1 = one level deep)
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -recursion -recursion-depth 2 -e .php -v

# Multiple extensions at once
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -e .php,.html,.txt,.bak,.conf -v
```

> [!warning] **`-e` extends the *wordlist*, not the URL — never combine it with an extension already in the template.** `-e .php,.html` turns each word `index` into `index`, `index.php`, `index.html`, then substitutes **all** of them into `FUZZ`. So `-u .../FUZZ` is what you want; `-u .../FUZZ.php -e .php,.html,.txt,.bak,.conf` sends `index.php`, `index.php.php`, `index.html.php`, `index.txt.php`, … — i.e. it tests **`.php` only**, at N× the request cost, and silently never tries `.html/.txt/.bak`.
> **Catch it by math:** requests should equal `wordlist × (1 + extensions)`. A real run of `FUZZ.php -e .php,.html,.txt,.bak,.conf` over a 220,544-word list fired **1,323,264** requests (`220,544 × 6`) yet only covered `.php`. If the counter is a clean multiple of your extension count, you've hit this.
> **Correct form:** bare template + `-e` — `ffuf -u http://host/FUZZ -e .php,.html,.txt,.bak,.conf -w list:FUZZ`.

---

## Subdomain & Vhost Fuzzing

```bash
# Subdomain fuzzing — FUZZ is in the HOSTNAME, so each word must actually DNS-resolve
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.inlanefreight.com/ -v

# VHost fuzzing — FUZZ is in the Host HEADER; base URL hits a fixed IP/hosts-mapped name
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://10.129.14.128/ -H "Host: FUZZ.inlanefreight.htb" -fs 612 -v
```

> [!warning] **Which one on HTB?** Use the **vhost** form (`-H "Host: FUZZ..."`). The subdomain form (`-u http://FUZZ.target.htb`) makes ffuf DNS-resolve every candidate, and `/etc/hosts` has **no wildcards** — so unless the box runs a DNS server, it errors on nearly every word. Vhost fuzzing connects to the known IP and only varies the `Host:` header, so it always connects. Full contrast table: [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing#Virtual Host vs Subdomain Fuzzing — know which you're doing|Fuzzing → VHost vs Subdomain]].

> [!tip] **Filtering vhost noise — the miss is the default page, so status code alone is useless.** Baseline it first with one bogus Host and read the **Size / Words / Lines** columns:
> ```bash
> ffuf -w list.txt:FUZZ -u http://10.129.x.x/ -H "Host: FUZZ.target.htb" \
>      -H "Host: definitelynotreal.target.htb" -mc all      # eyeball Size/Words/Lines of a known miss
> ```
> - **Catch-all is a fixed size** → `-fs <bytes>`.
> - **Size varies per request** — the 301/redirect **echoes the requested hostname**, so bytes scale with the length of each FUZZ word (the classic vhost trap where `-fs` is useless). Filter on a metric that stays constant instead: **`-fw <words>`** or **`-fl <lines>`** — the response template is identical, only the echoed host changes bytes, not word/line count.
> - **Don't want to eyeball it** → **`-ac`** auto-calibrates: ffuf fires dummy inputs, profiles the wildcard across size/words/lines, and filters it for you — the right tool when the baseline is *dynamic*. `-ach` calibrates per host; `-acc "<str>"` adds custom probe strings.
> - **A real vhost usually breaks the pattern** — its own app answers **200 / 403 / 401** (not the 301 catch-all) or a different word count; if the status differs, `-fc 301` is the cleanest cut. Always confirm against a **known-good Host** before trusting a "no hits" result.

---

## Parameter Fuzzing

```bash
# GET parameter discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://10.129.14.128/admin.php?FUZZ=test -fs 1234 -v

# POST parameter discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://10.129.14.128/admin.php \
  -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" -fs 1234 -v

# POST value fuzzing (known parameter)
ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ \
  -u http://10.129.14.128/login.php \
  -X POST -d "username=FUZZ&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" -fs 781 -v
```

---

## Multiple Wordlists (Named Keywords)

```bash
# FUZZ folders, WORDLIST filenames, EXT extensions simultaneously
ffuf -w folders.txt:FOLDERS \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:WORDLIST \
  -w extensions.txt:EXT \
  -u http://10.129.14.128/FOLDERS/WORDLISTEXT -v
```

---

## Auth & Session

```bash
# Cookie
ffuf -w wordlist.txt:FUZZ -u http://10.129.14.128/FUZZ \
  -b "PHPSESSID=abc123; security=low"

# Bearer token
ffuf -w wordlist.txt:FUZZ -u http://10.129.14.128/FUZZ \
  -H "Authorization: Bearer eyJ..."
```

---

## Filtering & Matching

| Flag | Description |
|------|-------------|
| `-fc <codes>` | Filter by status code (e.g. `-fc 404,403`) |
| `-fs <size>` | Filter by response size |
| `-fw <words>` | Filter by word count |
| `-fl <lines>` | Filter by line count |
| `-mc <codes>` | Match only these status codes (default is a fixed set — use `-mc all` to see everything) |
| `-ms <size>` | Match response size |
| `-mr <regex>` | **Match response body by regex** — the semantic-success matcher |
| `-fr <regex>` | Filter response body by regex |
| `-ac` | **Auto-calibrate** — probe the target, learn the wildcard/catch-all baseline (size + words + lines), filter it automatically |
| `-acc <str>` / `-ach` | Custom auto-calibration probe strings / calibrate **per host** (for vhost fuzzing) |

> [!tip] **Pick the filter metric by what's *constant* in a miss, not what's convenient.**
> - **Single fixed catch-all size** → `-fs`.
> - **Size drifts** — the miss echoes the requested host/path, or carries timestamps / CSRF tokens / per-request nonces → the byte count is useless; filter on **`-fw` / `-fl`** (word & line counts usually hold steady) or hand it to **`-ac`**.
> - **Same page served at many sizes** → **`-fr`** to regex the body, or invert to **`-mr`** on the success string (match meaning instead of filtering noise).
>
> When in doubt, reach for **`-ac`** first — it baselines across all three metrics so you don't have to. Same trap and same fixes bite **soft-404 directory fuzzing** (a 200 "not found" page whose size varies), not just vhosts.

> [!warning] **Match on meaning, not on a byte count.** `-fs <size>` / `-fc <code>` are brittle: the number is instance-specific, and if it's off by one, the filter hides the **correct** result too — which looks like a failed technique (bad seed, wrong payload) rather than a bad filter. Prefer matching the semantic success string:
> ```bash
> # Brittle — hides the hit if the "invalid" page isn't exactly 1256 bytes
> ffuf -w codes.txt -u '.../activate.php?code=FUZZ' -k --fs 1256
> # Robust — matches on what success actually says
> ffuf -w codes.txt -u '.../activate.php?code=FUZZ' -k -mc all -mr 'Account activated'
> ```
> (Check the success string isn't a substring of a failure string — here `Account already activated.` does **not** contain `Account activated`.)

> [!warning] **Use a positive control before you trust a "no hits" result.** A filter that matches the *baseline for every request* produces a **false all-clear, not a negative**. Classic trap: port 80 blanket-redirects everything to HTTPS, so every path — real or invented — returns an identical `301`; `-fc 301` then filters **100%** of responses and the scan reports zero hits while having tested nothing. Always confirm your config against a path you **know** exists (`-u .../index.php` should hit) before believing the empty result. A crashed/partial scan is likewise unreliable-but-feels-done — re-run it, don't trust it.

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-w <wordlist>:KEYWORD` | Wordlist with keyword |
| `-u` | Target URL |
| `-H` | Custom header |
| `-X` | HTTP method |
| `-d` | POST data |
| `-b` | Cookies |
| `-v` | Verbose — show full URLs |
| `-debug-log <file>` | Log errors |
| `-t <n>` | Threads (default 40) |
| `-rate <n>` | Requests per second |
| `-recursion` | Recursive scan |
| `-recursion-depth <n>` | Max recursion depth |
| `-e <ext>` | Extensions |
| `-o <file>` | Output file |
| `-of <format>` | Output format (json, csv, html) |
| `-p <delay>` | Delay between requests |


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]], [[Class notes/HTB Academy/CPTS v2 (claude)/Cross-Site Scripting (XSS)|Cross-Site Scripting (XSS)]], [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]], [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]], [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]], [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]], [[Class notes/HTB Academy/CPTS v2 (claude)/Login Brute Forcing|Login Brute Forcing]], [[Class notes/HTB Academy/CPTS v2 (claude)/Web Attacks|Web Attacks]] (CPTS v2). Also [[Class notes/HTB Academy/CWES Claude/Broken Auth|Broken Auth]] (CWES) — user/password/reset-token/OTP fuzzing — and [[Class notes/HTB Academy/CWES Claude/API Attacks|API Attacks]] (CWES) — parameter/ID/endpoint brute force.

---

*Created: 2026-03-13*
*Updated: 2026-08-26*
*Model: claude-opus-5*
