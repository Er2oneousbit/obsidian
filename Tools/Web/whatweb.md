# whatweb

**Tags:** `#whatweb` `#fingerprinting` `#techdetect` `#webenumeration` `#web`

Web fingerprinting tool. Identifies web technologies — CMS, frameworks, JavaScript libraries, web servers, analytics platforms — by analyzing HTTP response headers, HTML, and JavaScript. Faster than manual inspection and works well for bulk scanning with different aggression levels.

**Source:** https://github.com/urbanadventurer/WhatWeb
**Install:** Pre-installed on Kali — `sudo apt install whatweb`

```bash
whatweb http://target.com
```

> [!note]
> Aggression level matters: `-a 1` (passive, single request) vs `-a 3` (aggressive, multiple requests, follows redirects, triggers more plugins). Use `-a 1` for stealth, `-a 3` for thorough results. Use `-v` for verbose per-plugin output.

---

## Basic Usage

```bash
# Default scan (aggression level 1)
whatweb http://target.com

# Aggressive scan (level 3 — more requests, better coverage)
whatweb -a 3 http://target.com

# Verbose (shows each plugin result)
whatweb -v http://target.com

# Aggressive + verbose
whatweb -a 3 -v http://target.com
```

---

## Aggression Levels

```bash
# -a 1  Passive — single request, no additional crawling (default)
# -a 2  Polite — follow redirects, check robots.txt
# -a 3  Aggressive — tries common paths, more requests per target
# -a 4  Heavy — many requests, brute forces common files (noisy)

whatweb -a 1 http://target.com    # stealth — one request
whatweb -a 3 http://target.com    # standard assessment
whatweb -a 4 http://target.com    # thorough but noisy
```

---

## Multiple Targets

```bash
# From file (one URL per line)
whatweb -i targets.txt

# CIDR range
whatweb 10.10.10.0/24

# Multiple URLs inline
whatweb http://target1.com http://target2.com http://target3.com

# Pipe from other tools
cat hosts.txt | xargs whatweb
subfinder -d example.com -silent | httpx -silent | xargs whatweb
```

---

## Output Formats

```bash
# Default (brief, one line per target)
whatweb http://target.com

# Verbose (all plugins expanded)
whatweb -v http://target.com

# JSON output
whatweb http://target.com --log-json results.json

# XML
whatweb http://target.com --log-xml results.xml

# CSV
whatweb http://target.com --log-csv results.csv

# Brief (suppress non-findings)
whatweb http://target.com --log-brief results.txt

# Quiet (only errors)
whatweb http://target.com -q
```

---

## Authentication & Proxy

```bash
# Basic auth
whatweb http://target.com --user admin:password

# Cookie
whatweb http://target.com --cookie "PHPSESSID=abc123"

# Custom header
whatweb http://target.com --header "Authorization: Bearer token"

# Through proxy
whatweb http://target.com --proxy http://127.0.0.1:8080

# Custom user agent
whatweb http://target.com -U "Mozilla/5.0"
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-a <level>` | Aggression: 1-4 (default 1) |
| `-v` | Verbose output |
| `-i <file>` | Input file |
| `-t <n>` | Threads (default 25) |
| `--user` | Basic auth user:pass |
| `--cookie` | Cookie string |
| `--header` | Custom header |
| `-U` | User agent |
| `--proxy` | HTTP proxy |
| `--log-json` | JSON log file |
| `--log-xml` | XML log file |
| `--log-csv` | CSV log file |
| `-q` | Quiet |
| `--no-errors` | Suppress connection errors |
| `--follow-redirect` | Follow redirects (default: some) |

---

## Example Output

```
http://target.com [200 OK] Apache[2.4.41], Bootstrap[4.5.2],
  Cookies[PHPSESSID], Country[UNITED STATES][US],
  HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)],
  IP[10.10.10.10], JQuery[3.5.1], PHP[7.4.3],
  Script, Title[Company | Home], WordPress[5.6.0],
  X-Powered-By[PHP/7.4.3]
```

---

## Post-Fingerprint Actions

```bash
# WordPress detected
wpscan --url http://target.com --api-token TOKEN

# PHP version detected → check for vulns
searchsploit php 7.4

# Apache version → check vulns
searchsploit apache 2.4.41

# jQuery version → check retire.js
retire --url http://target.com

# Cookies without HttpOnly/Secure → note for report
# X-Powered-By header → version disclosure finding
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
