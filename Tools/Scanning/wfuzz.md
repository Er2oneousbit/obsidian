# wfuzz

**Tags:** `#wfuzz` `#webenumeration` `#fuzzing` `#bruteforce`

Web application fuzzer written in Python. Replaces `FUZZ` in any part of the request — URL, headers, POST data, cookies. Supports multiple injection points, payload encoding, and flexible filtering. Useful for directory brute force, vhost/subdomain discovery, and parameter fuzzing.

**Source:** https://github.com/xmendez/wfuzz
**Install:** Pre-installed on Kali — `sudo apt install wfuzz`

```bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  --sc 200,301,302 -u http://10.129.14.128/FUZZ
```

> [!note]
> Use `--sc` (show codes) or `--hc` (hide codes) to filter noise. `-c` enables color output. `-Z` ignores connection errors. For most tasks ffuf is faster, but wfuzz's flexible payload encoding and multiple injection points make it useful for complex fuzzing scenarios.

---

## Directory / File Fuzzing

```bash
# Basic directory brute force
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  --sc 200,301,302 -u http://10.129.14.128/FUZZ

# File extension fuzzing
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  --sc 200 -u http://10.129.14.128/indexFUZZ

# With specific extension
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  --sc 200,301 -u http://10.129.14.128/FUZZ.php
```

---

## Vhost / Subdomain Fuzzing

```bash
# Vhost fuzzing (Host header)
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.inlanefreight.htb" \
  --hh 612 -u http://10.129.14.128/

# Subdomain DNS fuzzing
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --sc 200,202,204,301,302,307,403 \
  -u http://FUZZ.inlanefreight.com/

# Save results
wfuzz -c -f sub-fighter.txt -Z \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --sc 200,202,204,301,302,307,403 http://FUZZ.inlanefreight.com/
```

---

## POST Data Fuzzing

```bash
# Fuzz POST parameter value
wfuzz -c -w /usr/share/seclists/Usernames/Names/names.txt \
  --sc 200 -d "username=FUZZ&password=test" \
  -u http://10.129.14.128/login.php

# Fuzz POST parameter name
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --hh 1234 -d "FUZZ=test" \
  -u http://10.129.14.128/admin.php
```

---

## Auth & Session

```bash
# Cookie
wfuzz -c -w wordlist.txt --sc 200 \
  -b "PHPSESSID=abc123" \
  -u http://10.129.14.128/FUZZ

# Basic auth
wfuzz -c -w wordlist.txt --sc 200 \
  --basic "admin:password" \
  -u http://10.129.14.128/FUZZ
```

---

## Filtering

| Flag | Description |
|------|-------------|
| `--sc <codes>` | Show only these status codes |
| `--hc <codes>` | Hide these status codes |
| `--ss <string>` | Show responses containing string |
| `--hs <string>` | Hide responses containing string |
| `--sh <size>` | Hide responses of this size |
| `--hh <chars>` | Hide responses with this char count |
| `--sl <lines>` | Hide responses with this line count |

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-c` | Color output |
| `-w <file>` | Wordlist |
| `-u` | Target URL (use `FUZZ` as placeholder) |
| `-H` | Custom header |
| `-d` | POST data |
| `-b` | Cookie |
| `-Z` | Ignore errors (continue on connection failure) |
| `-f <file>` | Save output to file |
| `-t <n>` | Threads (default 10) |
| `-s <sec>` | Delay between requests |
| `--proxy` | HTTP proxy |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
