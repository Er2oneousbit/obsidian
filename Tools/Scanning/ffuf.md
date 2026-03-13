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
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -v

# File extension fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://10.129.14.128/indexFUZZ -v

# Filename fuzzing (known extension)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://10.129.14.128/FUZZ.php -v

# Recursive scan (-recursion-depth 1 = one level deep)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -recursion -recursion-depth 2 -e .php -v

# Multiple extensions at once
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:FUZZ \
  -u http://10.129.14.128/FUZZ -e .php,.html,.txt,.bak,.conf -v
```

---

## Subdomain & Vhost Fuzzing

```bash
# Public subdomain (DNS)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.inlanefreight.com/ -v

# Virtual host (Host header — finds internal vhosts)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://10.129.14.128/ -H "Host: FUZZ.inlanefreight.htb" -fs 612 -v
```

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
| `-mc <codes>` | Match only these status codes |
| `-ms <size>` | Match response size |

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

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
