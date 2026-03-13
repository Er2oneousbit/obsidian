# feroxbuster

**Tags:** `#feroxbuster` `#webenumeration` `#fuzzing` `#dirbusting`

Fast, recursive content discovery tool written in Rust. Automatically recurses into discovered directories — the key advantage over ffuf/gobuster. Handles rate limiting, response filtering, and parallel scanning well out of the box.

**Source:** https://github.com/epi052/feroxbuster
**Install:** `sudo apt install feroxbuster`

```bash
feroxbuster -u http://10.129.14.128 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

> [!note]
> Recursive scanning is on by default — feroxbuster automatically dives into discovered directories. Use `-d` to cap depth and `--filter-size`/`--filter-status` to cut noise before reading results.

---

## Basic Usage

```bash
# Directory brute force
feroxbuster -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With file extensions
feroxbuster -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,bak,conf,xml

# Limit recursion depth
feroxbuster -u http://10.129.14.128 -w wordlist.txt -d 2

# No recursion
feroxbuster -u http://10.129.14.128 -w wordlist.txt --no-recursion
```

---

## Filtering Output

```bash
# Filter out status codes
feroxbuster -u http://10.129.14.128 -w wordlist.txt --filter-status 404,403

# Filter by response size (remove identical-sized error pages)
feroxbuster -u http://10.129.14.128 -w wordlist.txt --filter-size 1234

# Show only specific status codes
feroxbuster -u http://10.129.14.128 -w wordlist.txt --status-codes 200,301,302
```

---

## Auth & Headers

```bash
# Cookie session
feroxbuster -u http://10.129.14.128 -w wordlist.txt \
  -b "PHPSESSID=abc123; security=low"

# Custom header
feroxbuster -u http://10.129.14.128 -w wordlist.txt \
  -H "Authorization: Bearer eyJ..."

# Basic auth
feroxbuster -u http://10.129.14.128 -w wordlist.txt \
  --username admin --password password123
```

---

## HTTPS / Proxy

```bash
# Ignore TLS cert errors
feroxbuster -u https://10.129.14.128 -w wordlist.txt -k

# Through Burp proxy
feroxbuster -u http://10.129.14.128 -w wordlist.txt --proxy http://127.0.0.1:8080
```

---

## Output

```bash
feroxbuster -u http://10.129.14.128 -w wordlist.txt -o results.txt
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | Extensions (comma-separated) |
| `-d <n>` | Max recursion depth |
| `--no-recursion` | Disable auto-recursion |
| `-t <n>` | Threads (default 50) |
| `--filter-status` | Filter response codes |
| `--filter-size` | Filter by response size |
| `--status-codes` | Only show these codes |
| `-b` | Cookies |
| `-H` | Custom headers |
| `-k` | Ignore TLS errors |
| `--proxy` | HTTP proxy |
| `-o` | Output file |
| `-q` | Quiet mode |

---

## Wordlists

```bash
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt   # good default
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt          # file hunting
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt # classic
/usr/share/seclists/Discovery/Web-Content/common.txt                    # fast/small
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
