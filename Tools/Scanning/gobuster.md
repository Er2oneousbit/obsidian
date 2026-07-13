# gobuster

**Tags:** `#gobuster` `#webenumeration` `#dirbusting` `#dnsenumeration` `#fuzzing`

Directory/file, DNS, and vhost brute-forcing tool written in Go. Faster than traditional tools (dirb, dirbuster) with clean output. Modes: `dir` (web content), `dns` (subdomains), `vhost` (virtual hosts), `fuzz` (generic), `s3` (S3 buckets).

**Source:** https://github.com/OJ/gobuster
**Install:** `sudo apt install gobuster`

```bash
gobuster dir -u http://10.129.14.128 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

> [!note]
> Use `dir` for web content, `dns` for subdomain brute force, `vhost` for virtual hosts. Add `-x` for file extensions in `dir` mode. Filter noise with `-b` (exclude status codes).

---

## Directory / File Mode (`dir`)

```bash
# Basic directory scan
gobuster dir -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# With file extensions
gobuster dir -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,conf,xml

# Custom port
gobuster dir -u http://10.129.14.128:8080 -w wordlist.txt

# HTTPS (ignore cert)
gobuster dir -u https://10.129.14.128 -w wordlist.txt -k

# Filter status codes (exclude 403,404)
gobuster dir -u http://10.129.14.128 -w wordlist.txt -b 403,404

# With cookies
gobuster dir -u http://10.129.14.128 -w wordlist.txt \
  -c "PHPSESSID=abc123; security=low"

# Through Burp proxy
gobuster dir -u http://10.129.14.128 -w wordlist.txt \
  --proxy http://127.0.0.1:8080

# Output to file
gobuster dir -u http://10.129.14.128 -w wordlist.txt -o results.txt
```

---

## DNS Subdomain Mode (`dns`)

```bash
# Basic subdomain brute force
gobuster dns -d inlanefreight.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Custom DNS resolver
gobuster dns -d inlanefreight.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r 10.129.14.128

# Quiet mode + output
gobuster dns -q -d inlanefreight.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o subdomains.txt

# With pattern file (expands GOBUSTER keyword in pattern)
gobuster dns -d facebook.com -r d.ns.facebook.com \
  -w numbers.txt -p ./patterns.txt -o gobuster_facebook.txt -q
```

Pattern file format (`patterns.txt`):
```
lert-api-shv-{GOBUSTER}-sin6
atlas-pp-shv-{GOBUSTER}-sin6
```

---

## Vhost Mode (`vhost`)

```bash
# Virtual host discovery (Host header fuzzing)
gobuster vhost -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain inlanefreight.htb --append-domain

# Filter default response size
gobuster vhost -u http://10.129.14.128 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain inlanefreight.htb --append-domain \
  --exclude-length 612
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | Extensions (`dir` mode) |
| `-t <n>` | Threads (default 10) |
| `-b <codes>` | Exclude status codes |
| `-k` | Ignore TLS errors |
| `-c` | Cookies |
| `-H` | Custom header |
| `-r` | Custom DNS resolver (`dns` mode) |
| `-p` | Pattern file (`dns` mode) |
| `-q` | Quiet — no banner |
| `-o` | Output file |
| `--proxy` | HTTP proxy |

---

## Wordlists

```bash
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
