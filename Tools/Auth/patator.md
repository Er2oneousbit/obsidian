# Patator

**Tags:** `#patator` `#bruteforce` `#passwordattack` `#auth` `#spray` `#multiprotocol`

Multi-purpose brute-forcer with a modular, flexible design. The main advantage over Hydra/Medusa is granular control over request logic and response filtering — you define exactly what counts as a hit or miss using regex on the response. Excellent for HTTP forms, custom applications, and any case where simple success/fail matching is too crude.

**Source:** https://github.com/lanjelot/patator
**Install:** `sudo apt install patator` — pre-installed on Kali

```bash
# List all available modules
patator --help

# Get help for a specific module
patator ssh_login --help
patator http_fuzz --help
```

> [!note] **Patator vs Hydra/Medusa** — Use Patator when you need fine-grained response filtering (regex match/ignore on body, headers, status codes) or when Hydra/Medusa mishandle a target's responses. It's more verbose to set up but much more reliable against custom login forms and anti-brute-force responses.

---

## Core Syntax

Patator uses `FILE0`, `FILE1`, etc. as positional placeholders that map to `0=wordlist.txt` arguments.

```bash
patator <module> <module_options> 0=<wordlist> -x ignore:<filter>
```

**Common ignore filters:**

| Filter | Meaning |
|---|---|
| `-x ignore:code=200` | Ignore HTTP 200 responses (fail = 200, success = redirect) |
| `-x ignore:mesg='Login failed'` | Ignore responses containing this string |
| `-x ignore:fgrep='Invalid password'` | Fast string match (no regex) |
| `-x ignore:size=1234` | Ignore responses of this byte size |
| `-x ignore:egrep='(failed\|error\|invalid)'` | Regex match |

---

## SSH

```bash
# Username + password list
patator ssh_login host=10.10.10.10 user=root password=FILE0 0=/usr/share/wordlists/rockyou.txt \
  -x ignore:mesg='Authentication failed'

# User list + password list
patator ssh_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='Authentication failed'

# Non-standard port
patator ssh_login host=10.10.10.10 port=2222 user=admin password=FILE0 0=passwords.txt \
  -x ignore:mesg='Authentication failed'
```

---

## FTP

```bash
patator ftp_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='Login incorrect'
```

---

## HTTP Form (POST)

```bash
# Basic login form — ignore responses containing the failure string
patator http_fuzz url=http://10.10.10.10/login.php method=POST \
  body='username=FILE0&password=FILE1' \
  0=users.txt 1=passwords.txt \
  -x ignore:fgrep='Invalid credentials'

# Ignore by HTTP status code (success = 302 redirect, fail = 200)
patator http_fuzz url=http://10.10.10.10/login.php method=POST \
  body='user=FILE0&pass=FILE1' \
  0=users.txt 1=passwords.txt \
  -x ignore:code=200

# With session cookie / CSRF token (grab token first, pass via header)
patator http_fuzz url=http://10.10.10.10/login method=POST \
  header='Cookie: session=abc123' \
  body='username=FILE0&password=FILE1&_token=xyz' \
  0=users.txt 1=passwords.txt \
  -x ignore:fgrep='Wrong password'
```

---

## HTTP Basic Auth

```bash
patator http_fuzz url=http://10.10.10.10/admin/ \
  user_pass=FILE0:FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:code=401
```

---

## SMB

```bash
patator smb_login host=10.10.10.10 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt \
  -x ignore:mesg='STATUS_LOGON_FAILURE'
```

---

## MySQL / MSSQL

```bash
# MySQL
patator mysql_login host=10.10.10.10 user=root password=FILE0 0=passwords.txt \
  -x ignore:fgrep='Access denied'

# MSSQL
patator mssql_login host=10.10.10.10 user=sa password=FILE0 0=passwords.txt \
  -x ignore:fgrep='Login failed'
```

---

## DNS Subdomain Enumeration

```bash
patator dns_forward domain=FILE0.target.com 0=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -x ignore:code=NXDOMAIN
```

---

## Useful Options

```bash
# Threads (default: 10)
patator ssh_login ... --threads=4

# Delay between attempts (ms) — helps avoid lockouts
patator ssh_login ... --sleep=500

# Stop after N hits
patator ssh_login ... --max-hits=1

# Save results to file
patator ssh_login ... --log-file=results.txt

# Retry on connection errors
patator ssh_login ... --tries=2
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
