# WPScan

**Tags:** `#wpscan` `#wordpress` `#cms` `#webenumeration` `#bruteforce` `#web`

Automated WordPress security scanner and enumeration tool. Identifies vulnerable plugins, themes, and core versions; enumerates users, media, backups, and config files; and can brute force credentials via xmlrpc or login page. API token (free registration) unlocks the vulnerability database.

**Source:** https://github.com/wpscanteam/wpscan
**Install:** Pre-installed on Kali — `sudo apt install wpscan`
**API Token:** Register free at https://wpscan.com/register

```bash
wpscan --url http://target.com --api-token TOKEN
```

> [!note]
> The API token is required for vulnerability data — without it WPScan only enumerates. Free tier gives 25 API requests/day. Register at wpscan.com. For brute force: xmlrpc attack is faster and bypasses login page protections; use it when xmlrpc.php is enabled.

---

## Basic Enumeration

```bash
# Full enumeration (all checks) — requires API token for vuln data
wpscan --url http://target.com --enumerate --api-token YOUR_TOKEN

# Without API token (no vuln data, still enumerates)
wpscan --url http://target.com --enumerate
```

---

## Targeted Enumeration

```bash
# Enumerate users only
wpscan --url http://target.com --enumerate u

# Enumerate plugins
wpscan --url http://target.com --enumerate p --api-token TOKEN

# Enumerate vulnerable plugins only
wpscan --url http://target.com --enumerate vp --api-token TOKEN

# Enumerate vulnerable themes only
wpscan --url http://target.com --enumerate vt --api-token TOKEN

# Enumerate timthumbs (old vulnerability)
wpscan --url http://target.com --enumerate tt

# Enumerate config backups
wpscan --url http://target.com --enumerate cb

# Enumerate DB exports
wpscan --url http://target.com --enumerate dbe

# Enumerate media IDs
wpscan --url http://target.com --enumerate m
```

---

## Enumeration Codes Reference

| Code | Target |
|------|--------|
| `u` | Users |
| `p` | Plugins |
| `vp` | Vulnerable plugins |
| `ap` | All plugins |
| `t` | Themes |
| `vt` | Vulnerable themes |
| `at` | All themes |
| `tt` | Timthumbs |
| `cb` | Config backups |
| `dbe` | DB exports |
| `m` | Media (enumerate IDs) |
| `all` | Everything |

---

## Password Attacks

```bash
# xmlrpc brute force (faster, bypasses lockout on some configs)
wpscan --url http://target.com \
  --password-attack xmlrpc \
  -t 20 \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt

# Login page brute force
wpscan --url http://target.com \
  --password-attack login \
  -U admin \
  -P /usr/share/seclists/Passwords/darkweb2017-top10000.txt

# Multiple usernames (from enumeration output)
wpscan --url http://target.com \
  --password-attack xmlrpc \
  -U users.txt \
  -P passwords.txt
```

---

## Plugin Detection Mode

```bash
# Passive (default) — parse HTML only
wpscan --url http://target.com --detection-mode passive

# Aggressive — probe common plugin paths actively
wpscan --url http://target.com --enumerate ap --detection-mode aggressive

# Mixed (default when using --enumerate)
wpscan --url http://target.com --enumerate p --detection-mode mixed
```

---

## Authentication & Proxy

```bash
# With WordPress login cookie (for authenticated scans)
wpscan --url http://target.com \
  --cookie "wordpress_logged_in_HASH=value; wordpress_sec_HASH=value"

# HTTP basic auth (protecting the WordPress install)
wpscan --url http://target.com \
  --http-auth admin:password

# Through proxy
wpscan --url http://target.com --proxy http://127.0.0.1:8080

# Custom user agent
wpscan --url http://target.com -a "Mozilla/5.0"
```

---

## Output

```bash
# Save output
wpscan --url http://target.com -o results.txt

# JSON output
wpscan --url http://target.com -f json -o results.json
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `--url` | Target WordPress URL |
| `--enumerate` / `-e` | Enumerate (all or specific codes) |
| `--api-token` | WPScan API token for vuln data |
| `--password-attack` | Attack type: xmlrpc or login |
| `-U` | Username or username file |
| `-P` | Password or password file |
| `-t` | Threads (default 5) |
| `--detection-mode` | passive/aggressive/mixed |
| `--cookie` | Session cookie |
| `--http-auth` | HTTP basic auth user:pass |
| `--proxy` | HTTP proxy |
| `-a` | User agent |
| `-f json` | Output format |
| `-o` | Output file |
| `--update` | Update WPScan database |

---

## Post-Scan Actions

```bash
# Found admin user + weak password → exploit
# 1. Login at /wp-admin
# 2. Appearance → Theme Editor → 404.php → add PHP webshell
# 3. Trigger: http://target.com/wp-content/themes/THEME/404.php?cmd=id

# Found vulnerable plugin → searchsploit
searchsploit wordpress plugin-name

# xmlrpc.php enabled → multicall brute force, SSRF potential
curl -X POST http://target.com/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Backup files
curl http://target.com/wp-config.php.bak
curl http://target.com/wp-config.php~
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
