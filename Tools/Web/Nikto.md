# Nikto

**Tags:** `#nikto` `#webenumeration` `#webscanner` `#web` `#misconfig`

Web server scanner. Checks for dangerous files/programs, outdated server software, version-specific problems, server misconfigurations, and default credentials. Fast, noisy, comprehensive — not stealthy but excellent for finding low-hanging fruit and server-level issues.

**Source:** https://github.com/sullo/nikto
**Install:** Pre-installed on Kali — `sudo apt install nikto`

```bash
nikto -h http://target.com
```

> [!note]
> Nikto is intentionally noisy — it will be logged. Use it early in assessments when stealth doesn't matter, or when you want comprehensive coverage. The `-Tuning` flag selects test categories; `-Tuning b` runs everything. Pair with Burp to capture interesting requests for manual follow-up.

---

## Basic Usage

```bash
# Basic scan
nikto -h http://target.com

# HTTPS
nikto -h https://target.com

# Specific port
nikto -h http://target.com -p 8080

# Save output
nikto -h http://target.com -o results.txt
nikto -h http://target.com -o results.html -Format html
```

---

## Tuning (Test Categories)

```bash
# Run all tests
nikto -h http://target.com -Tuning b

# Specific categories
nikto -h http://target.com -Tuning 1   # Interesting files
nikto -h http://target.com -Tuning 2   # Misconfiguration
nikto -h http://target.com -Tuning 3   # Information disclosure
nikto -h http://target.com -Tuning 4   # Injection (XSS/Script)
nikto -h http://target.com -Tuning 5   # Remote file retrieval (inside webroot)
nikto -h http://target.com -Tuning 6   # Denial of Service
nikto -h http://target.com -Tuning 7   # Remote file retrieval (server wide)
nikto -h http://target.com -Tuning 8   # Command execution / remote shell
nikto -h http://target.com -Tuning 9   # SQL injection
nikto -h http://target.com -Tuning 0   # Upload
nikto -h http://target.com -Tuning a   # Authentication bypass
nikto -h http://target.com -Tuning b   # All (everything above)
```

---

## Authentication

```bash
# Basic auth
nikto -h http://target.com -id admin:password

# With cookie
nikto -h http://target.com -c "PHPSESSID=abc123; admin=1"

# Follow redirects (needed for auth flows)
nikto -h http://target.com -followredirects
```

---

## Proxy & Evasion

```bash
# Through Burp proxy (captures requests for review)
nikto -h http://target.com -useproxy http://127.0.0.1:8080

# Evasion methods (encode requests to evade IDS)
nikto -h http://target.com -evasion 1   # random URI encoding
nikto -h http://target.com -evasion 2   # directory self-reference (/./)
nikto -h http://target.com -evasion 3   # premature URL ending
nikto -h http://target.com -evasion 4   # prepend long random string
nikto -h http://target.com -evasion 5   # fake parameter
nikto -h http://target.com -evasion 6   # TAB as request spacer
nikto -h http://target.com -evasion 7   # change the case of the URL
nikto -h http://target.com -evasion 8   # use Windows path separator (\)

# Combine multiple evasion methods
nikto -h http://target.com -evasion 1278
```

---

## Multiple Targets

```bash
# From file (one URL/host per line)
nikto -h targets.txt

# Nmap XML input
nikto -h nmap.xml
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-h` | Target host/URL |
| `-p` | Port (default: 80/443) |
| `-ssl` | Force SSL |
| `-Tuning` | Test category (b = all) |
| `-id` | Basic auth credentials (user:pass) |
| `-c` | Cookie string |
| `-useproxy` | HTTP proxy |
| `-evasion` | IDS evasion method (1-8) |
| `-o` | Output file |
| `-Format` | Output format: txt, html, csv, xml |
| `-timeout` | Request timeout |
| `-followredirects` | Follow HTTP redirects |
| `-maxtime` | Max scan time (e.g., `1h`) |
| `-update` | Update plugin database |
| `-nointeractive` | Suppress prompts |

---

## What Nikto Checks

```
- Server version disclosure (Apache, nginx, IIS)
- Default files and directories
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Backup files (.bak, .old, ~files)
- Source code disclosure (.php~, .php.bak)
- Directory listings enabled
- Default credentials (Tomcat manager, etc.)
- CGI vulnerabilities
- Shellshock (CVE-2014-6271)
- Heartbleed (CVE-2014-0160)
- Clickjacking (X-Frame-Options missing)
- Missing security headers (X-XSS-Protection, HSTS, etc.)
- SQL injection fingerprinting
- XSS in parameters
- Remote file inclusion patterns
- PHP information disclosure (phpinfo())
- robots.txt / sitemap.xml sensitive entries
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
