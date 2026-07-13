# testssl.sh

**Tags:** `#testssl` `#ssl` `#tls` `#certificates` `#web` `#compliance`

Bash script that tests SSL/TLS configurations and vulnerabilities. Human-readable color-coded output, comprehensive checks, and no dependencies beyond openssl and bash. The fastest tool for getting a complete TLS picture on a target — covers protocols, ciphers, certificate issues, and known vulnerabilities.

**Source:** https://github.com/drwetter/testssl.sh
**Install:** Pre-installed on Kali — `sudo apt install testssl.sh` or `git clone https://github.com/drwetter/testssl.sh`

```bash
testssl.sh target.com
```

> [!note]
> testssl.sh vs SSLyze: testssl.sh has better human-readable output with color coding (red = bad, yellow = warning, green = good) and is easier to read quickly during an assessment. SSLyze is better for programmatic/JSON output. Both cover the same vulnerabilities.

---

## Basic Usage

```bash
# Full scan
testssl.sh target.com
testssl.sh https://target.com
testssl.sh target.com:8443

# STARTTLS
testssl.sh --starttls smtp target.com:587
testssl.sh --starttls imap target.com:143
testssl.sh --starttls ftp target.com:21
testssl.sh --starttls xmpp target.com:5222
testssl.sh --starttls ldap target.com:389
testssl.sh --starttls postgres target.com:5432
testssl.sh --starttls mysql target.com:3306
```

---

## Targeted Checks

```bash
# Protocols only
testssl.sh -p target.com

# Ciphers only
testssl.sh -e target.com         # all cipher suites
testssl.sh -E target.com         # all cipher suites per protocol

# Certificate info
testssl.sh -S target.com

# Vulnerabilities only
testssl.sh -U target.com

# Specific vulnerability
testssl.sh --heartbleed target.com
testssl.sh --robot target.com
testssl.sh --crime target.com
testssl.sh --breach target.com
testssl.sh --poodle target.com
testssl.sh --logjam target.com
testssl.sh --freak target.com
testssl.sh --drown target.com
testssl.sh --sweet32 target.com
testssl.sh --lucky13 target.com
testssl.sh --rc4 target.com
testssl.sh --ticketbleed target.com

# HTTP headers (HSTS, HPKP, CSP, etc.)
testssl.sh -h target.com
```

---

## Output & Reporting

```bash
# Save to log file
testssl.sh target.com --logfile results.log

# JSON output (for reporting tools)
testssl.sh target.com --jsonfile results.json

# HTML report
testssl.sh target.com --htmlfile results.html

# CSV output
testssl.sh target.com --csvfile results.csv

# All output formats simultaneously
testssl.sh target.com \
  --logfile results.log \
  --jsonfile results.json \
  --htmlfile results.html
```

---

## Multiple Targets

```bash
# From file (one target per line)
testssl.sh --file targets.txt

# Mass scan (parallel)
testssl.sh --parallel --file targets.txt

# CI-friendly (no color, machine-readable)
testssl.sh --color 0 --quiet target.com
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-p` | Protocols only |
| `-e` | All cipher suites |
| `-S` | Certificate info |
| `-U` | All vulnerability checks |
| `-h` | HTTP security headers |
| `--starttls <proto>` | STARTTLS: smtp/imap/ftp/ldap/postgres/mysql |
| `--heartbleed` | Heartbleed check |
| `--robot` | ROBOT check |
| `--poodle` | POODLE (SSLv3) |
| `--logjam` | LOGJAM (DH) |
| `--drown` | DROWN (SSLv2) |
| `--freak` | FREAK (EXPORT RSA) |
| `--logfile` | Log output |
| `--jsonfile` | JSON output |
| `--htmlfile` | HTML report |
| `--file` | Input file for batch |
| `--parallel` | Parallel scans |
| `--color 0` | Disable colors |
| `--quiet` | Less verbose |

---

## Reading Output

```
Color coding:
GREEN  = good / secure
YELLOW = warning / informational
RED    = bad / vulnerable / critical
BOLD   = important finding

Key sections:
 Testing protocols:          → which TLS/SSL versions are enabled
 Testing cipher categories:  → NULL, EXPORT, weak ciphers
 Testing server defaults:    → DH params, session tickets, etc.
 Testing server preferences: → cipher order, forward secrecy
 Testing vulnerabilities:    → CVE findings
 Testing HTTP header response → HSTS, HPKP, CSP, etc.
 Testing certificate:        → chain, validity, SANs, CT logs
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
