# wafw00f

**Tags:** `#wafw00f` `#waf` `#webenumeration` `#fingerprinting` `#web`

WAF (Web Application Firewall) detection tool. Sends a series of HTTP requests and analyzes responses to fingerprint which WAF product (if any) is protecting the target. Knowing the WAF helps select appropriate bypass techniques before running scanners or payloads.

**Source:** https://github.com/EnableSecurity/wafw00f
**Install:** `sudo apt install wafw00f` or `pip install wafw00f`

```bash
wafw00f http://target.com
```

> [!note]
> Run wafw00f before active scanning or payload testing. Knowing the WAF (Cloudflare, Akamai, AWS WAF, ModSecurity, etc.) informs your bypass approach. If no WAF is detected, proceed more aggressively. If detected, use vendor-specific bypass techniques or rate limit requests.

---

## Basic Usage

```bash
# Detect WAF
wafw00f http://target.com
wafw00f https://target.com

# Verbose output (shows what tests were performed)
wafw00f -v http://target.com

# Test all WAF signatures (not just first match)
wafw00f -a http://target.com

# Follow redirects
wafw00f -r http://target.com
```

---

## Multiple Targets

```bash
# From file (one URL per line)
wafw00f -i targets.txt

# Batch with output
wafw00f -i targets.txt -o results.csv -f csv
```

---

## Output Formats

```bash
# JSON
wafw00f http://target.com -o results.json -f json

# CSV
wafw00f http://target.com -o results.csv -f csv

# Text (default)
wafw00f http://target.com -o results.txt -f text
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-v` | Verbose |
| `-a` | Test all WAF signatures |
| `-r` | Follow redirects |
| `-t` | Request timeout |
| `-p` | HTTP proxy |
| `-i` | Input file |
| `-o` | Output file |
| `-f` | Output format: json/csv/text |

---

## WAFs Detected (Notable)

```
Cloudflare
Akamai
AWS WAF
Imperva / Incapsula
F5 BIG-IP ASM
Barracuda WAF
ModSecurity
Sucuri
Wordfence (WordPress)
Nginx (lua-resty-waf)
Fortinet FortiWeb
Citrix NetScaler
DenyAll
NAXSI
```

---

## WAF Bypass Approach by Product

```
Cloudflare:
  - Encode payloads (URL, HTML entities, Unicode)
  - Add legitimate context around payload
  - Use case variation: <ScRiPt>
  - Chunked transfer encoding
  - Origin IP direct access (bypass CDN entirely)

ModSecurity (generic):
  - Whitespace / comment injection: /*!50000 SELECT*/
  - HPP (HTTP Parameter Pollution): ?id=1&id=UNION
  - Encoding: double URL, HTML entities
  - Case variation in SQL keywords

AWS WAF:
  - Similar encoding techniques
  - Check for IP-based bypass if rules misconfigured

Akamai:
  - Slow requests (rate-based evasion)
  - Distributed source IPs

General bypass techniques:
  - Find direct IP / origin (check Shodan, SecurityTrails)
  - DNS history lookup for pre-CDN IPs
  - Try subdomains that may bypass WAF (dev., staging., api.)
```

---

## nmap Alternative

```bash
# nmap can also detect WAFs via HTTP scripts
nmap --script http-waf-detect http://target.com
nmap --script http-waf-fingerprint http://target.com
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
