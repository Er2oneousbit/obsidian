# nuclei

**Tags:** `#nuclei` `#scanning` `#webenumeration` `#vulnscanning` `#automation`

Template-based vulnerability scanner from ProjectDiscovery. Runs thousands of community templates against targets to detect CVEs, misconfigurations, exposed panels, default credentials, and more. Fast, accurate, and pipeline-friendly.

**Source:** https://github.com/projectdiscovery/nuclei
**Install:** `sudo apt install nuclei` or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

```bash
nuclei -u http://10.129.14.128
```

> [!note]
> Update templates before scanning: `nuclei -update-templates`. Templates live at `~/.local/nuclei-templates/`. Severity filter with `-s` to focus on critical/high findings. Pair with `subfinder` and `httpx` for automated attack surface scanning.

---

## Basic Usage

```bash
# Scan single target (all templates)
nuclei -u http://10.129.14.128

# Scan from list of URLs
nuclei -l urls.txt

# Update templates first
nuclei -update-templates
nuclei -u http://10.129.14.128
```

---

## Severity Filtering

```bash
# Only critical and high severity
nuclei -u http://10.129.14.128 -s critical,high

# Exclude info noise
nuclei -u http://10.129.14.128 -es info

# Specific severity only
nuclei -u http://10.129.14.128 -s medium
```

---

## Template Selection

```bash
# Specific template
nuclei -u http://10.129.14.128 -t exposures/files/git-config.yaml

# Template directory
nuclei -u http://10.129.14.128 -t exposures/

# Template by tag
nuclei -u http://10.129.14.128 -tags cve
nuclei -u http://10.129.14.128 -tags default-login
nuclei -u http://10.129.14.128 -tags wordpress
nuclei -u http://10.129.14.128 -tags sqli,xss

# Exclude template
nuclei -u http://10.129.14.128 -exclude-tags dos
```

---

## Common Template Categories

| Path | Finds |
|------|-------|
| `cves/` | CVE-specific exploits |
| `exposures/` | Exposed files, configs, credentials |
| `misconfigurations/` | Security misconfigs |
| `default-logins/` | Default credentials |
| `technologies/` | Tech fingerprinting |
| `takeovers/` | Subdomain takeovers |
| `network/` | Network service checks |
| `ssl/` | TLS/SSL issues |

---

## Pipeline Integration

```bash
# subfinder → httpx → nuclei (full auto recon)
subfinder -d inlanefreight.com -silent | \
  httpx -silent | \
  nuclei -s critical,high -o findings.txt

# Probe live hosts then scan
cat urls.txt | httpx -silent | nuclei -tags cve,default-login -o results.txt

# Scan with custom headers (authenticated)
nuclei -u http://10.129.14.128 \
  -H "Cookie: PHPSESSID=abc123" \
  -H "Authorization: Bearer eyJ..."
```

---

## Output

```bash
# Save to file
nuclei -u http://10.129.14.128 -o results.txt

# JSON output
nuclei -u http://10.129.14.128 -json -o results.json

# Silent (findings only, no banner)
nuclei -u http://10.129.14.128 -silent

# Stats during scan
nuclei -u http://10.129.14.128 -stats
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-l` | URL list file |
| `-t` | Template file/directory |
| `-tags` | Run by tag |
| `-s` | Severity filter |
| `-es` | Exclude severity |
| `-o` | Output file |
| `-json` | JSON output |
| `-silent` | Findings only |
| `-stats` | Show scan progress |
| `-c <n>` | Concurrency (default 25) |
| `-H` | Custom header |
| `-update-templates` | Update template DB |
| `-proxy` | HTTP proxy |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
