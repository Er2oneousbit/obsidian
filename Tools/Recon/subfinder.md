# subfinder

**Tags:** `#subfinder` `#recon` `#osint` `#subdomain` `#passivedns`

Fast passive subdomain discovery tool from ProjectDiscovery. Queries certificate transparency logs, DNS datasets, and passive DNS APIs to enumerate subdomains without touching the target. Designed for speed and pipeline integration with other tools like httpx and nuclei.

**Source:** https://github.com/projectdiscovery/subfinder
**Install:** `sudo apt install subfinder` or `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

```bash
subfinder -d inlanefreight.com -silent
```

> [!note]
> Passive only — no direct contact with the target. For active brute force add `-active` or pipe results into `dnsx`/`httpx`. Configure API keys in `~/.config/subfinder/provider-config.yaml` for more sources (Shodan, Censys, VirusTotal, etc.).

---

## Basic Usage

```bash
# Simple enum
subfinder -d inlanefreight.com

# Silent output (subdomains only)
subfinder -d inlanefreight.com -silent

# Save to file
subfinder -d inlanefreight.com -o subdomains.txt

# Multiple domains
subfinder -d inlanefreight.com -d example.com -silent

# Domains from file
subfinder -dL domains.txt -o subdomains.txt
```

---

## Sources & API Keys

```bash
# List available sources
subfinder -ls

# Use all sources (slower, needs API keys)
subfinder -d inlanefreight.com -all -silent

# Use specific sources
subfinder -d inlanefreight.com -sources shodan,censys,virustotal
```

API key config: `~/.config/subfinder/provider-config.yaml`
```yaml
shodan:
  - YOUR_SHODAN_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
virustotal:
  - YOUR_VT_KEY
```

---

## Pipeline (with httpx / nuclei)

```bash
# Find subdomains → probe live hosts
subfinder -d inlanefreight.com -silent | httpx -silent

# Find subdomains → probe → run nuclei
subfinder -d inlanefreight.com -silent | httpx -silent | nuclei -t exposures/

# Save IPs of live hosts
subfinder -d inlanefreight.com -silent | httpx -silent -ip -o live-hosts.txt
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain |
| `-dL <file>` | Domain list file |
| `-o <file>` | Output file |
| `-silent` | Print subdomains only |
| `-all` | Use all sources |
| `-sources <list>` | Specific sources (comma-separated) |
| `-ls` | List all sources |
| `-recursive` | Enable recursive subdomain discovery |
| `-v` | Verbose output |
| `-json` | JSON output |
| `-t <n>` | Threads (default 10) |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
