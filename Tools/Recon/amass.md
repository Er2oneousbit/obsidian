# amass

**Tags:** `#amass` `#recon` `#osint` `#subdomain` `#dns` `#passivedns`

OWASP subdomain enumeration and attack surface mapping tool. Combines passive OSINT sources (certificate transparency, DNS datasets, APIs) with active DNS brute force and crawling. Best for comprehensive external recon on a target organization.

**Source:** https://github.com/owasp-amass/amass
**Install:** `sudo apt install amass` or `go install github.com/owasp-amass/amass/v4/...@master`

```bash
amass enum -passive -d inlanefreight.com
```

> [!note]
> Passive mode uses only public data sources — no direct contact with the target. Active mode (`-active`) performs DNS resolution, zone transfers, and brute force — noisier but finds more. Use `subfinder` for fast passive-only enumeration; use amass for deep comprehensive scans.

---

## Passive Enumeration (Safe / No Target Contact)

```bash
# Basic passive subdomain enum
amass enum -passive -d inlanefreight.com

# Multiple domains
amass enum -passive -d inlanefreight.com -d inlanefreight.htb

# Save output
amass enum -passive -d inlanefreight.com -o subdomains.txt

# JSON output
amass enum -passive -d inlanefreight.com -json amass-output.json
```

---

## Active Enumeration

```bash
# Active — DNS resolution + zone transfer attempts
amass enum -active -d inlanefreight.com

# Active + brute force with wordlist
amass enum -active -brute -d inlanefreight.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Active + specify resolvers
amass enum -active -d inlanefreight.com -r 8.8.8.8,1.1.1.1

# Full scan — passive + active + brute
amass enum -d inlanefreight.com -active -brute \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o full-enum.txt
```

---

## Intel Mode (Org-Level OSINT)

```bash
# Find domains registered to an organization
amass intel -org "Inlane Freight"

# Reverse WHOIS — find all domains sharing registrant info
amass intel -whois -d inlanefreight.com

# ASN discovery
amass intel -asn 12345

# Find domains from IP range
amass intel -cidr 10.129.14.0/24
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `enum` | Subdomain enumeration mode |
| `intel` | Org/ASN/IP intelligence gathering |
| `-passive` | Passive sources only (no target contact) |
| `-active` | DNS resolution, zone transfers |
| `-brute` | DNS brute force |
| `-d <domain>` | Target domain |
| `-w <wordlist>` | Brute force wordlist |
| `-o <file>` | Text output |
| `-json <file>` | JSON output |
| `-r <resolvers>` | Custom DNS resolvers |
| `-v` | Verbose |

---

## Parse Results

```bash
# Extract unique subdomains from JSON
cat amass-output.json | jq -r '.name' | sort -u

# Combine with other tools
cat subdomains.txt | httpx -silent   # probe which are alive
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
