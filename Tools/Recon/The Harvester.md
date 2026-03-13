# theHarvester

**Tags:** `#harvester` `#theHarvester` `#recon` `#osint` `#passivedns` `#email`

OSINT tool for passive external recon. Aggregates data from search engines, certificate transparency, DNS datasets, and social media to harvest email addresses, subdomains, hosts, open ports, and employee names. Good first-pass tool before active scanning.

**Source:** https://github.com/laramies/theHarvester
**Install:** Pre-installed on Kali — `theHarvester`

```bash
theHarvester -d inlanefreight.com -b all
```

> [!note]
> Many sources require API keys for full results — configure in `/etc/theHarvester/api-keys.yaml`. Without keys, `google`, `bing`, `crtsh`, and `dnsdumpster` still work without auth. Use `-b all` to try everything.

---

## Basic Usage

```bash
# Single source
theHarvester -d inlanefreight.com -b google

# All sources
theHarvester -d inlanefreight.com -b all

# Limit results
theHarvester -d inlanefreight.com -b google -l 500

# Save to XML + HTML report
theHarvester -d inlanefreight.com -b all -f results

# JSON output
theHarvester -d inlanefreight.com -b all -f results.json --json-file
```

---

## Useful Sources

| Source | Finds | API Key Needed |
|--------|-------|----------------|
| `google` | Subdomains, emails | No |
| `bing` | Subdomains, emails | No |
| `crtsh` | Subdomains (cert transparency) | No |
| `dnsdumpster` | Subdomains, hosts | No |
| `shodan` | Open ports, banners, hosts | Yes |
| `hunter` | Emails, employee names | Yes |
| `linkedin` | Employee names | Yes |
| `virustotal` | Subdomains | Yes |
| `censys` | Hosts, IPs | Yes |

```bash
# Free sources only
theHarvester -d inlanefreight.com -b google,bing,crtsh,dnsdumpster
```

---

## Bulk Source Sweep (HTB Workflow)

```bash
# Create sources list
cat > sources.txt << 'EOF'
baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
EOF

export TARGET="inlanefreight.com"

# Run against all sources, save per-source files
cat sources.txt | while read source; do
  theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}" 2>/dev/null
done

# Combine and deduplicate subdomains
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f1 | sort -u > "${TARGET}_subdomains.txt"
cat *.txt | sort -u >> "${TARGET}_subdomains.txt"
sort -u "${TARGET}_subdomains.txt" -o "${TARGET}_subdomains.txt"

wc -l "${TARGET}_subdomains.txt"
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain |
| `-b <source>` | Data source(s), comma-separated, or `all` |
| `-l <n>` | Result limit (default 500) |
| `-f <file>` | Output file (creates `.xml` and `.json`) |
| `-v` | Verify hosts via DNS resolution |
| `-n` | DNS brute force on found hosts |
| `-c` | DNS brute force with TLD expansion |
| `-s <port>` | SHODAN source with specific port |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
