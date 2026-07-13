# httpx

**Tags:** `#httpx` `#webenumeration` `#probing` `#recon` `#web` `#projectdiscovery`

Fast multi-purpose HTTP toolkit from ProjectDiscovery. Probes a list of hosts/URLs for live web servers, extracts response data (status code, title, server headers, tech stack, content length), and filters/formats output for pipeline integration. The standard tool for converting host/IP lists into confirmed live web targets.

**Source:** https://github.com/projectdiscovery/httpx
**Install:** `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` or `sudo apt install httpx-toolkit`

```bash
cat hosts.txt | httpx -silent
```

> [!note]
> httpx is almost always the middle step in recon pipelines: subfinder → httpx → nuclei/ffuf/dalfox. Use `-silent` for clean output to pipe. `-tech-detect` fingerprints the technology stack using Wappalyzer signatures. `-probe` vs `-silent` gives different output formats.

---

## Basic Probing

```bash
# Probe hosts from file
cat hosts.txt | httpx -silent

# Probe with status code and title
cat hosts.txt | httpx -status-code -title

# Single target
echo "http://target.com" | httpx -status-code -title -tech-detect

# From subfinder
subfinder -d example.com -silent | httpx -silent

# CIDR range
echo "10.10.10.0/24" | httpx -silent
```

---

## Information Extraction

```bash
# Common useful flags combined
cat hosts.txt | httpx \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -web-server \
  -silent

# Extract specific response fields
cat hosts.txt | httpx -status-code -title -follow-redirects -silent

# Response body word/line count
cat hosts.txt | httpx -wc -lc -silent

# Extract response headers
cat hosts.txt | httpx -include-response-header -silent

# Extract specific header value
cat hosts.txt | httpx -match-regex "X-Powered-By: PHP"

# IP address of host
cat hosts.txt | httpx -ip -silent
```

---

## Filtering

```bash
# Show only specific status codes
cat hosts.txt | httpx -mc 200,301,302 -silent

# Exclude status codes
cat hosts.txt | httpx -fc 404,403 -silent

# Filter by response size
cat hosts.txt | httpx -ml 1000   # min content length
cat hosts.txt | httpx -fl 200    # filter by content length (exclude)

# Filter by title
cat hosts.txt | httpx -match-string "admin" -silent

# Filter by technology
cat hosts.txt | httpx -tech-detect | grep -i "wordpress"

# Filter by response time
cat hosts.txt | httpx -rt -filter-response-time ">5s"
```

---

## Screenshots

```bash
# Take screenshots (requires chromium)
cat hosts.txt | httpx -screenshot -srd ./screenshots -silent
```

---

## Output Formats

```bash
# JSON output (best for scripting)
cat hosts.txt | httpx -json -o output.json

# CSV
cat hosts.txt | httpx -csv -o output.csv

# Plain (default)
cat hosts.txt | httpx -o output.txt -silent

# Custom output fields
cat hosts.txt | httpx -o output.txt \
  -status-code -title -server -tech-detect -silent
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-silent` | Print only results |
| `-status-code` / `-sc` | Show HTTP status code |
| `-title` | Show page title |
| `-tech-detect` / `-td` | Fingerprint tech stack |
| `-server` / `-web-server` | Show Server header |
| `-content-length` / `-cl` | Show content length |
| `-follow-redirects` / `-fr` | Follow redirects |
| `-mc` | Match status codes |
| `-fc` | Filter status codes |
| `-ml` | Min content length |
| `-ms` | Match response size |
| `-match-string` | Match string in response |
| `-match-regex` | Match regex in response |
| `-ip` | Show resolved IP |
| `-threads` / `-t` | Concurrent threads (default 50) |
| `-timeout` | Request timeout (default 5s) |
| `-rate-limit` | Requests per second |
| `-json` | JSON output |
| `-o` | Output file |
| `-screenshot` | Take screenshots |
| `-proxy` | HTTP proxy |

---

## Pipeline Workflows

```bash
# Subdomain → probe → screenshot
subfinder -d example.com -silent | \
  httpx -silent -status-code -title | \
  tee live_hosts.txt | \
  awk '{print $1}' | \
  aquatone -out ./screenshots

# Subdomain → probe → nuclei scan
subfinder -d example.com -silent | \
  httpx -silent | \
  nuclei -t technologies/ -severity medium,high,critical

# Probe + filter to interesting ports/tech
cat ips.txt | httpx -silent -status-code -title -tech-detect \
  | grep -v "404\|400" | tee interesting.txt

# Find login pages
cat hosts.txt | httpx -silent -match-string "login\|signin\|password"
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
