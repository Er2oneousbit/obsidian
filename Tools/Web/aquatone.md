# aquatone

**Tags:** `#aquatone` `#webenumeration` `#screenshots` `#recon` `#web`

Visual web reconnaissance tool. Takes a list of hosts/URLs, visits each, takes a screenshot, and produces an HTML report with a thumbnail gallery plus HTTP response headers. Ideal for quickly triaging large subdomain lists to find interesting targets without manually visiting hundreds of URLs.

**Source:** https://github.com/shelld3v/aquatone (active fork) / https://github.com/michenriksen/aquatone (original)
**Install:**
```bash
sudo apt install golang chromium-driver
go install github.com/michenriksen/aquatone@latest
export PATH="$PATH":"$HOME/go/bin"
```

```bash
cat subdomains.txt | aquatone -out ./aquatone
```

> [!note]
> Input can be plain hostnames, URLs, or Nmap XML output. Pipe from subfinder, amass, or any host list. The HTML report (`aquatone_report.html`) is the primary output — open in browser. `-screenshot-timeout` often needs increasing for slow targets.

---

## Basic Usage

```bash
# Pipe subdomain list
cat subdomains.txt | aquatone -out ./aquatone_output

# With screenshot timeout (ms) — increase for slow targets
cat subdomains.txt | aquatone -out ./aquatone_output -screenshot-timeout 2000

# Pipe from subfinder
subfinder -d example.com -silent | aquatone -out ./aquatone_output

# Pipe from amass
amass enum -passive -d example.com | aquatone -out ./aquatone_output
```

---

## Nmap XML Input

```bash
# Run nmap, output XML
nmap -sV -p 80,443,8080,8443 10.10.10.0/24 -oX nmap.xml

# Feed XML to aquatone (discovers web ports automatically)
cat nmap.xml | aquatone -nmap -out ./aquatone_output
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-out <dir>` | Output directory |
| `-screenshot-timeout <ms>` | Screenshot timeout (default: 1000ms) |
| `-http-timeout <ms>` | HTTP request timeout (default: 3000ms) |
| `-threads <n>` | Concurrent workers (default: 6) |
| `-ports <list>` | `small`, `medium`, `large`, `xlarge`, or `80,443,8080` |
| `-proxy <url>` | HTTP proxy |
| `-nmap` | Parse stdin as Nmap XML |
| `-silent` | Suppress output |

---

## Port Profiles

```bash
# small  = 80, 443
# medium = 80, 443, 8000, 8080, 8443
# large  = adds common alt-HTTP ports
# xlarge = everything

cat hosts.txt | aquatone -ports medium -out ./output
cat hosts.txt | aquatone -ports 80,443,8080,8443,8888 -out ./output
```

---

## Output Files

```
aquatone_output/
├── aquatone_report.html     ← main output — open this in browser
├── aquatone_urls.txt        ← all URLs that responded
├── aquatone_session.json    ← session data
├── screenshots/             ← PNG screenshots per URL
└── headers/                 ← response headers per URL
```

---

## Workflow

```bash
# 1. Enumerate subdomains
subfinder -d example.com -silent > subs.txt
amass enum -passive -d example.com >> subs.txt
sort -u subs.txt > subs_unique.txt

# 2. Probe + screenshot
cat subs_unique.txt | aquatone -ports medium -screenshot-timeout 3000 -out ./aquatone

# 3. Open report
firefox ./aquatone/aquatone_report.html

# 4. Review — look for:
# - Login panels / admin interfaces
# - Default pages (Apache/nginx/IIS defaults = not hardened)
# - Unusual apps (internal tools, dev instances)
# - Error pages leaking stack traces / versions
```


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] (CPTS v2).

---

*Created: 2026-03-13*
*Updated: 2026-07-31*
*Model: claude-opus-5*
