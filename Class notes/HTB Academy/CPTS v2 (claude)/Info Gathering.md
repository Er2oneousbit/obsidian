# Information Gathering & Reconnaissance

**Tags:** `#enumeration` `#informationgathering` `#OSINT` `#recon` `#DNS` `#subdomain`

---

## Methodology

```
Passive Recon (no direct target contact)
  → WHOIS / ASN / IP ranges
  → Certificate transparency
  → DNS passive (DNSDumpster, VirusTotal, Shodan, Censys)
  → Google/GitHub dorking
  → theHarvester / Recon-ng
  → Wayback Machine / cached pages
  → Cloud storage enumeration

Active Recon (direct contact with target)
  → DNS zone transfer attempt
  → Subdomain brute force
  → Port scanning / service fingerprinting
  → Tech stack fingerprinting
  → Virtual host enumeration
  → Directory / content discovery
  → Web crawling
```

> Always passive first — build target picture before making noise.

---

## Passive Recon

### WHOIS

```bash
whois example.com
whois 10.10.10.10

# Look for: registrant org/name/email, registrar, name servers, creation date
# Registrant email → search for other domains owned by same email
```

### ASN / IP Range Lookup

Finding all IP space owned by the target organization:

```bash
# Resolve to IP, then look up ASN
host example.com
whois -h whois.radb.net -- '-i origin AS12345'

# BGP / ASN lookup
# https://bgp.he.net/     ← search org name, find ASN + prefixes
# https://search.arin.net ← ARIN (North America)
# https://apps.db.ripe.net← RIPE (Europe)

# Resolve ASN to CIDR ranges
whois -h whois.radb.net -- '-i origin AS12345' | grep -E "^route"
```

### Certificate Transparency (crt.sh)

Certificates are publicly logged — reveals subdomains even for sites with no DNS records.

```bash
# Web
# https://crt.sh/?q=%.example.com

# CLI
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### DNS Passive Enumeration

```bash
# DNSDumpster — https://dnsdumpster.com/
# VirusTotal — https://www.virustotal.com/gui/domain/example.com/relations
# Censys — https://search.censys.io/
# Shodan — https://www.shodan.io/

# theHarvester — aggregate passive DNS, emails, IPs from multiple sources
theHarvester -d example.com -b all
theHarvester -d example.com -b google,bing,dnsdumpster,crtsh,virustotal
theHarvester -d example.com -b all -l 500 -f output.html

# Common sources: google, bing, dnsdumpster, crtsh, virustotal, shodan, anubis, otx
```

### Shodan

```bash
# CLI
shodan init <API_KEY>
shodan search "hostname:example.com"
shodan search "org:\"Example Corp\""
shodan host 10.10.10.10

# Web queries
# org:"Example Corp"
# hostname:example.com
# net:10.10.10.0/24
# ssl.cert.subject.cn:example.com
# product:"Apache httpd"
# http.title:"Login"
```

### Google Dorking

```bash
# Subdomain discovery
site:example.com -www

# Login / admin panels
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin OR inurl:portal)

# Exposed files
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:xlsx OR filetype:csv)
site:example.com filetype:sql
site:example.com (ext:conf OR ext:cnf OR ext:env OR ext:yml OR ext:yaml)
site:example.com filetype:log

# Config / sensitive files
site:example.com inurl:config.php
site:example.com inurl:wp-config
site:example.com inurl:backup
site:example.com inurl:".git"

# Combine operators
site:example.com intitle:"index of"
site:example.com intext:"password" filetype:txt
```

Full operator reference: [GHDB](https://www.exploit-db.com/google-hacking-database)

### GitHub Dorking

```bash
# Search on github.com
org:ExampleCorp password
org:ExampleCorp secret
org:ExampleCorp api_key
org:ExampleCorp "example.com" password
"example.com" token
"example.com" DB_PASSWORD

# Tools
git clone https://github.com/trufflesecurity/trufflehog
trufflehog github --org ExampleCorp

git clone https://github.com/zricethezav/gitleaks
gitleaks detect --source /path/to/repo
```

### Wayback Machine / Historical Pages

```bash
# Web: https://web.archive.org/

# gau — fetch all URLs from Wayback + OTX + Common Crawl
go install github.com/lc/gau/v2/cmd/gau@latest
gau example.com | tee gau_output.txt

# waybackurls
go install github.com/tomnomnom/waybackurls@latest
echo "example.com" | waybackurls | tee wayback_output.txt

# Look for: old endpoints, forgotten subdomains, leaked params, backup files
grep -E "\.php|\.asp|\.aspx|\.jsp" gau_output.txt
grep -E "backup|config|admin|test|dev" gau_output.txt
grep -E "\.sql|\.bak|\.zip|\.tar" gau_output.txt
```

### Cloud Storage Enumeration

```bash
# S3 buckets — common naming patterns
# https://buckets.grayhatwarfare.com/

# Manual checks
curl https://s3.amazonaws.com/example
curl https://example.s3.amazonaws.com
curl https://example-backup.s3.amazonaws.com
curl https://example-dev.s3.amazonaws.com

# s3scanner
pip3 install s3scanner
s3scanner scan --buckets-file buckets.txt

# Azure blobs
# https://example.blob.core.windows.net/
# Google Cloud
# https://storage.googleapis.com/example
```

---

## Active DNS Enumeration

### Zone Transfer

```bash
# Identify name servers first
dig NS example.com
nslookup -type=NS example.com

# Attempt zone transfer against each NS
dig axfr @ns1.example.com example.com
dig axfr @ns2.example.com example.com

# Also check: https://hackertarget.com/zone-transfer/
```

### Subdomain Brute Force

```bash
# gobuster
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 8.8.8.8 -t 50

# ffuf
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u https://FUZZ.example.com \
  -mc 200,301,302,403 -t 50

# dnsenum
dnsenum --dnsserver 8.8.8.8 --enum -p 0 -s 0 -o subdomains.txt \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt example.com

# amass (comprehensive — passive + active)
amass enum -d example.com
amass enum -active -d example.com -o amass_output.txt
amass enum -passive -d example.com

# subfinder (passive)
subfinder -d example.com -o subdomains.txt
subfinder -d example.com -all -recursive

# Resolve discovered subdomains
cat subdomains.txt | dnsx -silent -a -o resolved.txt
```

### DNS Manual Queries

```bash
# A record
dig example.com A
dig example.com A @8.8.8.8

# All records
dig example.com ANY

# MX
dig example.com MX

# TXT (SPF, DMARC, verification tokens)
dig example.com TXT
dig _dmarc.example.com TXT

# Reverse lookup
dig -x 10.10.10.10

# nslookup equivalent
nslookup example.com
nslookup -type=any example.com
nslookup -type=mx example.com
```

### IIS Version → Windows Version

| IIS Version | Windows Server |
|---|---|
| 6.0 | 2003 |
| 7.0 | 2008 |
| 7.5 | 2008 R2 |
| 8.0 | 2012 |
| 8.5 | 2012 R2 |
| 10.0 | 2016 / 2019 / 2022 |

---

## Tech Stack Fingerprinting

### HTTP Headers

```bash
curl -skI https://example.com
curl -sk -D - https://example.com -o /dev/null

# Look for: Server, X-Powered-By, X-AspNet-Version, Set-Cookie names, CF-Ray (Cloudflare)
```

### whatweb

```bash
whatweb https://example.com
whatweb -v https://example.com          # verbose
whatweb -a 3 https://example.com        # aggressive (makes more requests)
whatweb -a 3 --log-json output.json https://example.com
```

### wafw00f — WAF detection

```bash
wafw00f https://example.com
wafw00f -a https://example.com          # try all WAF fingerprints
```

### Wappalyzer

Browser extension or CLI:

```bash
npm install -g wappalyzer
wappalyzer https://example.com
```

### eyewitness — screenshot at scale

```bash
eyewitness --web -f urls.txt --timeout 10 -d screenshots/
eyewitness --web --single https://example.com
```

### aquatone — screenshot + report

```bash
cat subdomains.txt | aquatone -out aquatone_report/
```

### httpx — probe live hosts

```bash
# From subfinder/amass output
cat subdomains.txt | httpx -silent -title -status-code -tech-detect -o live_hosts.txt
cat resolved.txt | httpx -silent -title -status-code -follow-redirects
```

### Netcraft

Web: [https://sitereport.netcraft.com](https://sitereport.netcraft.com) — hosting history, tech stack, SSL, risk rating.

---

## Virtual Host Enumeration

```bash
# ffuf — fuzz Host header (vhost mode)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://10.10.10.10 \
  -H "Host: FUZZ.example.com" \
  -fs <default_response_size>

# gobuster vhost mode
gobuster vhost -u http://example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain \
  -t 50

# Manual curl test
curl -s -I http://10.10.10.10 -H "Host: dev.example.com"
curl -s http://10.10.10.10 -H "Host: admin.example.com" | grep -i "title\|<h1"

# Batch test from wordlist
while read vhost; do
  echo -n "[$vhost] "
  curl -sk -o /dev/null -w "%{http_code} %{size_download}\n" \
    http://10.10.10.10 -H "Host: ${vhost}.example.com"
done < /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Add discovered vhosts to `/etc/hosts`:

```bash
echo "10.10.10.10  dev.example.com admin.example.com" | sudo tee -a /etc/hosts
```

---

## Directory & Content Discovery

```bash
# ffuf — directory brute force
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u https://example.com/FUZZ \
  -mc 200,201,301,302,403 -t 50

# ffuf — file brute force
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -u https://example.com/FUZZ \
  -mc 200,201,301,302,403

# ffuf — extension fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -u https://example.com/FUZZ \
  -e .php,.asp,.aspx,.jsp,.txt,.bak,.zip,.conf,.log

# gobuster dir
gobuster dir -u https://example.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,txt,bak \
  -t 50 -o gobuster_output.txt

# feroxbuster — recursive
feroxbuster -u https://example.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 3 -x php,html,txt -t 50
```

### Always Check

```bash
curl -sk https://example.com/robots.txt
curl -sk https://example.com/sitemap.xml
curl -sk https://example.com/.well-known/security.txt
curl -sk https://example.com/.git/HEAD          # exposed git repo
curl -sk https://example.com/.env               # exposed env file
curl -sk https://example.com/crossdomain.xml
```

---

## Port Scanning

```bash
# Fast full TCP — find open ports first
nmap -p- --min-rate 5000 -T4 10.10.10.10 -oG allports.txt

# Targeted version + script scan on open ports
nmap -sV -sC -p 22,80,443,8080,8443 10.10.10.10 -oA targeted

# UDP (top 100)
nmap -sU --top-ports 100 10.10.10.10

# OS detection
nmap -O --osscan-guess 10.10.10.10

# Subnet sweep
nmap -sn 10.10.10.0/24

# All common scripts
nmap -sV -sC --script=default,vuln 10.10.10.10
```

### Service-Specific NSE Scripts

```bash
nmap --script http-title,http-headers,http-methods 10.10.10.10 -p 80,443,8080,8443
nmap --script ssl-cert,ssl-enum-ciphers 10.10.10.10 -p 443,8443
nmap --script smb-enum-shares,smb-os-discovery 10.10.10.10 -p 445
nmap --script snmp-info -sU -p 161 10.10.10.10
nmap --script ftp-anon,ftp-bounce 10.10.10.10 -p 21
nmap --script ssh-auth-methods,ssh-hostkey 10.10.10.10 -p 22
nmap --script banner 10.10.10.10
```

---

## Web Crawling

```bash
# ZAP — spider via CLI
zap-cli spider https://example.com

# hakrawler
echo "https://example.com" | hakrawler -depth 3 -plain | tee crawl_output.txt

# gospider
gospider -s https://example.com -o output/ -c 10 -d 3

# katana
katana -u https://example.com -d 3 -o katana_output.txt

# Extract unique URLs from crawl
cat crawl_output.txt | grep "example.com" | sort -u > unique_urls.txt
```

---

## Email & OSINT

```bash
# theHarvester — emails, names, IPs, subdomains
theHarvester -d example.com -b google,bing,linkedin,hunter -l 500

# LinkedIn — employee enumeration
# https://www.linkedin.com/search/results/people/?keywords=example+corp
# Cross-reference with username-anarchy for AD usernames

# Hunter.io — https://hunter.io/domain-search
# Phonebook.cz — https://phonebook.cz/
# Dehashed — https://dehashed.com/ (leaked credentials)
```

---

## Automation Frameworks

### Recon-ng

```bash
recon-ng
> marketplace install all
> workspaces create example_com
> modules load recon/domains-hosts/bing_domain_web
> options set SOURCE example.com
> run
> modules load recon/hosts-hosts/resolve
> run
> show hosts
```

### SpiderFoot

```bash
# Web UI
spiderfoot -l 0.0.0.0:5001
# Browse to http://localhost:5001 → New Scan → enter domain

# CLI
spiderfoot -s example.com -m sfp_bing,sfp_dns,sfp_shodan -o output.csv
```

### amass (full passive + active)

```bash
# Passive only (no direct contact)
amass enum -passive -d example.com -o passive_subs.txt

# Active (brute + permutation + scraping)
amass enum -active -d example.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o active_subs.txt

# Intel — find related domains from ASN/org
amass intel -org "Example Corp" -max-dns-queries 500
amass intel -asn 12345
```

---

## Vulnerability Research

```bash
# searchsploit — local ExploitDB copy
searchsploit apache 2.4
searchsploit wordpress 5.8
searchsploit -x 12345          # examine exploit
searchsploit -m 12345          # copy to current dir

# Online
# https://www.exploit-db.com/
# https://nvd.nist.gov/vuln/search
# https://www.rapid7.com/db/
# https://packetstormsecurity.com/

# Metasploit search
msfconsole -q -x "search type:exploit apache; exit"
```

---

## Quick Reference — Key Sites

| Purpose | URL |
|---|---|
| Certificate transparency | https://crt.sh |
| Passive DNS / subdomain | https://dnsdumpster.com |
| Passive DNS | https://www.virustotal.com |
| Internet scanning | https://www.shodan.io |
| Internet scanning | https://search.censys.io |
| ASN / BGP lookup | https://bgp.he.net |
| Tech fingerprint | https://sitereport.netcraft.com |
| Historical pages | https://web.archive.org |
| Cloud storage | https://buckets.grayhatwarfare.com |
| Google dorks DB | https://www.exploit-db.com/google-hacking-database |
| Default creds | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Leaked creds | https://dehashed.com |
| Email harvesting | https://hunter.io |
| Domain intel | https://domain.glass |

---

## Checklist

```
Passive
[ ] WHOIS — registrant, nameservers, dates
[ ] ASN / IP ranges — bgp.he.net, ARIN/RIPE
[ ] crt.sh — certificate transparency subdomain harvest
[ ] theHarvester — emails, subdomains, IPs
[ ] Google dorks — exposed files, panels, config, backups
[ ] GitHub dorking — leaked secrets, tokens, credentials
[ ] Shodan/Censys — open services, SSL certs, banners
[ ] Wayback Machine / gau — old endpoints, forgotten apps
[ ] Cloud storage — S3, Azure blob, GCS buckets
[ ] LinkedIn/OSINT — employee names → username list

Active
[ ] Zone transfer attempt against all NS records
[ ] Subdomain brute force (gobuster/ffuf/amass/subfinder)
[ ] Port scan — full TCP then targeted version/script
[ ] UDP scan (top 100)
[ ] Tech fingerprint — whatweb, wafw00f, HTTP headers
[ ] Virtual host enumeration — ffuf Host header fuzz
[ ] Directory brute force — ffuf/gobuster/feroxbuster
[ ] robots.txt, sitemap.xml, .well-known, .git, .env
[ ] Web crawl — hakrawler/katana/gospider
[ ] Screenshot all discovered hosts — eyewitness/aquatone
[ ] Vuln research — searchsploit, ExploitDB, Rapid7 on identified versions
```
