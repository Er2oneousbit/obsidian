# HTTP / HTTPS

#HTTP #HTTPS #web #enumeration #webapp

## What is HTTP/HTTPS?
HyperText Transfer Protocol — application-layer protocol for web communication. HTTPS = HTTP over TLS/SSL. Every web app target starts with HTTP/HTTPS enumeration. Covers general web service recon — see Tomcat, IIS, Jenkins notes for app-specific attacks.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Common alternate: 8080, 8443, 8000, 8888, 8008

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Web/whatweb\|whatweb]] | Tech-stack / CMS / framework fingerprinting |
| [[Tools/File Transfer/cURL\|cURL]] | Headers, methods, cookies/auth, source grep, ad-hoc requests |
| [[Tools/Web/httpx\|httpx]] | Fast probing of many hosts/ports — status, title, tech, TLS |
| [[Tools/Scanning/nuclei\|nuclei]] | Template-based vuln/exposure scanning (CVEs, misconfigs, panels) |
| [[Tools/Web/Nikto\|Nikto]] | Web-server vuln/misconfig scanner |
| [[Tools/Scanning/gobuster\|gobuster]] | Directory/file/vhost/dns brute force |
| [[Tools/Scanning/ffuf\|ffuf]] | Directory, vhost, and parameter fuzzing |
| [[Tools/Scanning/feroxbuster\|feroxbuster]] | Recursive content discovery |
| [[Tools/Scanning/dirsearch\|dirsearch]] | Content discovery (extension-aware) |
| [[Tools/Scanning/wfuzz\|wfuzz]] | Vhost / parameter fuzzing |
| [[Tools/Web/git-dumper\|git-dumper]] | Reconstruct source from an exposed `.git/` directory |
| [[Tools/File Transfer/wget\|wget]] | Recursive mirroring of exposed content |
| [[Tools/Web/openssl\|openssl]] | Inspect TLS cert / negotiate manually |

---

## Enumeration

### Tech Fingerprinting

```bash
# whatweb — tech stack, CMS, framework fingerprinting
whatweb <target>
whatweb -v http://<target>
whatweb -a 3 http://<target>   # aggression level 3

# curl — headers
curl -I http://<target>
curl -ILk https://<target>    # follow redirects, ignore SSL errors
curl -v http://<target>       # verbose (shows request + response headers)

# nikto — web server scanner
nikto -h http://<target>
nikto -h https://<target> -ssl
nikto -h <target> -port 8080

# Check robots.txt and sitemap
curl http://<target>/robots.txt
curl http://<target>/sitemap.xml
```

### Directory / File Brute Force

```bash
# gobuster
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,html,txt,bak
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50

# ffuf
ffuf -u http://<target>/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403
ffuf -u http://<target>/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.old,.zip

# feroxbuster (recursive)
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
feroxbuster -u http://<target> -w wordlist.txt -x php,txt,html --depth 3

# dirsearch
dirsearch -u http://<target>
dirsearch -u http://<target> -e php,html,txt,bak
```

### Virtual Host / Subdomain Enumeration

```bash
# ffuf — vhost fuzzing
ffuf -u http://<target>/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_response_size>

# gobuster vhost
gobuster vhost -u http://<domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# gobuster dns
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# wfuzz
wfuzz -u http://<target>/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404 --hw <default_words>
```

### Parameter / API Fuzzing

```bash
# ffuf — GET param fuzzing
ffuf -u "http://<target>/page?FUZZ=value" -w params.txt
ffuf -u "http://<target>/page?param=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# ffuf — POST data fuzzing
ffuf -u http://<target>/login -X POST -d "username=FUZZ&password=pass" -w users.txt -H "Content-Type: application/x-www-form-urlencoded"
```

### Mass Probing & Templated Scanning

```bash
# httpx — probe a list of hosts/ports: live, status, title, tech, TLS SAN
cat hosts.txt | httpx -sc -title -td -tls-grab -ip
httpx -l hosts.txt -ports 80,443,8080,8443 -json -o httpx.json

# nuclei — run the template library against a target (CVEs, exposures, panels)
nuclei -u https://<target>
nuclei -l alive.txt -tags cve,exposure,misconfiguration -severity medium,high,critical
# Chain: httpx to find live hosts, pipe straight into nuclei
httpx -l hosts.txt -silent | nuclei -tags exposure,panel
```

---

## HTTP Methods & Verb Tampering

```bash
# Enumerate allowed methods
curl -X OPTIONS http://<target>/ -i 2>&1 | grep -i "^Allow:"
nmap -p 80,443 --script http-methods --script-args http-methods.test-all <target>

# TRACE enabled → Cross-Site Tracing (XST), can echo headers/cookies
curl -X TRACE http://<target>/ -i

# PUT/DELETE enabled → direct file write (see WebDAV/IIS notes for shell upload)
curl -X PUT http://<target>/test.txt --data "poc" -i

# Verb tampering for auth bypass — a control that only blocks GET/POST may let
# an arbitrary or HEAD method through to the protected handler
curl -X HEAD  http://<target>/admin -i        # HEAD reaches GET handler, ACL only checks GET
curl -X FOO   http://<target>/admin -i        # unknown verb → some stacks default-allow
curl -X POST  http://<target>/admin -i        # method the deny rule forgot

# Method-override headers (framework routers honour these even if the edge blocks the verb)
curl http://<target>/admin -H "X-HTTP-Method-Override: PUT" -i
curl http://<target>/admin -H "X-HTTP-Method: DELETE" -i
```

---

## Connect / Access

```bash
# curl — basic requests
curl http://<target>/
curl -L http://<target>/             # follow redirects
curl -k https://<target>/            # ignore SSL errors
curl -b "session=abc123" http://<target>/admin   # with cookie
curl -H "Authorization: Bearer <token>" http://<target>/api
curl -u user:pass http://<target>/   # basic auth
curl -d "param=value" -X POST http://<target>/login

# wget
wget http://<target>/file.txt
wget -r -np http://<target>/        # recursive download

# Check for backup / common files
for f in .git .svn .DS_Store .htpasswd .env web.config backup.zip admin.php phpinfo.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://<target>/$f)
  echo "$code $f"
done
```

---

## Common Findings / Quick Checks

```bash
# .git exposure
curl -s http://<target>/.git/HEAD
git-dumper http://<target>/.git /tmp/repo

# phpinfo exposure
curl http://<target>/phpinfo.php
curl http://<target>/info.php
curl http://<target>/test.php

# Default creds on login pages
# admin/admin, admin/password, admin/123456, root/root

# Source code review
curl -s http://<target>/ | grep -i "password\|secret\|token\|api_key\|user"

# Check HTTP methods
curl -X OPTIONS http://<target>/ -v 2>&1 | grep -i "Allow:"

# SSL cert info
openssl s_client -connect <target>:443 < /dev/null 2>/dev/null | openssl x509 -noout -text
```

---

## Wordlists (Key Locations)

| Purpose | Path |
|---|---|
| Common dirs | `/usr/share/wordlists/dirb/common.txt` |
| Medium dirs | `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Raft files | `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` |
| Subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| LFI paths | `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` |
| API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/objects.txt` |
| Passwords | `/usr/share/wordlists/rockyou.txt` |

---

## Dangerous Settings

| Issue | Risk |
|---|---|
| Directory listing enabled | File and source code exposure |
| `TRACE`/`PUT`/`DELETE` methods enabled | XST / arbitrary file write |
| Method-based ACL (blocks only GET/POST) | Verb-tampering auth bypass |
| `.git` / `.svn` exposed | Full source code access |
| Backup files (`.bak`, `.old`, `.zip`) | Source and credential exposure |
| Default credentials | Immediate admin access |
| HTTP not redirecting to HTTPS | Credential sniffing |
| `X-Frame-Options` missing | Clickjacking |
| `robots.txt` with sensitive paths | Reveals hidden endpoints |
| phpinfo.php exposed | Full PHP config disclosure |

---

## Quick Reference

| Goal | Command |
|---|---|
| Tech fingerprint | `whatweb -v http://host` |
| Headers | `curl -I http://host` |
| Dir brute (ffuf) | `ffuf -u http://host/FUZZ -w wordlist.txt` |
| Dir brute (gobuster) | `gobuster dir -u http://host -w wordlist.txt -x php,txt` |
| Vhost fuzz | `ffuf -u http://host/ -H "Host: FUZZ.domain" -w subdomains.txt -fs <size>` |
| Nikto scan | `nikto -h http://host` |
| Check .git | `curl http://host/.git/HEAD` |
| Templated scan | `nuclei -u https://host -tags cve,exposure` |
| Verb tamper bypass | `curl -X HEAD http://host/admin -i` |
| SSL cert | `openssl s_client -connect host:443 < /dev/null` |

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
