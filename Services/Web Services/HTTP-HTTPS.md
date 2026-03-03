#HTTP #HTTPS #web #enumeration #webapp

## What is HTTP/HTTPS?
HyperText Transfer Protocol — application-layer protocol for web communication. HTTPS = HTTP over TLS/SSL. Every web app target starts with HTTP/HTTPS enumeration. Covers general web service recon — see Tomcat, IIS, Jenkins notes for app-specific attacks.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Common alternate: 8080, 8443, 8000, 8888, 8008

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

## Dangerous Settings / Misconfigurations

| Issue | Risk |
|---|---|
| Directory listing enabled | File and source code exposure |
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
| SSL cert | `openssl s_client -connect host:443 < /dev/null` |
