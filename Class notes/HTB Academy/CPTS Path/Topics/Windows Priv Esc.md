
# 🛡️ Windows Privilege Escalation

**Tags:** `#Privesc` `#PrivilegeEscalation` `#Windows`

---

## 📚 References & Learning Resources


---

## 🧰 Tools for Enumeration & Exploitation
- 🔗 [[Potato]]  
- 🔗 [AS-REP Roasting Attack Explained - MITRE ATT&CK T1558.004](https://www.picussecurity.com/resource/blog/as-rep-roasting-attack-explained-mitre-attack-t1558.004)  
- 🔗 [Windows Commands | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

| Tool | Description |
|------|-------------|
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | C# tool for local privilege escalation checks. [GitHub](https://github.com/GhostPack/Seatbelt) |
| [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) | Script for finding privilege escalation paths. [GitHub](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), [Docs](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) |
| [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) | PowerShell script for identifying and exploiting misconfigurations. [Raw Script](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) |
| [SharpUp](https://github.com/GhostPack/SharpUp) | C# version of PowerUp. [GitHub](https://github.com/GhostPack/SharpUp) |
| [JAWS](https://github.com/411Hall/JAWS) | PowerShell 2.0 script for privilege escalation enumeration. [GitHub](https://github.com/411Hall/JAWS) |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher) | Extracts saved session info (PuTTY, WinSCP, RDP, etc.). [GitHub](https://github.com/Arvanaghi/SessionGopher) |
| [Watson](https://github.com/rasta-mouse/Watson) | .NET tool to find missing KBs and suggest exploits. [GitHub](https://github.com/rasta-mouse/Watson) |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Retrieves stored passwords from various sources. [GitHub](https://github.com/AlessandroZ/LaZagne) |
| [WES-NG](https://github.com/bitsadmin/wesng) | Suggests exploits based on `systeminfo` output. [GitHub](https://github.com/bitsadmin/wesng) |
| [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) | Includes tools like [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice). |
| [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) | Dumps hashes from remote machines without agents. [GitHub](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Finds sensitive data (creds, configs) in large environments. [GitHub](https://github.com/SnaffCon/Snaffler) |

---

## 🔍 Manual Checks & Commands

### 🗝️ General Notes

- Goal: Gain access to accounts or systems with higher privileges.
- Common writable location: `C:\Windows\Temp`

### 🌐 Network & Routing
- `route print` display the routing table
- `arp -a` display arp table
- `ipconfig /all` display NIC status and info as well as DNS servers

### 🔒 AppLocker

- `Get-AppLockerPolicy - local` list rules from local system
- `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections` expand all applied rules
- `Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone` who is allowed to run **cmd.exe**

### 🛡️ Windows Defender

```powershell
Get-MpComputerStatus

# View Defender exclusions
$preferences = Get-MpPreference
$preferences.ExclusionPath
$preferences.ExclusionExtension
$preferences.ExclusionProcess
```

### 👥 User & Group Enumeration

```bash
query user                           # Active sessions
whoami /priv | findstr Enabled       # Current privileges
whoami /groups                       # Group memberships
net user                             # List local users
net localgroup                       # List local groups
```

### ⚙️ Processes & Applications

```bash
tasklist /svc       # Running processes with services
wmic product get name
# or
Get-WmiObject -Class Win32_Product | Select Name, Version

netstat -ano        # Network connections with PIDs
```

### 🖥️ System Info

```bash
systeminfo          # OS version and details
wmic qfe            # Installed hotfixes
# or
Get-Hotfix
```

### 📂 Environment Variables

```bash
set                 # View environment variables (including PATH)
```
