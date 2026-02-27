## 🏴‍☠️ Pillaging

**Tags:** `#Pillaging` `#PostExploitation` `#PrivilegeEscalation` `#RedTeam`

Pillaging refers to the process of searching a compromised system for sensitive data, credentials, configuration files, and other valuable artifacts that can aid in further exploitation or lateral movement.

---

### 🔍 What to Look For

|**Target**|**Description**|
|---|---|
|**Credentials**|Plaintext passwords, hashes, tokens, SSH keys|
|**Configuration Files**|May contain hardcoded secrets or environment variables|
|**Databases**|Connection strings, credentials, sensitive data|
|**Source Code**|API keys, secrets, logic flaws|
|**Logs**|May reveal usernames, passwords, tokens, or internal paths|
|**Backups**|Often unprotected and contain sensitive data|
|**Emails**|Internal communications, credentials, or sensitive attachments|

---

### 🐧 Linux Pillaging Targets

- `/etc/` — System-wide config files (e.g., `passwd`, `shadow`, `crontab`)
- `/home/` — User directories (e.g., `.bash_history`, `.ssh/`, `.gnupg/`)
- `/var/log/` — System and application logs
- `/var/www/` — Web server files (e.g., config, source code)
- `/opt/` — Custom or third-party applications
- `/tmp/` — Temporary files, sometimes used for staging

---

### 🪟 Windows Pillaging Targets

- `C:\Users\` — User profiles (e.g., `Desktop`, `Documents`, `Downloads`)
- `C:\ProgramData\` — Shared application data
- `C:\Windows\System32\config\` — Registry hives (e.g., `SAM`, `SYSTEM`, `SECURITY`)
- `C:\inetpub\wwwroot\` — Default IIS web root
- `C:\Users\<user>\AppData\` — Application data (e.g., tokens, credentials)
- `C:\Users\<user>\Recent\` — Recently accessed files
- `C:\Users\<user>\NTUSER.DAT` — User-specific registry settings

#### 🔑 Credential Locations

- `SAM` + `SYSTEM` hives — Can be dumped and cracked offline
- `AppData\Roaming\Microsoft\Credentials\` — Windows Credential Manager
- `AppData\Local\Google\Chrome\User Data\Default\Login Data` — Chrome saved passwords
- `AppData\Roaming\FileZilla\recentservers.xml` — FTP credentials
- `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` — PowerShell history

---

### 🧪 Useful Commands

#### Linux

```bash
grep -Ri 'password\|secret\|token\|key' /home /var /opt /etc 2>/dev/null
find / -type f -name "*.conf" -o -name "*.env" 2>/dev/null
find / -name "id_rsa" -o -name "authorized_keys" 2>/dev/null
printenv
```

#### Windows (PowerShell)

```powershell
Get-ChildItem -Recurse -Include *.config,*.xml,*.ini,*.env -Path C:\Users\ -ErrorAction SilentlyContinue
Select-String -Path C:\Users\*\Documents\* -Pattern "password|secret|token|key"
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

---

### 🧠 Tips for Effective Pillaging

- Prioritize **user-owned** files and **developer artifacts**
- Look for **misconfigured permissions** (e.g., world-readable secrets)
- Use **automated tools** like:
    - `LinPEAS`
    - `WinPEAS`
    - `Leslie`
- Check for **mounted shares** or **network drives**
- Don’t overlook **browser history**, **saved passwords**, or **clipboard contents**

---
