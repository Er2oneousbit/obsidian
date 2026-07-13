## 🛡️ Interview Notes: What Are Common Windows OS Vulnerabilities?

### What Are Windows OS Vulnerabilities?
- Weaknesses in **Windows configuration or binaries** that attackers exploit for **privilege escalation, persistence, or lateral movement**.  
- Often abused post-exploitation once an initial foothold is gained.  

---

### 🧪 Common Windows OS Attacks

#### 🔧 Unquoted Service Paths
- Services with paths containing spaces and **no quotation marks** can allow attackers to place malicious executables in earlier path locations.  
- Example:  
`C:\Program Files\Vulnerable App\Service.exe`
→ Attacker drops `C:\Program.exe` → executed at service startup.  

---

#### 🔧 DLL Hijacking (Binary Planting)
- Applications load DLLs from predictable locations.  
- Attacker places a **malicious DLL** in the search path → app executes it.  

---

#### 🔧 Weak Service Permissions
- Services configured with **write permissions** allow attackers to modify binary path or parameters.  
- Can replace service executable with malicious one → runs with SYSTEM privileges.  

---

#### 🔧 AlwaysInstallElevated
- Windows Installer policy misconfig.  
- If enabled, attacker can craft a malicious MSI file → installs with elevated privileges.  

---

#### 🔧 Registry Persistence
- Attackers add keys in:  
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- `HKLM\...\Run`  
- Ensures malware runs at user/system startup.  

---

#### 🔧 Scheduled Tasks / Services
- Create or modify scheduled tasks to re-execute payloads at boot or intervals.  
- Abuse service creation if attacker has rights.  

---

#### 🔧 User Account Control (UAC) Bypass
- Abuse trusted binaries or misconfigurations to escalate privileges without triggering UAC prompts.  

---

### 🛡️ How to Defend Against Windows OS Attacks
- Quote all service paths.  
- Use **service hardening** and apply least privilege to service accounts.  
- Restrict file/folder and registry permissions.  
- Monitor for unusual service or task creation.  
- Disable or limit use of **AlwaysInstallElevated**.  
- Enable logging (Sysmon, Event Logging) for persistence indicators.  
- Apply regular patching to OS and third-party apps.  

---

### 💡 Interview Tip
- If asked: “How do attackers escalate on Windows?” → Mention **service misconfigs, DLL hijacking, UAC bypass, AlwaysInstallElevated, registry keys, scheduled tasks**.  
- If asked: “How do defenders stop this?” → Stress **hardening, monitoring, least privilege, patching**.  
