## 🛡️ Interview Notes: What Are Common Linux OS Vulnerabilities?

### What Are Linux OS Vulnerabilities?
- Weaknesses in **Linux configurations, binaries, or file permissions** that attackers exploit for **privilege escalation, persistence, or lateral movement**.  
- Common in post-exploitation scenarios after initial foothold.  

---

### 🧪 Common Linux OS Attacks

#### 🔧 SUID / SGID Abuse
- SUID (Set User ID) binaries run with the file owner’s privileges (often root).  
- If misconfigured, attacker can escalate by exploiting the binary.  
- Example:  
`find / -perm -4000 -type f 2>/dev/null`
→ Look for exploitable SUID binaries (e.g., `vim`, `nmap`, `bash`).  

---

#### 🔧 Cron Job Abuse
- Misconfigured cron jobs run with elevated privileges.  
- If script or binary in job is writable by attacker → privilege escalation.  

---

#### 🔧 PATH Hijacking
- Scripts executed with `sudo` may call system binaries without absolute paths.  
- Attacker creates a malicious binary with same name earlier in `$PATH`.  
- Example: `cp` replaced with attacker’s payload.  

---

#### 🔧 World-Writable Files & Directories
- Sensitive files or executables writable by low-privilege users.  
- Example: `/etc/shadow` or `/etc/passwd` misconfigured → attacker can add root account.  

---

#### 🔧 Weak SSH Configurations
- Password authentication allowed with weak creds.  
- Private keys stored insecurely (`id_rsa` with loose permissions).  
- Authorized_keys file writable by attacker.  

---

#### 🔧 Kernel Exploits
- Outdated kernels vulnerable to known exploits (e.g., Dirty COW, Dirty Pipe).  
- Often used when no other escalation paths exist.  

---

#### 🔧 Persistence Techniques
- Adding SSH keys to `~/.ssh/authorized_keys`.  
- Creating malicious cron jobs.  
- Editing `/etc/passwd` to add backdoor accounts.  
- LD_PRELOAD or shared object injection.  

---

### 🛡️ How to Defend Against Linux OS Attacks
- Regularly audit for **SUID/SGID binaries**.  
- Restrict cron job permissions and validate scripts.  
- Use absolute paths in scripts.  
- Apply least privilege on files and directories.  
- Patch kernels and software frequently.  
- Use **SSH key-based auth** with strict permissions.  
- Monitor logs for unusual cron, SSH, or user account changes.  

---

### 💡 Interview Tip
- If asked: “How do attackers escalate on Linux?” → Mention **SUID binaries, cron jobs, PATH hijacking, weak permissions, kernel exploits**.  
- If asked: “How do defenders stop this?” → Emphasize **hardening, patching, monitoring, least privilege**.  
