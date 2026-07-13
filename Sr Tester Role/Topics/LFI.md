## 🛡️ Interview Notes: What Is LFI?

### ❓ What Is LFI?
- **Local File Inclusion (LFI)** is a vulnerability that allows a web application to **load and display files from the local filesystem**.  
- It happens when user input is used to construct file paths **without proper sanitization or validation**.  
- Common impacts:  
  - 📖 Reading sensitive files (e.g., `/etc/passwd`, application logs, source code)  
  - 🗺️ Gaining insight into server structure  
  - 💀 Chaining into **RCE** via log poisoning, PHP wrappers, or upload directories  

---

### 🧪 How to Detect and Exploit LFI
- Look for parameters like:  
  - `?page=home`  
  - `?file=report.pdf`  
  - `?template=about`  

- Try injecting file paths (defanged examples):  
  - Unix: `../../../../etc/passwd`  
  - Windows: `..\\..\\..\\windows\\win.ini`  

- Evasion tricks:  
  - 🔹 Null byte injection (older PHP): `../../etc/passwd%00`  
  - 🔹 Double/URL encoding: `%252e%252e%252fetc%252fpasswd`  

- PHP wrappers:  
  - `php://filter/convert.base64-encode/resource=index.php` → read source code  
  - `data://` or `expect://` (older PHP, possible RCE vectors)  

- Log poisoning chain:  
  - Inject PHP code into logs (e.g., User-Agent or Referer header)  
  - Then include the log file via LFI → code execution  

---

### 🛡️ How to Fix LFI
- ✅ Avoid dynamic file inclusion based on user input  
- ✅ Use whitelists for allowed files or templates  
- ✅ Sanitize input: remove `../`, null bytes, and traversal patterns  
- ✅ Use functions like `realpath()` to validate file paths  
- ✅ Apply strict file permissions to prevent access to sensitive files  
- ✅ Disable dangerous PHP wrappers if not needed  
- ✅ Monitor logs for suspicious file access attempts  

---
