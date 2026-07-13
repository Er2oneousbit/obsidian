## 🛡️ Interview Notes: What Is a File Upload Vulnerability?

### ❓ What Is a File Upload Vulnerability?
- A **file upload vulnerability** occurs when an application improperly handles **user-supplied files**, allowing attackers to upload **malicious content**.  
- Impact can include:  
  - 💀 Remote Code Execution (RCE) → uploading a defanged webshell  
  - ⚡ Stored XSS → uploading a malicious `.svg` or `.html` file  
  - 🧨 Denial of Service → uploading large files or zip bombs  
  - 🔓 Sensitive Data Exposure → overwriting config or log files  

---

### 🧪 How to Detect and Exploit File Upload Vulnerabilities
- Upload a file and intercept the request with **Burp Suite**.  
- Try bypassing restrictions:  
  - 🌀 **Extension filtering bypass** → `shell[.]php[.]jpg`, `shell[.]php%00[.]jpg`  
  - 🌀 **Content-Type spoofing** → send `Content-Type: image/jpeg` for a `.php` file  
  - 🌀 **Double extensions** → `shell[.]php[.]png`  
  - 🌀 **Case manipulation** → `shell[.]PhP`  

- Common malicious uploads (defanged):  
  - Webshell snippet: `&lt;?php echo shell_exec($_GET['cmd']); ?&gt;`  
  - Polyglot files → valid image + PHP code  

- Locate where the file is stored:  
  - Look for predictable paths or upload responses like:  
    ```
    hxxp://target[.]com/uploads/shell[.]php
    ```  

- If direct execution is blocked, try chaining:  
  - 🔗 **Upload + LFI** → upload file, then include it via Local File Inclusion  
  - 🎨 **Stored XSS** → malicious `.svg` or `.html` upload  
  - 📄 **Document payloads** → macro-enabled `.docm` or `.xlsm`  

---

### 🛡️ How to Fix File Upload Vulnerabilities
- ✅ Validate file type both client-side and server-side:
  - Check MIME type, extension, and file signature (magic bytes)  
- ✅ Rename uploaded files and store **outside the web root**  
- ✅ Restrict dangerous file types (`.php`, `.jsp`, `.exe`, etc.)  
- ✅ Force download via **Content-Disposition headers**  
- ✅ Apply access controls on uploaded files  
- ✅ Sanitize file names and paths (no traversal `../`)  
- ✅ Monitor upload directories for suspicious activity  

---
