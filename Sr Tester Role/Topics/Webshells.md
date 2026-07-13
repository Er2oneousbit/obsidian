## 🛡️ Interview Notes: What Are Web Shells?

### What is a Web Shell?

- A **web shell** is a script uploaded to a web server that provides **remote command execution** or file access via a web interface.
- It’s often used post-exploitation to:
    - Maintain access
    - Pivot within the network
    - Execute commands or upload/download files
- Web shells can be written in any server-side language:
    - PHP, ASP, JSP, Python, Node.js, etc.

---

### 🧪 How to Detect/Use Web Shells

#### 🔍 Common Upload Vectors

- File upload functionality without proper validation
- LFI/RFI vulnerabilities
- Misconfigured CMS plugins or themes

#### 🧬 Common Web Shell Examples (Defanged)

**PHP (e.g., phpbash, b374k, or minimal shell):**

```
&lt;?php system($_GET['cmd']); ?&gt;
```


Show more lines

**ASP:**

```
&lt;% eval request("cmd") %&gt;
```


**JSP:**

```
&lt;% Runtime.getRuntime().exec(request.getParameter("cmd")); %&gt;
```


#### 🧰 Tools

- **Burp Suite** for upload testing
- **Weevely**, **China Chopper**, **reGeorg**, or **custom shells**
- **Web shell detection** via YARA rules, AV, or EDR logs

---

### 🛡️ How to Prevent Web Shells

- **Sanitize and validate file uploads**:
    - Restrict file types and MIME types
    - Rename files and store outside the web root
- Disable execution in upload directories:
    - Use `.htaccess` or web server config
- Monitor for:
    - Unexpected file changes
    - Suspicious HTTP requests (e.g., `cmd=`, `eval=`)
- Use **WAFs**, **EDR**, and **file integrity monitoring**.
- Apply **least privilege** to the web server and application users.