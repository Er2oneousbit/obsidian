## 🛡️ Interview Notes: What Is SSRF?

### What is SSRF?

- **Server-Side Request Forgery (SSRF)** is a vulnerability that allows an attacker to make the server send HTTP requests **on its own behalf**, often to internal systems.
- It exploits the **trust the server has in internal or protected resources**.
- Common use cases include:
    - Accessing internal admin panels or metadata services (e.g., AWS `169.254.169.254`)
    - Port scanning internal networks
    - Bypassing IP-based access controls
    - Chaining into other vulnerabilities (e.g., RCE, XSS)

---

### 🧪 How to Detect/Exploit SSRF

- Look for endpoints that **fetch URLs or external resources**:
    - Image fetchers, PDF generators, webhook testers, etc.
- Try injecting URLs like:
    - `http://127.0.0.1:80`
    - `http://localhost/admin`
    - `http://169.254.169.254/latest/meta-data/`
- Use **Burp Collaborator**, **requestbin**, or your own server (e.g., `eb-offsec.com`) to detect outbound requests.
- Test for **URL parsing tricks**:
    - DNS rebinding: `http://attacker.com@internal`
    - Encoded IPs: `http://2130706433` (decimal for 127.0.0.1)
    - Redirect chains: `http://yourdomain.com/redirect?url=http://internal`

---

### 🛡️ How to Fix SSRF

- **Whitelist** allowed domains/IPs instead of blacklisting.
- Use a **URL parser** that enforces strict validation (e.g., no redirects, no IP bypasses).
- Block access to internal IP ranges (e.g., `127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`, etc.).
- Disable unnecessary URL-fetching features in the application.
- Use **network segmentation** to isolate services that make outbound requests.
- Monitor for unusual outbound traffic patterns.