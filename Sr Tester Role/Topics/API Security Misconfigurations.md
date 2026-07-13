## 🛡️ Interview Notes: What Are API Security Misconfigurations?

### What are API Security Misconfigurations?
- **API Security Misconfigurations** occur when APIs are deployed with **insecure settings, defaults, or missing controls**.  
- They are one of the most common and dangerous issues because they often expose sensitive endpoints or allow unintended access.  
- Common impacts:
  - Unauthorized data access
  - Information disclosure
  - Easier exploitation of other vulnerabilities

---

### 🧪 How to Detect/Exploit API Security Misconfigurations
- Look for **common mistakes** in API setups:
  - **Verbose error messages** (stack traces, DB errors, debug info)
  - **Lack of TLS/HTTPS enforcement**
  - **Missing security headers** (CORS misconfigurations, CSP, etc.)
  - **Directory listings or exposed files** (e.g., `.env`, `.git/`)
  - **Unrestricted CORS**:
    - `Access-Control-Allow-Origin: *`
  - **Improper caching of sensitive responses**
  - **Default or test accounts** left enabled
  - **Unpatched API frameworks/libraries**

- Example findings:
  - API response shows `X-Powered-By: Express` → version disclosure  
  - `/api/docs` or `/swagger` endpoint publicly exposed with no auth  
  - Misconfigured CORS:
    ```
    Access-Control-Allow-Origin: *
    Access-Control-Allow-Credentials: true
    ```
    → Allows credential theft via malicious websites

- Tools:
  - **Burp Suite**, **Postman**
  - **Nmap** with service detection
  - **Nikto**, **Nuclei templates**
  - Manual review of response headers and error handling

---

### 🛡️ How to Fix API Security Misconfigurations
- Follow **secure deployment practices**:
  - Disable directory listings, stack traces, and verbose error messages
  - Enforce HTTPS/TLS across all endpoints
  - Apply strict **CORS rules**:
    - Only allow trusted origins
    - Avoid `Access-Control-Allow-Origin: *` with credentials
- Remove default/test accounts and unused endpoints
- Apply **security headers**:
  - CSP, X-Frame-Options, X-Content-Type-Options
- Patch frameworks and libraries regularly
- Perform **hardening** and **baseline reviews**:
  - Automate with CIS Benchmarks or Nuclei scans
- Include misconfig checks in **CI/CD pipelines**

---

### 💡 Interview Tip
- One-liner: **“Misconfigurations are low-hanging fruit — attackers love them because they’re easy, and defenders hate them because they’re preventable.”**
