## 🛡️ Interview Notes: What Is XSS?

### ❓ What Is XSS?
- **Cross-Site Scripting (XSS)** is a web vulnerability that allows attackers to inject **malicious JavaScript** into trusted websites.  
- It occurs when user input isn’t properly sanitized or escaped, allowing script execution in a victim’s browser.  
- Potential impacts:  
  - 🍪 Stealing cookies or session tokens  
  - 🔑 Capturing credentials or personal info  
  - 🕹️ Performing actions as the victim (CSRF-like abuse)  
  - 📡 Exfiltrating sensitive data to attacker-controlled servers  

---

### 🔍 Types of XSS
1. **💾 Stored XSS**  
   - Payload is stored in the site’s backend (e.g., database, logs).  
   - Executes whenever users load the affected page.  

2. **🔗 Reflected XSS**  
   - Payload is embedded in a URL (e.g., query string).  
   - Reflected by the server in the response.  
   - Often delivered via crafted links.  

3. **🖥️ DOM-Based XSS**  
   - Payload is processed entirely in the browser (JavaScript/DOM).  
   - No server-side involvement.  
   - Triggered by links, hash fragments, or client-side input handling.  

---

### 🧪 How to Detect and Exploit XSS
- Insert special characters to test sanitization:  
  - `< > " ' / \ & %`  
  - Use polyglot payloads to bypass filters.  

- HTML/JS rendering tests (defanged examples):  
  - `&lt;h1&gt;HTML render test&lt;/h1&gt;`  
  - `&lt;scr&lt;ipt&gt;alert('XSS')&lt;/scr&lt;ipt&gt;`  

- Attribute/event handler tests:  
  - `&lt;img src=x onerror=alert(1)&gt;`  
  - `&lt;svg onload=alert(1)&gt;`  

- Filter bypass tricks:  
  - Break up keywords → `&lt;scri&lt;pt&gt;pt&gt;`  

- Confirm exfiltration:  
  - Use a webhook or listener (e.g., requestbin, Burp Collaborator, custom server)  
  - Catch outbound requests triggered by injected payloads  

---

### 🛡️ How to Fix XSS
- ✅ **Sanitize user input** → escape dangerous characters (`<`, `>`, `'`, `"`, `/`, `&`)  
- ✅ Use safe rendering methods → `textContent` or `innerText` instead of `innerHTML`  
- ✅ Apply **Content Security Policy (CSP)** → restrict inline scripts and external JS sources  
- ✅ Use **HttpOnly cookies** → prevent session theft via JavaScript  
- ✅ Validate and sanitize on both **client** and **server side** for defense in depth  

---
