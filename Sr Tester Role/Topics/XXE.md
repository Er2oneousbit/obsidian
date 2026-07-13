## 🛡️ Interview Notes: What Is XXE?

### ❓ What Is XXE?
- **XML External Entity (XXE)** is a vulnerability that occurs when an XML parser processes **external entities** defined inside XML input.  
- It can allow attackers to:  
  - 📖 Read local files (e.g., `/etc/passwd`)  
  - 🌐 Perform SSRF (Server-Side Request Forgery)  
  - 🗺️ Enumerate internal systems  
  - 💀 In some cases, achieve **RCE** (e.g., via deserialization or file upload vectors)  

---

### 🧪 How to Detect and Exploit XXE
- Look for XML-based inputs:  
  - SOAP APIs, SAML assertions, SVG uploads, XML file uploads  

- Classic malicious DTD injection (defanged example):  
  ```xml
  &lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;  
  &lt;root&gt;&amp;xxe;&lt;/root&gt;
