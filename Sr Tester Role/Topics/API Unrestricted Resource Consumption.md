## 🛡️ Interview Notes: What Is Unrestricted Resource Consumption?

### ❓ What Is Unrestricted Resource Consumption?
- **Unrestricted Resource Consumption** (a.k.a. API DoS) happens when an API does not properly limit or control resource use, allowing attackers to **exhaust system resources**.  
- Common attack vectors:  
  - ⏳ Sending massive requests or nested queries (CPU/memory exhaustion)  
  - 📦 Uploading huge files or many small files (disk exhaustion)  
  - 🔁 Unlimited API calls (rate limiting not enforced)  
  - 📊 Expensive queries (deep object expansions, GraphQL batching)  
- Potential impacts:  
  - 🚨 Denial of Service (DoS) for legitimate users  
  - 💸 Increased cloud/infra costs (bandwidth, compute)  
  - 🔓 Brute-force or credential stuffing via unchecked login attempts  

---

### 🧪 How to Detect and Exploit Unrestricted Resource Consumption
- Look for API endpoints that allow **unbounded input**:  
  - Pagination without limits → `?limit=100000`  
  - File upload endpoints without size checks  
  - Expensive filters or regex in search queries  

- Attack strategies:  
  - 🔁 Send parallel requests at high volume to test rate limits  
  - 📂 Upload oversized files or zip bombs  
  - 🧩 GraphQL → use batching or recursion to force heavy computation  

- Indicators:  
  - Slow responses under load  
  - Errors like `500` or `502` under large requests  
  - No throttling or account lockouts for repeated login attempts  

- Tools:  
  - 🛠️ Burp Intruder / Turbo Intruder for high-volume requests  
  - 🛠️ OWASP Amass / custom fuzzers for enumeration load tests  

---

### 🛡️ How to Fix Unrestricted Resource Consumption
- ✅ Enforce **rate limiting** and request quotas per user/IP/token  
- ✅ Set **pagination limits** (e.g., `limit=100 max`)  
- ✅ Validate file uploads (size, type, number of files)  
- ✅ Implement **timeouts** and **query cost analysis** for complex requests (esp. GraphQL)  
- ✅ Add **CAPTCHAs** or proof-of-work for high-risk endpoints (e.g., login, search)  
- ✅ Monitor logs for unusual traffic spikes or request patterns  

---
