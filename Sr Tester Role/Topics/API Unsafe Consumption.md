## 🛡️ Interview Notes: What Is Unsafe Consumption of APIs?

### ❓ What Is Unsafe Consumption of APIs?
- **Unsafe Consumption of APIs** happens when applications **trust data from external or third-party APIs** without proper validation or security checks.  
- Attackers can exploit this trust to:  
  - 🔓 Inject malicious data (leading to injection or logic flaws)  
  - 🪤 Supply manipulated responses (SSRF, code execution, misrouting)  
  - 🧩 Abuse weak contracts (unexpected fields, schema drift)  
  - 🚨 Trigger application crashes or unexpected behaviors  

---

### 🧪 How to Detect and Exploit Unsafe API Consumption
- Identify where the target system consumes **external APIs** (payment gateways, geolocation, social logins, partner APIs).  
- Testing approaches:  
  - 🛠️ **Tamper with responses** if you control or intercept the third-party endpoint  
  - 🛠️ Replay unexpected fields or nested data structures  
  - 🛠️ Supply edge cases (very large responses, malformed JSON/XML)  
- Real-world attack scenarios:  
  - Fake identity providers in OAuth/OIDC flows  
  - Poisoned API responses causing privilege escalation  
  - Trusting unsigned data from 3rd parties (supply chain compromise)  

---

### 🛡️ How to Fix Unsafe API Consumption
- ✅ Validate and sanitize **all data** from external APIs before use  
- ✅ Enforce **strict schemas/contracts** (e.g., JSON schema validation)  
- ✅ Apply **timeouts, size limits, and rate limiting** for inbound responses  
- ✅ Use **mutual TLS, API keys, or signatures** to verify API sources  
- ✅ Avoid over-trusting 3rd party services → treat responses as **untrusted input**  
- ✅ Monitor for anomalies or unexpected behaviors in third-party integrations  

---
