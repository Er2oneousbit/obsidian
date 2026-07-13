## 🛡️ Interview Notes: What Is Improper Inventory Management?

### ❓ What Is Improper Inventory Management?
- **Improper Inventory Management** occurs when an organization fails to properly track, secure, and retire **all API endpoints**.  
- Attackers can discover **shadow APIs** (undocumented) or **deprecated versions** that are less secure.  
- Potential impacts:  
  - 🔓 Accessing older APIs without modern security controls (auth, rate limiting)  
  - 🛠️ Exploiting unpatched vulnerabilities in forgotten endpoints  
  - 🚪 Pivoting from “internal-only” APIs exposed accidentally  

---

### 🧪 How to Detect and Exploit Improper Inventory Management
- Map all exposed API endpoints:  
  - Review Swagger/OpenAPI, GraphQL introspection, WSDLs.  
  - Use fuzzing tools (`/v1/`, `/v2/`, `/beta/`, `/internal/`).  
  - Check subdomains (`api.dev.target.com`, `staging.target.com`).  

- Common attacker approaches:  
  - 🔍 **Version hunting** → try `/api/v1/` vs `/api/v2/`  
  - 🧩 **Shadow APIs** → endpoints used by mobile apps or thick clients but not documented  
  - 📂 **Unpublished routes** → discovered through JavaScript files, error messages, or Burp passive scans  

- Indicators of exposure:  
  - APIs not listed in inventory but publicly reachable  
  - Older endpoints lack controls like auth, rate limiting, or logging  
  - Inconsistent schemas across versions  

---

### 🛡️ How to Fix Improper Inventory Management
- ✅ Maintain a **complete inventory** of all APIs (public, private, partner, internal).  
- ✅ Use **API gateways** to enforce uniform security controls.  
- ✅ Retire and decommission old endpoints properly (return `410 Gone`).  
- ✅ Regularly test and audit for shadow/deprecated APIs.  
- ✅ Monitor for unexpected traffic to unadvertised endpoints.  
- ✅ Integrate API discovery into CI/CD pipelines (scan code + configs).  

---
