## 🛡️ Interview Notes: What Is Excessive Data Exposure?

### ❓ What Is Excessive Data Exposure?
- **Excessive Data Exposure (EDE)** occurs when an API returns more data than necessary and **trusts the client to filter** what is shown to the user.  
- Attackers can inspect raw API responses to extract sensitive information that the UI never displays.  
- Potential impacts:  
  - 🔓 Disclosure of PII (emails, SSNs, medical records)  
  - 💳 Financial leakage (balances, credit limits, hidden fields)  
  - 🚪 Enumeration of hidden fields for privilege escalation  

---

### 🧪 How to Detect and Exploit Excessive Data Exposure
- Inspect API responses for **extra fields** not used in the frontend.  
  - Example (defanged):  
    ```
    GET /api/user/123
    {
      "username": "jdoe",
      "email": "jdoe@example.com",
      "role": "admin",
      "ssn": "123-45-6789",
      "creditLimit": 10000
    }
    ```
    UI might only show `username` and `email`, but sensitive fields are exposed.  

- Common checks:  
  - Compare **frontend UI vs. raw API responses**.  
  - Test role differences (low-priv vs. high-priv users).  
  - Check GraphQL introspection / OpenAPI specs for fields not shown in the app.  

- Tools & techniques:  
  - 🛠️ Burp Suite (compare UI vs. API traffic)  
  - 🛠️ GraphQL introspection queries  
  - 🛠️ Swagger/OpenAPI documentation review  

---

### 🛡️ How to Fix Excessive Data Exposure
- ✅ Perform **response-level filtering on the server**, not the client.  
- ✅ Return **only the fields needed** for each endpoint/function.  
- ✅ Apply **object property-level authorization checks** (tie into Mass Assignment defense).  
- ✅ Regularly review API contracts (Swagger/OpenAPI) for sensitive fields.  
- ✅ Test APIs with different roles to ensure least-privilege data access.  
- ✅ Monitor logs for unusual data harvesting patterns.  

---
