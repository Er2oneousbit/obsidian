## 🛡️ Interview Notes: What Is BOLA?

### ❓ What Is BOLA?
- **Broken Object Level Authorization (BOLA)** is the **#1 most common API vulnerability** (OWASP API Top 10).  
- It occurs when an API exposes object identifiers (IDs, keys, UUIDs) without properly enforcing **authorization checks**.  
- Often confused with IDOR — but BOLA is API-focused and typically appears in **REST and SOAP endpoints**, where direct access to object references is common.  
- Potential impacts:  
  - 🔓 Unauthorized access to sensitive data (user profiles, invoices, medical records)  
  - 📝 Modifying or deleting data belonging to other users  
  - 🚪 Lateral movement or privilege escalation through API misuse  

---

### 🧪 How to Detect and Exploit BOLA
- Identify API endpoints that handle object IDs:  
  - `GET /api/users/123`  
  - `POST /api/invoices/456/download`  

- Modify the object ID and observe:  
  - `GET /api/users/124` → another user’s data  
  - `POST /api/orders/999/cancel` → canceling someone else’s order  

- Common test cases:  
  - 🔁 Increment/decrement IDs  
  - 🔑 Swap UUIDs or usernames  
  - 🧪 Try unauthorized object access with different roles  

- Tools & techniques:  
  - 🛠️ Burp Repeater/Intruder to fuzz object IDs  
  - 🛠️ Burp extensions like **Autorize** or **AuthMatrix** to test access by role  
  - 🛠️ Compare responses between low-priv and high-priv accounts  

---

### 🛡️ How to Fix BOLA
- ✅ Enforce **authorization checks** on the server for *every request*, not just authentication.  
- ✅ Apply **object-level access control** consistently:  
  - User A cannot fetch/modify objects belonging to User B.  
- ✅ Avoid exposing predictable identifiers:  
  - Use non-sequential IDs (UUIDs, opaque references).  
  - But don’t rely on obscurity alone — checks must still be enforced.  
- ✅ Implement **RBAC/ABAC** (role-based or attribute-based access control).  
- ✅ Log and alert on suspicious sequential access attempts.  
- ✅ Include BOLA in automated tests and code reviews for APIs.  

---
