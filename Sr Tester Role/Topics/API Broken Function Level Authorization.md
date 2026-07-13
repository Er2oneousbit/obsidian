## 🛡️ Interview Notes: What Is BFLA?

### ❓ What Is BFLA?
- **Broken Function Level Authorization (BFLA)** occurs when an API endpoint fails to properly enforce **authorization checks on functions or actions**.  
- While BOLA focuses on *object-level access* (resources like `/user/123`), BFLA abuses *functional access* (endpoints only intended for privileged users).  
- Potential impacts:  
  - 🔓 Regular users invoking **admin-only endpoints**  
  - 🛠️ Executing functions outside a user’s role (e.g., approving payments, managing accounts)  
  - 🚪 Escalation from normal user → privileged roles  

---

### 🧪 How to Detect and Exploit BFLA
- Look for API endpoints grouped by roles:  
  - `/api/admin/*`  
  - `/api/moderator/*`  
  - `/api/internal/*`  

- Try invoking these endpoints with lower-privilege accounts:  
  - `POST /api/admin/createUser`  
  - `DELETE /api/admin/deleteInvoice?id=456`  

- Common scenarios:  
  - 🔑 User account can access staff/admin functions  
  - 🧩 Functionality hidden in UI but exposed in API  
  - 🔁 Vertical privilege escalation through undocumented endpoints  

- Tools & techniques:  
  - 🛠️ Burp Suite + **AuthMatrix** to map permissions across roles  
  - 🛠️ Compare responses between roles (low vs. high privilege)  
  - 🛠️ Manual fuzzing of hidden or undocumented routes  

---

### 🛡️ How to Fix BFLA
- ✅ Enforce **role-based access control (RBAC)** or **attribute-based access control (ABAC)** at the API layer.  
- ✅ Never rely solely on the **frontend/UI** to hide privileged functions.  
- ✅ Apply **least privilege principles** — each role should only have required functions.  
- ✅ Implement centralized authorization checks instead of scattered role checks.  
- ✅ Regularly test and audit role-based access mappings.  
- ✅ Monitor logs for suspicious access attempts to privileged endpoints.  

---
