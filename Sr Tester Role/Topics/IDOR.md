## 🛡️ Interview Notes: What Is IDOR?

### ❓ What Is IDOR?
- **Insecure Direct Object Reference (IDOR)** is an access control vulnerability where an attacker gains unauthorized access to resources **by modifying a direct reference** such as a user ID, file name, or record number.  
- It happens when the application **fails to enforce authorization checks** on user-supplied input.  
- Common impacts:  
  - 👁️ Viewing other users’ data  
  - ✍️ Modifying another user’s records  
  - 📂 Downloading unauthorized files  
  - 🔄 Performing actions on behalf of other users (e.g., password reset, order cancellation)  

---

### 🧪 How to Detect and Exploit IDOR
- Look for endpoints that reference objects by ID:  
  - `GET /user/123/profile`  
  - `POST /invoice/download?id=456`  
- Modify the reference and observe responses:  
  - 🔢 Increment/decrement values (`123 → 124`)  
  - 🔡 Try predictable patterns (UUIDs, usernames)  
- Key checks:  
  - **Horizontal privilege escalation** → accessing peer data  
  - **Vertical privilege escalation** → accessing admin-only data  
- Tools:  
  - 🛠️ Burp Suite Repeater or Intruder for ID fuzzing  
  - 🛠️ Extensions like Autorize or AuthMatrix for role testing  

---

### 🛡️ How to Fix IDOR
- ✅ Enforce **server-side authorization checks** on every request  
  - Validate the user’s permissions before granting access  
- ✅ Avoid exposing direct object references  
  - Use indirect identifiers (e.g., hashed IDs, opaque UUIDs) **with access control**  
- ✅ Implement **RBAC** (role-based access control) or **ABAC** (attribute-based access control)  
- ✅ Log and monitor suspicious patterns (e.g., sequential ID enumeration)  
- ✅ Add IDOR scenarios into automated tests and security reviews  

---
