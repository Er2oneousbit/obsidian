## 🛡️ Interview Notes: What Is Mass Assignment?

### ❓ What Is Mass Assignment?
- **Mass Assignment** (also called **Object Property Level Authorization flaws**) happens when an API automatically binds user input to data objects **without filtering allowed fields**.  
- Attackers can supply extra parameters to modify sensitive fields that should not be user-controllable.  
- Potential impacts:  
  - 🔓 Privilege escalation (set `isAdmin=true`)  
  - 💳 Financial abuse (set `price=0` or `balance=9999`)  
  - 🚪 Workflow bypass (change `status=pending` → `status=approved`)  

---

### 🧪 How to Detect and Exploit Mass Assignment
- Look at JSON/XML request bodies for updatable objects:  
  - Example (defanged):  
    ```
    POST /api/user/update
    {
      "username": "user1",
      "email": "test@example.com"
    }
    ```

- Add extra fields that shouldn’t normally be exposed:  
  - `{"username":"user1","role":"admin"}`  
  - `{"product":"123","price":"0.01"}`  
  - `{"status":"approved"}`  

- Indicators of vulnerability:  
  - API accepts and applies unexpected parameters  
  - Sensitive properties exposed in responses or API docs (Swagger, GraphQL introspection, WSDL)  

- Tools & techniques:  
  - 🛠️ Burp Repeater for manual fuzzing of hidden fields  
  - 🛠️ Compare client requests vs. server responses for unused fields  
  - 🛠️ Use wordlists of common object properties (`isAdmin`, `role`, `balance`, `status`)  

---

### 🛡️ How to Fix Mass Assignment
- ✅ Implement **allow-lists** (define which fields can be updated by which roles).  
- ✅ Avoid automatically binding entire request bodies to backend objects.  
- ✅ Enforce **property-level authorization checks**:  
  - Example: only admins can update `role` or `status`.  
- ✅ Hide sensitive properties from API docs and responses.  
- ✅ Regularly test APIs for hidden/unintended fields.  

---
