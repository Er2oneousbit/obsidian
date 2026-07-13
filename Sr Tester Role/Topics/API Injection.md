## 🛡️ Interview Notes: What Is API Injection?

### What is API Injection?
- **API Injection** vulnerabilities occur when untrusted input is inserted into API calls without proper validation or sanitization.  
- Similar to SQLi or command injection, but in an **API context**:
  - GraphQL queries/mutations
  - JSON/XML input
  - NoSQL queries
- Impacts include:
  - **Data exfiltration** (query manipulation)
  - **Privilege escalation**
  - **RCE** (in some cases via underlying libraries)
  - **Denial of Service (DoS)** through malicious payloads

---

### 🧪 How to Detect/Exploit API Injection
- Look for API endpoints that accept **user-controlled input**:
  - JSON bodies, GraphQL queries, XML payloads
- Test with injection payloads (defanged examples):

  **SQL-like injection in JSON**  
  `{ "user": "admin' OR '1'='1" }`

  **GraphQL injection**  
  `{ user(id:"1"){name role} }` → Try altering: `{ user(id:"1 OR 1=1"){name role} }`

  **NoSQL injection**  
  `{ "username": { "$ne": null }, "password": { "$ne": null } }`

  **Command/Code injection via API**  
  `{ "filename": "report; whoami" }`

- Indicators:
  - Unexpected error messages (stack traces, DB errors)
  - Overly verbose responses
  - Ability to retrieve unauthorized data

- Tools:
  - **Burp Suite**, **Postman**, **Insomnia**
  - Fuzzers like **ffuf**, **intruder**, or custom scripts

---

### 🛡️ How to Fix API Injection
- **Input validation & sanitization**:
  - Enforce schemas (JSON Schema, XML Schema) and reject unknown fields
  - Whitelist expected values and data types
- **Use parameterization**:
  - Prepared statements for DB queries
  - ORM frameworks where possible
- **Apply least privilege**:
  - API service accounts should not have excessive DB or OS rights
- **Error handling**:
  - Don’t expose stack traces or query errors in responses
- **Security testing**:
  - Include injection tests in CI/CD pipelines
  - Use SAST/DAST tools to catch common injection flaws

---

### 💡 Interview Tip
- One-liner: **“API injection is just SQLi/command injection in JSON, GraphQL, or XML clothing.”**  
- Show that you understand it’s the *same family of vulnerability* applied to modern API data formats.
