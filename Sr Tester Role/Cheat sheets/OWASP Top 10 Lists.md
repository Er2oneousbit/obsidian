# 🛡️ OWASP Top 10 Cheat Sheet (Web, API, AI/LLM)

---

## 🌐 Web Applications (OWASP Top 10 – 2021)
1. **Broken Access Control** – Missing/weak authz → IDOR, privilege escalation.  
2. **Cryptographic Failures** – Weak crypto → plaintext data leaks.  
3. **Injection** – SQLi, NoSQLi, command injection via unsanitized input.  
4. **Insecure Design** – Logic flaws, no rate limits, poor workflows.  
5. **Security Misconfiguration** – Default creds, bad CORS, verbose errors.  
6. **Vulnerable & Outdated Components** – Unpatched libs → known exploits.  
7. **Identification & Auth Failures** – Broken login/MFA/session mgmt.  
8. **Software & Data Integrity Failures** – Unsafe updates, deserialization, supply chain.  
9. **Logging & Monitoring Failures** – Gaps in detection/response.  
10. **Server-Side Request Forgery (SSRF)** – Abusing server to pivot into internal/cloud.  

---

## 🔌 APIs (OWASP Top 10 – 2023)
1. **Broken Object Level Authorization (BOLA)** – Horizontal data access (classic IDOR).  
2. **Broken Auth** – Weak or missing login, MFA, or tokens.  
3. **Broken Object Property Level Authorization (BOPLA)** – Unauthorized property manipulation.  
4. **Unrestricted Resource Consumption** – DoS via large/complex requests.  
5. **Broken Function Level Authorization (BFLA)** – Privilege escalation via function calls.  
6. **Unrestricted Access to Sensitive Business Flows** – Abusing workflows (e.g., checkout, money transfer).  
7. **Server-Side Request Forgery (SSRF)** – API as proxy into internal/cloud.  
8. **Security Misconfiguration** – Exposed debug endpoints, weak CORS.  
9. **Improper Inventory Management** – Shadow/deprecated APIs, version sprawl.  
10. **Unsafe Consumption of APIs** – Trusting third-party APIs without validation.  

---

## 🤖 LLMs / AI Systems (OWASP Top 10 – 2024 Draft)
1. **Prompt Injection** – Malicious instructions override intended logic.  
2. **Insecure Output Handling** – Model output executed directly (RCE, XSS, SQLi).  
3. **Training Data Poisoning** – Backdoored or biased training sets.  
4. **Model Denial of Service** – Resource exhaustion (long prompts, recursion).  
5. **Supply Chain Vulnerabilities** – Untrusted models, weights, datasets.  
6. **Sensitive Information Disclosure** – Model leaks secrets/tokens.  
7. **Insecure Plugin / Extension Design** – Over-privileged model integrations.  
8. **Excessive Agency** – Model given dangerous real-world powers (e.g., shell, transactions).  
9. **Overreliance / Inadequate Monitoring** – Blind trust in model outputs, no human in loop.  
10. **Model Theft / Data Extraction** – Model weights or training data exfiltrated via queries.  

---

# 💡 Interview Flex
- **Web Top 10** → traditional appsec (breadth).  
- **API Top 10** → access control + data-centric (depth).  
- **AI/LLM Top 10** → emerging risks (novel attack surface).  
