## 🛡️ Interview Notes: How Do You Report Pentest Findings?

### ❓ What Is Pentest Reporting?
- Reporting is the **primary deliverable** of a pentest.  
- A strong report communicates to **different audiences**:  
  - 📊 Executives → “Why this matters” in plain English  
  - 🛠️ Developers → “How to reproduce and fix” in technical detail  
  - 🧑‍💻 Security teams → “How to prioritize” with severity ratings  

---

### 📝 Reporting Cheat Sheet

#### 1. Executive Summary (CTO / CISO / PM)
- 1 paragraph explaining:  
  - Vulnerability name in plain English  
  - What attacker can do (no jargon)  
  - What it means for the business  
  - Severity rating  

**Example:**  
> Our testing identified an *Insecure Direct Object Reference (IDOR)* in the billing API. An attacker can retrieve invoices belonging to other customers by modifying a request parameter. This could expose financial data across the customer base, creating regulatory and reputational risk. Severity: **High**.  

---

#### 2. Technical Details (for Developers/Engineers)
- **Title:** Vulnerability + Location  
- **Description:** Technical explanation of flaw  
- **Steps to Reproduce:** Numbered and copy-paste ready  
- **Evidence:** Screenshots, Burp requests/responses, console output (defanged)  
- **Impact:** Technical + real-world damage  

**Example:**  
**Title:** IDOR in `/api/invoices/{invoice_id}`  
**Description:** API does not enforce ownership validation. Any authenticated user can modify the `invoice_id` to access another customer’s invoice.  
**Steps to Reproduce:**  
1. Log in as User A and capture: `GET /api/invoices/12345`  
2. Change `12345` to another ID.  
3. Response shows another customer’s invoice.  

---

#### 3. Risk Rating
- Use consistent framework (CVSS, OWASP Risk Rating).  
- **Formula:** Likelihood + Impact → Overall Risk  

**Example:**  
- Likelihood: High (easy to exploit, no auth required)  
- Impact: High (financial data exposure)  
- **Risk: High**  

---

#### 4. Remediation Guidance
- Give **specific, actionable advice**, not generic fixes.  

**Bad:** “Validate input.”  
**Good:**  
- Implement ownership checks in the API controller  
- Use indirect references (e.g., UUIDs instead of sequential IDs)  
- Add tests to enforce access controls  

---

#### 5. Senior-Level Touches
- Prioritization: “This finding should be remediated before others due to its high risk.”  
- References: OWASP docs, vendor best practices, code samples  
- Context: Tie finding to compliance requirements (PCI, HIPAA, GDPR)  
