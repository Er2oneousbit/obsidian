## 🎯 Senior Pentester Interview Q&A Bank

---

### 🔒 Technical Web/API Scenarios

**Q1. What’s your process when testing an undocumented API?**

- **Recon:** Enumerate endpoints (Burp logging, fuzzing with ffuf/wfuzz/gobuster, hidden Swagger, guessing naming conventions).  
- **Exploration:** Build an ad-hoc API map by analyzing requests/responses.  
- **Security checks:** Authentication, authorization, role-based access, rate limits.  
- **Prioritization:** Focus on sensitive data and state-changing endpoints.  

💡 *Senior flex:* Show that you’d **document as you go** so the client ends up with a useful API map too.

---

**Q2. You find an IDOR letting you pull invoices. How do you demonstrate impact safely?**

- Pull only **1–2 safe records** (your account or redacted test data).  
- Capture **screenshot of request/response**.  
- Stop — don’t dump all data.  
- Report impact as: *“This could expose all customer financial records, violating PCI/PII obligations.”*  

💡 *Senior flex:* Show you know **where to stop** — safe proof, not database breach.

---

**Q3. A dev says: “JWTs are signed, so they’re secure.” How do you respond?**

- **Clarify:** Signing ≠ encryption. Sensitive claims still readable.  
- **Risks:** Weak secrets, `alg=none`, key confusion attacks.  
- **Demonstrate:** Example of forging admin token with cracked secret.  
- **Business risk:** “If attackers can forge admin tokens, they effectively become app admins.”  

---

**Q4. How do you test for API rate limiting issues?**

- Use Burp Intruder/ffuf to fuzz requests → watch for throttling.  
- Test differences between **unauthenticated vs authenticated** users.  
- Check for **account lockouts, resource exhaustion**.  
- Risk framing: *“Without rate limiting, brute force and scraping attacks become trivial.”*  

---

### 📱 Mobile “Just Enough” Knowledge

**Q5. You’re not a mobile specialist. What common mobile risks do you still check for?**

- Insecure local storage (tokens/credentials in cleartext).  
- Hardcoded secrets in APK/IPA.  
- Weak TLS/SSL (no cert pinning, easy to bypass).  
- Underlying API vulnerabilities (same checks as web).  

💡 *Senior flex:* Say you’d escalate deep mobile RE to a mobile specialist, but you **know the API layer is fair game**.

---

### 🧠 Senior Mindset / Leadership

**Q6. A junior tester reports XSS but can’t exploit it. How do you coach them?**

- Ask what payloads they tried → teach context-specific payloads.  
- Walk them through a simple PoC (alert box).  
- Explain **business impact**: session hijack, credential theft.  
- Guide them on **how to document properly**.  

💡 *Senior flex:* Position yourself as a **multiplier** — helping juniors become independent.

---

**Q7. How do you scope an API pentest with vague requirements?**

- Clarify goals: protecting PII? testing auth? resilience?  
- Ask for docs/Swagger if possible.  
- Define boundaries (which APIs, what data).  
- Align on constraints: time, accounts, sensitive data safety.  

💡 *Senior flex:* Show that **early scoping prevents drama** at readout time.

---

**Q8. One week to test a massive web app. How do you prioritize?**

- Recon first: estimate app size/scope.  
- Focus high-value: auth, payment, sensitive data.  
- Light automation to maximize coverage.  
- Ensure regulated data flows (PCI/PII) get priority.  

💡 *Senior flex:* “I balance **depth vs breadth** so we leave no critical gap even if time is short.”

---


**Q9. Tell me about a time you found a high-risk vuln.**

- Choose a memorable “war story” (XSS → session hijack, SQLi → RCE, IDOR → mass data exposure).  
- Walk through discovery → exploit → safe proof.  
- End with how you **communicated risk** and **client response**.  

💡 *Senior flex:* Always highlight both **technical impact** and **communication success**.


**Q10. What separates a good report from a great one?**

- **Good:** Accurate technical detail.  
- **Great:** Tailored exec summary, clear repro steps, strong business framing, prioritized remediation.  
- **Bonus:** Links to references and compliance context (PCI/GDPR/HIPAA).  

💡 *Senior flex:* Great reports **educate** as well as inform — clients reuse them as training docs.



---

### 🌐 Advanced Web/API Scenarios

**Q11. How do you test an API with GraphQL endpoints differently from REST?**
- GraphQL allows **single endpoint queries** with complex depth.
- Test for:
  - Introspection exposure
  - Query depth/complexity → DoS
  - Broken auth at field level
- Risk framing: *“Attackers can pull entire datasets in one query if depth/limits aren’t enforced.”*

---

**Q12. What’s your approach if you suspect business logic flaws?**
- Understand **intended workflow** (e.g., order process, role assignment).
- Try **out-of-order actions** (apply coupon after payment).
- Test for **role bypass** (user→admin escalation).
- Senior flex: tie failures back to *financial loss or abuse at scale*.

---

### 💻 System / OS Scenarios

**Q13. You find a command injection vuln. How do you safely demonstrate it?**
- Start with benign commands: `id`, `whoami`, `echo test`.
- Avoid destructive payloads.
- Show impact with minimal harm.
- Report: *“This gives attacker full OS control; demoed with user ID leak.”*

---

**Q14. How do you test a thick client without reverse engineering?**
- Intercept traffic (Burp, Fiddler, Proxifier).
- Look for:
  - Cleartext credentials
  - Hidden API endpoints
  - Weak encryption/obfuscation
- Frame as: *“We can still test its attack surface via its traffic even without reversing the binary.”*

---

### 🤖 AI/LLM Scenarios

**Q15. An LLM app uses your prompt as input for a backend API call. What’s the risk?**
- Prompt injection → force LLM to reveal API keys, query internals, or craft harmful requests.
- This can become **indirect injection** against downstream systems.
- Senior flex: position as “new flavor of injection” requiring **input/output filtering**.

---

**Q16. How would you explain AI ‘token’ to a non-technical stakeholder?**
- A token = smallest chunk of text the model processes.
- Analogy: *“Tokens are like puzzle pieces; the AI builds meaning from them.”*
- Risk: prompt length = cost and performance; not a “security token.”

---

### 🧑‍💼 Senior Mindset / Leadership

**Q17. A client insists a vuln is low risk, but you know it’s exploitable. How do you handle it?**
- Show a **safe PoC**.
- Translate impact into **business terms**.
- Offer **mitigation options** (not just “fix it”).
- Goal: educate, not argue.

---

**Q18. How do you balance breadth vs depth in an assessment?**
- Breadth ensures coverage → no blind spots.
- Depth finds critical vulns → impactful proof.
- Senior flex: say you **prioritize based on business risk + time constraints.**

---

**Q19. What’s your approach if you find nothing critical in an engagement?**
- Deliver value anyway:
  - Highlight strengths
  - Recommend hardening (headers, monitoring, logging)
  - Provide **assurance** with documented testing
- Senior flex: *“No highs isn’t a failure — it’s assurance, but I’ll always suggest defense-in-depth.”*

---

**Q20. What makes you a *senior* pentester vs a strong mid-level?**
- Technical depth across web/API/OS/AI.
- Strong reporting + client communication.
- Mentorship of juniors.
- Ability to scope, prioritize, and deliver under pressure.
- Business awareness: risk framing beyond CVEs.
