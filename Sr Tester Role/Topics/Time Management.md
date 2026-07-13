## 🛡️ Interview Notes: How Do You Prioritize a Pentest With Limited Time?

### What is Pentest Methodology?
- A **structured approach** to testing that ensures coverage, prioritization, and actionable results.  
- Senior pentesters are expected to **adapt based on available time** and **business risk**.  

---

### ⏱️ Engagement Length Scenarios

#### ⚡ 1–2 Day Pentest (Rapid Assessment)
- **Focus:** High-risk, quick-win vulnerabilities that show business impact fast.  
- **Approach:**
  - Rapid recon → identify exposed endpoints, login pages, APIs.  
  - Test for **critical vulns**: auth bypass, IDOR/BOLA, SQLi, file upload, SSRF.  
  - Validate only the most likely exploit paths.  
  - Deliver **evidence-driven findings** tied to sensitive data exposure.  
- **Goal:** Give stakeholders confidence whether “doors are wide open” without full coverage.

---

#### 📅 1 Week Pentest (Balanced Coverage)
- **Focus:** Balance between quick wins and deeper coverage.  
- **Approach:**
  - Recon + enumeration (map entire attack surface).  
  - Systematic testing of **OWASP Top 10** and **API Top 10** (auth flaws, access control, injection, XSS, CSRF).  
  - Look for **business logic flaws** (coupon abuse, privilege missteps).  
  - Begin chaining vulnerabilities → show realistic attack paths.  
  - Validate **defensive controls** (rate limiting, logging, MFA).  
- **Goal:** Provide both **technical coverage** and **business impact scenarios**.

---

#### 🏗️ 2 Week Pentest (Deep-Dive Engagement)
- **Focus:** Full coverage across application, infrastructure, and chaining attacks.  
- **Approach:**
  - Exhaustive recon (subdomain enumeration, endpoint fuzzing, tech stack profiling).  
  - Full vuln testing across web, API, thick client (if in scope).  
  - Advanced techniques:  
    - **Logic flaw exploitation** (workflow abuse, multi-step bypasses).  
    - **Privilege escalation** across roles.  
    - **Chaining** (e.g., SSRF → metadata → key theft → lateral movement).  
  - Local OS checks (Windows/Linux misconfigs, persistence vectors).  
  - API authentication deep-dive (OAuth, SAML, OIDC).  
  - AI/LLM testing if integrated (prompt injection, output handling, data leakage).  
  - Post-exploitation simulations: lateral movement, data exfil, persistence.  
- **Goal:** Deliver a **mature risk picture** with prioritized roadmap + mitigation strategy.

---

### 📊 Prioritization Rules (All Engagements)
- **Impact > Volume** → One PII-leaking IDOR > 20 missing headers.  
- **Business Context First** → Show “why it matters” in plain language.  
- **Exploitability** → Prioritize low-skill, high-impact flaws first.  
- **Chaining** → Highlight how small issues combine into big risks.  

---

### 💡 Interview Tip
- If asked: *“What changes in your approach depending on time?”* →  
  - 2 days = focus on **critical flaws** and **evidence of business risk**.  
  - 1 week = balanced **coverage of common vulns + business logic**.  
  - 2 weeks = **deep-dive**, chaining, OS-level checks, and advanced scenarios.  
- Phrase it as: *“I scale depth based on time, but I always deliver actionable business risk findings.”*  
