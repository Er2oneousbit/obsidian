## 🛡️ Interview Notes: Non-Technical Skills for Senior Pentesters

### Why Non-Technical Skills Matter
- A Senior Pentester is not just a **vulnerability finder**, but also a **translator** between technical details and business risk.  
- Expected to **mentor junior testers**, **handle exec conversations**, and **push for remediation** effectively.  

---

### 🎤 Communication Skills

- **Executive Communication**
  - Speak in **business terms**: “data exposure → regulatory fines” not “SQLi in parameter.”  
  - Keep executive summaries to **2–3 sentences**.  
  - Always link findings to **impact on customer trust, revenue, or compliance**.  

- **Developer Communication**
  - Be **actionable**: give exact remediation guidance (code samples, config fixes).  
  - Avoid blame — focus on “how to fix” not “why it’s broken.”  
  - Show willingness to **walk through fixes** if needed.  

- **Closing Meetings**
  - Acknowledge strengths as well as weaknesses.  
  - Emphasize “partnership” not “gotcha.”  

---

### 👥 Leadership & Mentorship

- **Mentoring Juniors**
  - Teach **prioritization**: “an IDOR leaking PII matters more than 10 missing headers.”  
  - Pair on tests: let them run scans, then show them how to turn noise into signal.  
  - Encourage **report-writing practice** early — it’s the hardest skill to grow.  

- **Leading Engagements**
  - Set expectations with clients up front (scope, timelines, deliverables).  
  - Delegate tasks (e.g., have juniors run recon while you focus on logic flaws).  
  - Keep the **big picture** in mind — tie findings back to business risk.  

---

### 📊 Prioritization & Risk Context

- **Risk Language**
  - Use consistent severity frameworks (CVSS, OWASP risk rating).  
  - Always explain **Likelihood + Impact = Risk**.  
  - Show how **low-level issues can chain** into critical impact.  

- **Time-Constrained Testing**
  - Be ready to answer: *“If you only had 2 days, what would you test?”*  
  - Show methodology scaling: quick wins first → deeper coverage if time allows.  

---

### 🧑‍💼 Handling Pushback

- **When Devs say “This isn’t important”**
  - Reframe in business context: *“If an attacker can enumerate all invoices, that’s PCI data exposure.”*  
- **When Execs say “We can’t fix that right now”**
  - Suggest mitigations: *“Rate limiting buys time while you refactor auth checks.”*  
- **When Juniors miss findings**
  - Treat as learning: *“Here’s how I spotted this IDOR; next time, try fuzzing object IDs systematically.”*  

---

### 💡 Interview Tip
- Expect scenario questions like:  
  - “How would you mentor a new pentester?”  
  - “How do you explain a critical finding to a non-technical exec?”  
  - “What do you do if remediation is resisted?”  
- Best answers balance **technical credibility** with **collaboration and diplomacy**.  
