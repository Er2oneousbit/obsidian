## 🛡️ Interview Notes: What Is LLM Overreliance?

### ❓ What Is Overreliance on LLMs?
- **Overreliance** occurs when people or systems **trust LLM output without proper verification**.  
- LLMs can produce confident but incorrect or biased results ("hallucinations").  
- Risks of overreliance:  
  - 📉 Business logic errors when AI output drives workflows blindly  
  - 🧑‍⚖️ Legal or compliance violations (e.g., fabricated citations)  
  - 🔓 Security risks if unsafe code, queries, or configs are accepted at face value  
  - 🛠️ Engineers skipping validation/testing because “the model said so”  

---

### 🧪 How to Detect and Exploit Overreliance
- Attackers exploit trust by:  
  - Seeding malicious but plausible input (docs, data, code) that the model then amplifies  
  - Supplying poisoned external data that the system consumes without human review  
  - Leveraging hallucinations in AI-driven decision-making (e.g., finance, healthcare, legal)  

- Indicators:  
  - Systems acting on model outputs with **no validation or guardrails**  
  - Users treating model output as fact without cross-checking  
  - Automated pipelines that skip human approval for high-risk actions  

---

### 🛡️ How to Fix Overreliance
- ✅ Treat all LLM output as **untrusted** until validated  
- ✅ Require **human-in-the-loop** for sensitive or high-stakes decisions  
- ✅ Cross-verify outputs against trusted sources (databases, APIs, curated knowledge)  
- ✅ Apply **fact-checking, validation, and sanity checks** before using LLM responses in workflows  
- ✅ Train users on risks of hallucinations and biases  
- ✅ Monitor downstream actions taken on model outputs for anomalies  

---
