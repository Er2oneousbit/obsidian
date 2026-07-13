## 🛡️ Interview Notes: What Is Excessive Agency in LLMs?

### ❓ What Is Excessive Agency?
- **Excessive Agency** occurs when an LLM is given too much **autonomy to act on behalf of users or systems** without sufficient safeguards.  
- Agency here means the model’s ability to **take actions, make decisions, and chain tasks** instead of just producing text.  
- Risks of excessive agency:  
  - 🔁 Infinite loops that waste resources (token floods, runaway costs)  
  - 🛠️ Unintended system actions (deleting files, sending sensitive data)  
  - 📡 Unsafe chaining of tools or APIs (pivoting into other systems)  
  - 🚨 Loss of human oversight in critical workflows  

---

### 🧪 How to Detect and Exploit Excessive Agency
- Look for setups where the LLM:  
  - Has **autonomous control** (e.g., AutoGPT, LangChain agents)  
  - Can **invoke plugins, APIs, or system commands** without user approval  
  - Chains multiple tools together without validation  

- Exploitation scenarios:  
  - Attacker crafts a prompt that causes the LLM to loop endlessly → **DoS**  
  - Prompt injection manipulates the model into using plugins for **data exfiltration**  
  - Model instructed to execute unsafe commands through a connected shell tool  

- Indicators:  
  - Models performing multi-step actions without human confirmation  
  - High-volume or unexpected plugin/API calls triggered by LLMs  
  - Lack of boundaries on what the model is “allowed” to do  

---

### 🛡️ How to Fix Excessive Agency
- ✅ Apply **least privilege** to LLMs — only allow necessary tools or actions  
- ✅ Require **explicit user approval** for sensitive or destructive tasks  
- ✅ Impose **limits on loops, steps, and recursion** to prevent runaway chains  
- ✅ Sandbox and isolate environments where LLMs can act  
- ✅ Implement **guardrails** (allow-lists of approved commands, APIs, or plugins)  
- ✅ Log and monitor all autonomous actions for anomalies  

---


### 🔗 Cross-Reference
- ⚠️ In modern AI/LLM systems, **command injection can occur through excessive agency**.  
- Example: If an LLM has direct access to a shell tool or plugin and can be tricked into running arbitrary commands, the effect is command injection, but the root cause is poor **agency control**.  


### 🔗 Cross-Reference
- ⚠️ Excessive agency often overlaps with **command injection**.  
- If an LLM is wired into system tools (like a shell executor) without guardrails, a prompt injection can escalate into **full RCE on the host**.  
- The model isn’t vulnerable because it’s “smart” or “dumb” — it’s vulnerable because it was **given unsafe authority**.  
