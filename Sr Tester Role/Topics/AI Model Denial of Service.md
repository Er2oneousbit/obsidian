## 🛡️ Interview Notes: What Is LLM Denial of Service?

### ❓ What Is Model Denial of Service (DoS)?
- **Model Denial of Service (DoS)** happens when attackers craft prompts or requests that **exhaust the LLM’s resources** (CPU, GPU, memory, or cost budget).  
- Unlike traditional DoS, this targets **inference workloads** and can disrupt availability or drive up usage costs.  
- Potential impacts:  
  - ⏳ Sluggish or unavailable service for real users  
  - 💸 Cloud cost spikes from expensive queries  
  - 🚨 Resource starvation leading to service crashes  

---

### ❓ Side Note: What Is an AI Token?
- An **AI token** is a small unit of text (not a request or API key).  
- Models break words into **subword chunks** (tokens) for processing:  
  - `"Hello world!"` → 3 tokens (`Hello`, ` world`, `!`)  
  - `"Unbelievable"` → 3 tokens (`Un`, `believ`, `able`)  
- Costs and limits are measured in tokens:  
  - **Input tokens** = your prompt  
  - **Output tokens** = model’s response  
  - **Context window** = max tokens the model can process at once (e.g., ~128k for GPT-4 Turbo)  
- DoS attacks exploit this by **flooding the model with massive token counts** (e.g., pasting a book into one prompt).  

---

### 🧪 How to Detect and Exploit LLM DoS
- Attack vectors:  
  - **Prompt bombs** → overly long inputs that force the model to process massive context windows  
  - **Nested or recursive instructions** → “Repeat the word X a million times”  
  - **Adversarial tokens** → sequences that maximize compute load  
  - **Chaining plugins or APIs** → forcing repeated expensive calls  

- Indicators:  
  - Unusually high latency for certain queries  
  - Resource exhaustion logs (GPU memory maxed out)  
  - Sudden spikes in token usage or billing metrics  

- Tools/approaches:  
  - 🛠️ Burp/Turbo Intruder equivalents adapted for LLM APIs  
  - 🛠️ Fuzzing long/unusual prompts  
  - 🛠️ Monitoring inference cost and throughput during testing  

---

### 🛡️ How to Fix LLM DoS
- ✅ Enforce **rate limits** and **quotas** per user/session  
- ✅ Cap **input length** (max tokens per prompt) and output length  
- ✅ Use **query cost analysis** — reject or down-rank expensive requests  
- ✅ Add **timeouts** for inference tasks  
- ✅ Implement **circuit breakers** in multi-agent or plugin-enabled systems  
- ✅ Monitor usage for anomalies (sudden token floods, recursive requests)  

---
