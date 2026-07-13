## 🛡️ Interview Notes: What Is Training Data Poisoning?

### ❓ What Is Training Data Poisoning?
- **Training Data Poisoning** occurs when attackers manipulate or insert malicious data into the dataset used to train an LLM.  
- Since models “learn” patterns from their data, poisoned data can:  
  - 🧪 Introduce **backdoors** (special triggers cause malicious behavior)  
  - 🔓 Leak sensitive information included in training  
  - 🕹️ Manipulate model outputs toward attacker-controlled narratives  
  - 🚨 Reduce reliability/accuracy by skewing responses  

---

### 🧪 How to Detect and Exploit Training Data Poisoning
- Attack vectors:  
  - Uploading malicious content to **public sources** likely used in training (e.g., forums, GitHub, Wikipedia).  
  - Introducing **trigger phrases** that cause harmful or biased outputs.  
  - Poisoning RAG pipelines by slipping malicious docs into vector stores.  

- Exploitation examples (conceptual):  
  - Model outputs attacker-controlled responses when prompted with `"specialstring123"`.  
  - Malicious payloads inserted into FAQs or documentation, later scraped and learned by the model.  

- Indicators:  
  - Model behaves oddly or dangerously when triggered with certain keywords.  
  - Unexpected or biased responses that align with poisoned data.  
  - Backdoor-like behavior reproducible across queries.  

- Tools & research:  
  - 🛠️ Adversarial training tests  
  - 🛠️ Data lineage analysis to track sources  
  - 🛠️ Poisoning detection frameworks in ML security research  

---

### 🛡️ How to Fix Training Data Poisoning
- ✅ Use **trusted, curated datasets** — avoid blind scraping of unverified sources  
- ✅ Apply **data sanitization and filtering** before training  
- ✅ Perform **adversarial testing** to look for hidden triggers/backdoors  
- ✅ Monitor model behavior over time for anomalies  
- ✅ Incorporate **differential privacy** to reduce data leakage risks  
- ✅ Secure the **supply chain** of training data (versioning, integrity checks)  

---
