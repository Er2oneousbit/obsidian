## 🛡️ Interview Notes: What Are LLM Supply Chain Vulnerabilities?

### ❓ What Are Supply Chain Vulnerabilities in LLMs?
- **Supply Chain Vulnerabilities** happen when attackers target the ecosystem around the LLM rather than the model itself.  
- Since LLMs rely on many external components (models, datasets, libraries, plugins, APIs), compromise in any link can affect security.  
- Potential impacts:  
  - 🐍 Malicious or backdoored ML libraries (PyTorch, TensorFlow)  
  - 📦 Dependency confusion in AI frameworks/packages  
  - 🧩 Compromised pre-trained models (trojaned weights/backdoors)  
  - 🔗 Insecure plugins or connectors exposing sensitive data  
  - ☁️ Insecure deployment (cloud misconfigs, poisoned images/containers)  

---

### 🧪 How to Detect and Exploit Supply Chain Vulnerabilities
- Attack vectors:  
  - Upload malicious **pre-trained models** to public hubs (Hugging Face, GitHub)  
  - Poison **requirements.txt** or package managers (`pip`, `npm`) for AI projects  
  - Modify **containers or VM images** used to host AI models  
  - Slip malicious code into **RAG connectors, plugins, or extensions**  

- Exploitation examples (conceptual):  
  - Trojaned model behaves normally until a **trigger phrase** activates hidden behavior  
  - Compromised library executes malicious code on import  
  - Plugin mishandles API credentials, leaking secrets  

- Indicators:  
  - Use of **unverified models/libraries** from public sources  
  - Lack of integrity checks or signing on ML artifacts  
  - Inconsistent or unexpected model behavior  

---

### 🛡️ How to Fix Supply Chain Vulnerabilities
- ✅ Use **trusted sources** for models, datasets, and libraries  
- ✅ Apply **package signing** and integrity verification (hashes, checksums)  
- ✅ Regularly **scan dependencies** for CVEs and malicious packages  
- ✅ Validate and sandbox **plugins, APIs, and connectors** before use  
- ✅ Lock down **container and VM images** (scan for malware, patch regularly)  
- ✅ Maintain a **SBOM (Software Bill of Materials)** for AI components  
- ✅ Monitor model outputs for anomalies that may indicate backdoors  

---
