# 🧩 Pentester Confusion Matrix
_A quick-reference sheet for vulnerabilities and attack types that sound similar but differ in key ways._

---

## 🌐 Web / API Vulnerabilities

### 🔄 XSS vs CSRF
- **XSS (Cross-Site Scripting)** → Inject malicious JavaScript, browser executes it, attacker steals data.  
- **CSRF (Cross-Site Request Forgery)** → Trick user’s browser to send unintended requests, attacker performs actions.  

---

### 🔄 Password Spraying vs Password Stuffing vs Brute Force
- **Brute Force** → Many guesses vs one account.  
- **Password Spraying** → Few common passwords vs many accounts.  
- **Password Stuffing** → Many leaked passwords vs one or a few known accounts.  

---

### 🔄 LFI vs RFI
- **LFI (Local File Inclusion)** → Include local server files (e.g., `/etc/passwd`).  
- **RFI (Remote File Inclusion)** → Include attacker-hosted file via URL → direct RCE.  

---

### 🔄 BOLA vs BFLA
- **BOLA (Object Level)** → Change object IDs to access other users’ data.  
- **BFLA (Function Level)** → Call higher-privileged functions directly.  

---

### 🔄 Mass Assignment vs Excessive Data Exposure
- **Mass Assignment** → Attacker sends extra fields in requests to modify unauthorized attributes.  
- **Excessive Data Exposure** → API leaks too much data in responses.  

---

### 🔄 Reflected XSS vs DOM XSS vs Stored XSS
- **Reflected** → Payload echoed back in server response.  
- **DOM** → Payload executed in client-side JS/DOM.  
- **Stored** → Payload stored in DB and runs on page load.  

---

### 🔄 SQLi vs NoSQLi
- **SQLi** → Relational DBs (MySQL, MSSQL), `' OR 1=1--`.  
- **NoSQLi** → Document DBs (Mongo, Couch), `{ "$ne": null }`.  

---

### 🔄 SSRF vs XXE
- **SSRF** → Trick server into making HTTP requests to internal systems.  
- **XXE** → Abuse XML parser to load external/local entities, often leading to SSRF or file read.  

---

### 🔄 DoS vs DDoS
- **DoS** → Single source overwhelms service.  
- **DDoS** → Botnet overwhelms target at scale.  

---

### 🔄 CSP vs CORS
- **CSP (Content Security Policy)** → HTTP header controlling where resources (scripts, styles, images) can be loaded from. Prevents XSS by restricting inline scripts, external script injection.  
- **CORS (Cross-Origin Resource Sharing)** → HTTP header controlling which external domains can make requests to your API/app. Prevents unauthorized cross-origin requests.  
- **Key Diff**: CSP is about *what can execute in the browser*; CORS is about *who can talk to the server*.

---

### 🔄 OAuth vs OIDC
- **OAuth 2.0** → Authorization (“app can act on your behalf”).  
- **OIDC** → Authentication layer on top of OAuth (“who you are”).  

---

### 🔄 Authentication vs Authorization
- **Authentication** → Who you are (identity check).  
- **Authorization** → What you can do (permissions check).  

---

## 🖥️ OS / Infrastructure

### 🔄 Privilege Escalation vs Lateral Movement
- **Privilege Escalation** → Gain higher rights on same system (user → root).  
- **Lateral Movement** → Move from one system/account to another at same privilege.  

---

### 🔄 Persistence vs Privilege Escalation
- **Persistence** → Maintain long-term access (registry keys, services, cronjobs).  
- **Privilege Escalation** → Gain more control (admin/system/root).  

---

### 🔄 Sandbox Escape vs VM Escape
- **Sandbox Escape** → Break out of restricted app container (e.g., browser sandbox).  
- **VM Escape** → Break out of guest VM into host system.  

---

### 🔄 Symmetric vs Asymmetric Encryption
- **Symmetric** → One key for encrypt + decrypt. Fast, used for bulk data.  
- **Asymmetric** → Public/private key pair. Used for exchange + signatures.  

---

### 🔄 Encoding vs Encryption vs Hashing
- **Encoding** → Data representation (Base64, URL encoding). No secrecy.  
- **Encryption** → Reversible secrecy (AES, RSA).  
- **Hashing** → One-way integrity (SHA256, bcrypt).  

---

### 🔄 MITM vs Replay Attack
- **MITM (Man-in-the-Middle)** → Attacker intercepts and modifies live traffic.  
- **Replay** → Attacker captures and replays old valid requests.  

---

## 🤖 AI / LLM Security

### 🔄 Prompt Injection vs Jailbreaking
- **Prompt Injection** → Malicious input instructs model to override original instructions.  
- **Jailbreaking** → Explicitly bypass safety filters to make model act outside intended scope.  

---

### 🔄 Data Leakage vs Sensitive Info Disclosure
- **Data Leakage (LLM02)** → Model spills training data, system prompts, configs.  
- **Sensitive Info Disclosure (LLM07)** → Model reveals real user/PII/API keys.  

---

### 🔄 Hallucination vs Data Poisoning
- **Hallucination** → Model generates convincing but false content.  
- **Data Poisoning** → Attacker manipulates training data so model outputs attacker-chosen responses.  

---

### 🔄 Insecure Output Handling vs XSS
- **Insecure Output Handling (LLM03)** → App trusts model output, renders unsafe HTML/JS.  
- **XSS** → User input not sanitized → code runs in browser.  

---

### 🔄 Excessive Agency vs Command Injection
- **Excessive Agency (LLM09)** → Model given dangerous permissions (file system, shell) and tricked into unsafe actions.  
- **Command Injection** → Attacker crafts input that breaks into system shell commands.  

---

### 🔄 AI Token vs JWT Token
- **AI Token** → Unit of text the LLM processes (subword chunks like “pen-test” split into “pen” + “test”).  
- **JWT Token** → Cryptographically signed string used for user authentication/authorization.  

---

## 📊 General Security Concepts

### 🔄 Vulnerability vs Exploit vs Payload
- **Vulnerability** → Weakness in system.  
- **Exploit** → Code/method to take advantage of vuln.  
- **Payload** → Malicious code delivered once exploit succeeds.  

---

### 🔄 Risk vs Threat vs Vulnerability
- **Risk** → Potential for loss if threat exploits vuln.  
- **Threat** → Something that can cause harm (attacker, malware).  
- **Vulnerability** → Weakness that can be exploited.  

---

### 🔄 Qualitative vs Quantitative Risk Assessment
- **Qualitative** → High/Medium/Low ratings, subjective analysis.  
- **Quantitative** → Dollar values, probabilities, hard metrics (e.g., ALE, SLE).  

---

### 🔄 Threat Modeling vs Risk Assessment
- **Threat Modeling** → Identify attackers, attack paths, assets at risk.  
- **Risk Assessment** → Measure business impact + likelihood.  

---
