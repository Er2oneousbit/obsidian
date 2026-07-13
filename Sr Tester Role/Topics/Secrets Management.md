## 🛡️ Interview Notes: What Are Common Crypto & Secrets Management Issues?

### What Are Crypto & Secrets Management Issues?
- Weaknesses in how applications **encrypt, store, or handle secrets (keys, tokens, passwords)**.  
- Lead to data exposure, privilege escalation, or full system compromise.  

---

### 🧪 Common Issues and Attacks

#### 🔑 Hardcoded Credentials
- Secrets embedded in source code, binaries, or config files.  
- Example: API keys in GitHub repo, DB creds in `.env`.  
- Tools: `trufflehog`, `git-secrets`, manual review.  

---

#### 🔑 Weak or Reused Keys
- Short RSA keys (<2048-bit) or default vendor keys.  
- Symmetric keys reused across multiple services.  
- Example: JWT signed with weak secret like `password123`.  

---

#### 🔑 TLS Misconfiguration
- Weak ciphers, SSLv2/3, TLS 1.0/1.1 enabled.  
- Missing `HSTS` or certificate pinning.  
- Self-signed or expired certificates.  
- Tools: `testssl.sh`, SSL Labs scanner.  

---

#### 🔑 Improper Key Storage
- Secrets stored in plaintext or weakly encrypted.  
- DBs, config files, or logs containing creds.  
- Cloud metadata services exposing tokens (`169.254.169.254`).  

---

#### 🔑 JWT Vulnerabilities
- `alg: none` accepted → skip signature validation.  
- Key confusion (RS256 → HS256 swap).  
- Tokens with no expiry (`exp` claim missing).  
- Replay attacks if tokens not rotated or invalidated.  
- Tools: `jwt_tool`, `john`, `hashcat`.  

---

#### 🔑 Padding Oracle Attacks
- Attack on block ciphers in CBC mode.  
- Exploit error messages during decryption to recover plaintext.  
- Example: POODLE, Lucky13.  

---

### 🛡️ How to Fix Crypto & Secrets Issues
- Remove **hardcoded creds**; use secure vaults (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).  
- Enforce **key rotation** and strong entropy.  
- Use **modern TLS** (TLS 1.2+), disable weak ciphers/protocols.  
- Store passwords with strong hashing (e.g., bcrypt, Argon2).  
- Enforce **JWT best practices**:  
  - Strong signing algorithms (RS256+).  
  - Validate all claims (`exp`, `aud`, `iss`).  
  - Short lifetimes + refresh tokens.  
- Harden error handling: return generic errors on crypto failures.  

---

### 💡 Interview Tip
- If asked “How do attackers find secrets?” → say **code review, Git history, decompiling binaries, cloud metadata abuse**.  
- If asked “How should secrets be stored?” → answer **vaults, strong crypto, no plaintext, rotate often**.  
