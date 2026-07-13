## 🛡️ Interview Notes: What Are JWT Vulnerabilities?

### ❓ What Is a JWT?
- A **JSON Web Token (JWT)** is a compact, URL-safe token used for **authentication and authorization**.  
- Format: `header.payload.signature`  
- Common in stateless authentication systems (APIs, SPAs, microservices).  
- Vulnerabilities arise when JWTs are **improperly validated, signed, or stored**.  

---

### 🧪 How to Detect and Exploit JWT Vulnerabilities

#### 🔓 None Algorithm Attack
- Some libraries accept `alg: none`, skipping signature checks.  
- Defanged header example:  
`{ "alg": "none", "typ": "JWT" }`

- Remove the signature → token becomes:  

#### 🔐 Key Confusion / Public Key as HMAC Secret
- If server expects **RS256** but accepts **HS256**:  
- Change `alg` to `HS256`  
- Sign with the **public key** as the HMAC secret  
- Result → forged valid tokens.  

#### 🧬 Weak Secret Brute-Forcing
- HS256 with weak secrets can be brute-forced using:  
- jwt_tool  
- John the Ripper  
- jwt-cracker  
- Once cracked, attacker can forge arbitrary tokens.  

#### 🧨 Token Replay / No Expiry
- Tokens without `exp` (expiration) can be reused indefinitely.  
- Replay attacks possible if tokens aren’t rotated/invalidated.  

#### 🧪 Payload Tampering
- If claims aren’t validated, attackers can escalate privileges.  
- Example → modify payload to:  
`{ "admin": true }`

---

### 🛡️ How to Fix JWT Vulnerabilities
- ✅ Enforce algorithm server-side (never trust `alg` field).  
- ✅ Use **asymmetric signing (RS256/ES256)** with proper key management.  
- ✅ Validate claims: `exp`, `iat`, `nbf`, `aud`, `iss`.  
- ✅ Rotate secrets and keys regularly.  
- ✅ Use **short-lived tokens** + refresh tokens securely.  
- ✅ Store tokens in `HttpOnly`, `Secure`, `SameSite` cookies.  
- ✅ Monitor for anomalies or abuse in token usage.  

---
