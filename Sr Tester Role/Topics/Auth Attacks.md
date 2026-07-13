## 🛡️ Interview Notes: What Are Authentication Attacks?

### ❓ What Are Authentication Attacks?
- **Authentication attacks** target the mechanisms that verify a user’s identity.  
- The attacker’s goal is to **bypass, brute-force, or manipulate** login systems.  
- Successful attacks can lead to:
  - 🚨 Unauthorized access  
  - 🚨 Privilege escalation  
  - 🚨 Account takeover  
  - 🚨 Lateral movement  

---

### 🧪 Common Authentication Attacks

#### 🔐 Brute Force
- Repeatedly guessing credentials until successful.  
- Many passwords, one account
- Tools: Hydra, Burp Intruder, Medusa.  
- ⚠️ Mitigated by: rate limiting, account lockout, CAPTCHA.  

#### 🔐 Credential Stuffing
- Using leaked username/password pairs from other breaches.  
- Many leaked cred pairs, many sites
- Exploits password reuse across services.  
- ⚠️ Mitigated by: MFA, breached credential monitoring, device fingerprinting.  

#### 🔐 Password Spraying
- Trying a few common passwords (e.g., `Spring2025!`) across many accounts.  
- Few passwords, many accounts
- Avoids lockouts by rotating usernames.  
- ⚠️ Mitigated by: strong password policies, IP/user lockouts.  

#### 🛠️ Password Reset Weakness
- Guessable or short reset tokens.  
- Tokens never expire or can be reused.  
- Flawed reset flows that let attackers change other users’ passwords.  

#### 📱 2FA / MFA Bypass
- SIM swapping, phishing, or abusing insecure fallback mechanisms.  
- ⚠️ Mitigated by: phishing-resistant MFA (FIDO2/WebAuthn), disabling SMS/email recovery.  

#### 🎟️ Session Hijacking
- Stealing or predicting session tokens (via XSS, cookies, URLs).  
- ⚠️ Mitigated by: secure cookie flags (`HttpOnly`, `Secure`, `SameSite`), regenerating tokens.  

#### 🧩 JWT Attacks
- Abusing `alg=none`, weak secrets, or key confusion.  
- ⚠️ Mitigated by: strict signature validation, key rotation, strong secrets.  

---

### 🛡️ How to Defend Against Authentication Attacks
- 🔑 Enforce **strong password policies** (≥12 chars, no complexity gimmicks).  
- 🔑 Store creds with bcrypt or Argon2 (never MD5/SHA1).  
- 🔑 Implement MFA everywhere — especially sensitive actions.  
- 🔑 Use secure session management:
  - Random, unpredictable tokens  
  - Short token lifetimes  
  - Cookie flags: `HttpOnly`, `Secure`, `SameSite`  
  - Session regeneration on login/privilege change  
- 🔎 Monitor for anomalies:
  - Failed login spikes  
  - Logins from unusual geos/devices  
  - Use of breached credentials  
- 🧑‍💻 Train users against phishing/social engineering.  
