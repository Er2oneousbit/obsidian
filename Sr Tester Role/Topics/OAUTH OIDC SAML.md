## 🛡️ Interview Notes: What Are OAuth, OIDC, and SAML?

### What is OAuth?
- **OAuth 2.0** is an **authorization framework**.  
- Lets a user grant a third-party app limited access to their resources **without sharing credentials**.  
- Example: “Login with Google” → app gets a token to access Google data on your behalf.  
- ⚠️ Misconception: OAuth is **not authentication** by itself.

---

### What is OIDC?
- **OpenID Connect (OIDC)** is an **authentication layer built on top of OAuth 2.0**.  
- Provides a standard way to prove **who the user is** (identity).  
- Uses **ID tokens (JWTs)** that contain claims (e.g., username, email).  
- Example: “Login with Google” → app gets an ID token proving your identity.  

---

### What is SAML?
- **Security Assertion Markup Language (SAML)** is an **XML-based standard for SSO (Single Sign-On)**.  
- Typically used in enterprise (ADFS, Okta, corporate apps).  
- Provides **authentication assertions** from an Identity Provider (IdP) to a Service Provider (SP).  
- Example: You log into your company portal, and SAML asserts your identity to Salesforce or Slack.  

---

### 🧪 Common Vulnerabilities

#### OAuth
- **Authorization Code Interception** → attacker steals code in redirect flow.  
- **Implicit Flow Issues** → tokens leaked via URLs.  
- **Open Redirect Abuse** → attacker tricks user into granting consent.  

#### OIDC
- **ID Token Manipulation** → weak signature validation → forged identity.  
- **Nonce/Replay Issues** → reuse of tokens if not validated properly.  
- **Mix-up Attacks** → confuse which IdP issued the token.  

#### SAML
- **Signature Wrapping** → attacker injects unsigned elements into signed SAML.  
- **XML External Entity (XXE)** in SAML parsers.  
- **Replay Attacks** if assertions lack timestamps/nonces.  

---

### 🛡️ How to Fix These Issues

- Use **PKCE (Proof Key for Code Exchange)** with OAuth to prevent interception.  
- Prefer **Authorization Code Flow with PKCE** over Implicit Flow.  
- Validate **token signatures, issuers, audiences, and expirations**.  
- In SAML:  
  - Enforce **strict XML signature validation**  
  - Disable DTD processing (prevents XXE)  
  - Use short lifetimes for assertions  
- Always use **TLS** end-to-end.  
- Implement **robust logout/invalidation** for tokens and sessions.  

---

### 💡 Interview Tip
- If asked to compare:  
  - **OAuth** = authorization (“what you can do”)  
  - **OIDC** = authentication built on OAuth (“who you are”)  
  - **SAML** = older XML-based SSO standard, still widely used in enterprises  
