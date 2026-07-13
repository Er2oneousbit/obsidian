## 🛡️ Interview Notes: What Are WebSocket Vulnerabilities?

### ❓ What Are WebSocket Vulnerabilities?
- **WebSockets** provide a persistent, bi-directional communication channel between client and server.  
- Vulnerabilities occur when authentication, authorization, or message handling is **insecure**.  
- Potential impacts:  
  - 🔓 Unauthorized access to real-time data  
  - 📝 Message tampering or injection  
  - 🕹️ Bypassing traditional HTTP security controls (CSRF, CORS)  
  - 💀 Account takeover or privilege escalation  

---

### 🧪 How to Detect and Exploit WebSocket Vulnerabilities
- Inspect WebSocket traffic in **Burp Suite** (`Proxy → WebSockets History`).  
- Check handshake and connection setup:  
  - Missing or weak authentication on `Upgrade: websocket` request  
  - No token or session validation during handshake  

- Test message-level issues:  
  - Modify JSON payloads sent over WebSockets  
  - Inject unexpected fields (e.g., `"role":"admin"`)  
  - Replay or fuzz messages  

- Look for lack of access control:  
  - Can one user subscribe to another’s messages?  
  - Can unauthorized users access privileged channels?  

- Payload tampering examples (defanged):  
  - Normal: `{"action":"getUser","id":1001}`  
  - Tampered: `{"action":"getUser","id":1002}`  

- Advanced attacks:  
  - 🔀 Cross-Site WebSocket Hijacking (CSWSH) if Origin checks are missing  
  - 🛠️ Abuse of binary frames or compression to smuggle data  

---

### 🛡️ How to Fix WebSocket Vulnerabilities
- ✅ Authenticate WebSocket connections the same way as HTTP (tokens, sessions, headers).  
- ✅ Validate Origin headers and enforce same-origin policies.  
- ✅ Apply strict authorization checks to every message/action.  
- ✅ Sanitize all input within messages (defend against injection).  
- ✅ Encrypt traffic with TLS (`wss://` instead of `ws://`).  
- ✅ Use short-lived tokens and revalidate sessions periodically.  
- ✅ Monitor and log WebSocket activity for anomalies.  

---
