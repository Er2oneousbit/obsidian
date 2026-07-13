## 🛡️ Interview Notes: What Are Kerberos and NTLM Attacks?

### What is Kerberos?
- **Kerberos** is a network authentication protocol used in Active Directory (AD) environments.  
- Relies on a **Key Distribution Center (KDC)** which issues tickets:  
  - **TGT (Ticket Granting Ticket)** proves your identity.  
  - **Service Tickets** prove access to specific services.  
- Stronger than NTLM, but still has attack vectors.  

---

### 🧪 Common Kerberos Attacks

- **Kerberoasting**  
  → Request service tickets for accounts with SPNs.  
  → Tickets are encrypted with the service account’s NTLM hash.  
  → Offline crack the hash to recover service account password.  

- **AS-REP Roasting**  
  → If “Do not require pre-authentication” is enabled on a user, attacker can request an encrypted AS-REP response and crack it offline.  

- **Pass-the-Ticket (PtT)**  
  → Steal a valid Kerberos ticket from memory (e.g., via Mimikatz) and reuse it.  

- **Golden Ticket**  
  → Compromise KRBTGT account (the KDC’s root key).  
  → Forge TGTs for any user, including domain admins.  

- **Silver Ticket**  
  → Compromise a service account.  
  → Forge service tickets for that service without KDC involvement.  

---

### What is NTLM?
- **NTLM (NT LAN Manager)** is an older Microsoft authentication protocol.  
- Uses a **challenge-response mechanism** with password hashes.  
- Still used for legacy apps or fallback when Kerberos fails.  

---

### 🧪 Common NTLM Attacks

- **Pass-the-Hash (PtH)**  
  → Use stolen NTLM hash directly to authenticate without knowing plaintext password.  

- **NTLM Relay**  
  → Capture NTLM challenge-response and relay it to another service to authenticate.  
  → Example: SMB relay → gain access to file shares.  

- **Password Cracking**  
  → Capture NTLMv2 challenge-response and brute-force offline with tools like Hashcat.  

---

### 🛡️ How to Defend Against Kerberos/NTLM Attacks

- Enforce **strong passwords** for service accounts.  
- Use **Managed Service Accounts** where possible.  
- Limit accounts with **SPNs** and monitor for unusual ticket requests.  
- Enable **Kerberos pre-authentication** for all users.  
- Regularly rotate the **KRBTGT account password** (for Golden Ticket defense).  
- Disable or restrict **NTLM usage** where possible.  
- Enable **SMB signing** and **LDAP signing** to mitigate NTLM relay.  
- Monitor logs for unusual ticket-granting activity or authentication anomalies.  

---

### 💡 Interview Tip
- If asked “What’s the difference?”:  
  - **Kerberos** = ticket-based, stronger, default in AD.  
  - **NTLM** = challenge-response, legacy fallback.  
- If asked “What are Golden vs Silver Tickets?”:  
  - **Golden Ticket** = forged TGT → domain-wide access.  
  - **Silver Ticket** = forged service ticket → access to specific service.  
