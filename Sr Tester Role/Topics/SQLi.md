## 🛡️ Interview Notes: What Is SQLi?

### ❓ What Is SQLi?
- **SQL Injection (SQLi)** is a vulnerability where an attacker manipulates input to **interfere with queries** sent to the database.  
- It occurs when user input is **unsafely concatenated** into SQL statements without proper parameterization or sanitization.  
- Common impacts:  
  - 🚪 Bypassing authentication  
  - 📂 Extracting sensitive data (e.g., usernames, passwords, credit cards)  
  - 📝 Modifying or deleting data  
  - 💀 Achieving **RCE** in some DBMS setups (via functions, file writes, or xp_cmdshell)  

---

### 🧪 How to Detect and Exploit SQLi
- Look for inputs that interact with the database:  
  - Login forms, search bars, filters, URL parameters  

- Classic test payloads (defanged examples):  
  - `' OR '1'='1`  
  - `admin'--`  
  - `1 AND 1=1` vs `1 AND 1=2`  

- Blind SQLi (time-based):  
  - `1' AND SLEEP(5)--`  

- UNION-based SQLi:  
  - `' UNION SELECT NULL, version(), user()--`  

- Tools:  
  - 🛠️ **sqlmap** for automated detection and exploitation  
  - 🛠️ Burp Suite with extensions (SQLiPy, sqlmap integration)  

---

### 🛡️ How to Fix SQLi
- ✅ Use **parameterized queries / prepared statements**  
- ✅ Avoid dynamic SQL string concatenation with user input  
- ✅ Use safe **ORMs** that abstract query construction (e.g., SQLAlchemy, Hibernate)  
- ✅ Apply **least privilege** for DB accounts (no unnecessary `DROP`, `ALTER`, etc.)  
- ✅ Sanitize and validate input:  
  - Whitelist expected values  
  - Reject unexpected characters/patterns  
- ✅ Monitor logs for anomalies or suspicious queries  

---
