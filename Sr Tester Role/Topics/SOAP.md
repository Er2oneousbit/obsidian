## 🛡️ Interview Notes: What Is SOAP API Testing?

### What is SOAP?
- **SOAP (Simple Object Access Protocol)** is a protocol for exchanging structured XML messages between systems.  
- Unlike REST, SOAP is **strictly structured** and usually uses **WSDL (Web Services Description Language)** to define endpoints, parameters, and data types.  
- Common in **enterprise apps, financial services, and legacy systems**.  

---

### 🧪 How to Test SOAP APIs

#### 🔍 Recon
- Look for **WSDL files**:  
  - `http://target.com/service?wsdl`  
  - They describe methods, parameters, and datatypes.  
- Use tools like **SoapUI**, **Burp**, or **Postman** to parse WSDL and generate requests.  

#### 💥 Common Vulnerabilities
- **XML Injection** → Modify SOAP body to inject malicious XML.  
- **XXE (XML External Entity)** → SOAP parsers often mishandle external entities.  
- **WS-Security Misconfigurations** → Weak or missing signature/encryption.  
- **Replay Attacks** → If timestamp/signature validation is weak.  
- **Overly Verbose Errors** → SOAP faults may reveal stack traces, internal logic.  
- **Authentication Flaws** → Poor implementation of WS-Security headers (e.g., username/password tokens in cleartext).  

#### 🔧 Example Payloads (defanged)
- Test parameter tampering:  
  ```xml
  <soap:Envelope>
    <soap:Body>
      <GetUser>
        <UserID>123</UserID>
      </GetUser>
    </soap:Body>
  </soap:Envelope>
```
- Change 123 → 124 (BOLA-style test).
- Test XXE:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope>
  <soap:Body>
    <GetData>&xxe;</GetData>
  </soap:Body>
</soap:Envelope>
```

### 🛡️ How to Fix SOAP Issues
- Enforce **strong WS-Security**:
  - Message signing + encryption
  - Timestamp validation + nonce usage to prevent replay attacks
- Disable **DTD and external entities** in XML parsers
- Validate input strictly against the **WSDL schema**
- Return **generic error messages** only (no stack traces)
- Use **TLS everywhere** (SOAP is often deployed over HTTP internally)
- Limit exposed operations and remove unused endpoints

---

### 💡 Interview Tip
- If asked “How is SOAP different from REST?” → emphasize:  
  - **REST** = flexible, lightweight, JSON, no strict schema  
  - **SOAP** = rigid XML structure, WSDL contract, more security features built-in (but often misused)  
