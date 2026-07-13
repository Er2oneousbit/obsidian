## 🛡️ Interview Notes: What Is CSRF?

### ❓ What Is CSRF?
- **Cross-Site Request Forgery (CSRF)** is a web vulnerability that tricks a user’s browser into making **unintended requests** to a site where they’re already authenticated.  
- It exploits the **trust a site has in the user’s browser**, not the other way around.  
- The attacker doesn’t steal data directly, but instead causes actions like:  
  - 🔄 Changing account settings  
  - 💰 Transferring funds  
  - 📝 Submitting forms  
- These actions are performed using the victim’s **session cookies**, which the browser automatically includes in requests.  

---

### 🧪 How to Detect and Exploit CSRF
- Identify **state-changing endpoints** (e.g., POST requests that update user data).  
- Check if the endpoint accepts requests without CSRF tokens or origin checks.  
- Craft a malicious request (defanged example):  

```html
&lt;form action="https://target.com/update-email" method="POST"&gt;
  &lt;input type="hidden" name="email" value="attacker[at]example.com"&gt;
&lt;/form&gt;
&lt;scri&lt;pt&gt;document.forms[0].submit();&lt;/scri&lt;pt&gt;
