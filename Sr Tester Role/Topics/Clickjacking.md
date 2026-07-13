## 🛡️ Interview Notes: What Is Clickjacking?

### ❓ What Is Clickjacking?
- **Clickjacking** (UI Redress Attack) is a vulnerability where an attacker tricks a user into clicking on a **hidden or disguised element** in a webpage.  
- It leverages iframes and visual manipulation to make users perform actions they didn’t intend.  
- Potential impacts:  
  - 🔓 Changing account settings (e.g., enable 2FA bypass, change email)  
  - 💳 Initiating unauthorized transactions  
  - 🎯 Triggering administrative actions  
  - 📷 Enabling webcam/microphone if permissions dialogs are hidden  

---

### 🧪 How to Detect and Exploit Clickjacking
- Test if the target site can be embedded in an iframe:  
  `<iframe src="https://target[.]com" width="800" height="600"></iframe>`  

- Overlay invisible or opaque elements to trick the user into clicking:  
  `<div style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%"></div>`  

- Combine with **social engineering** to lure the victim into clicking.  
- Enhanced techniques:  
  - 🌀 “Likejacking” → tricking users into liking/sharing content  
  - 🔀 Cursor-jacking → altering pointer positions  
  - 🧩 Chaining with CSRF or XSS for deeper exploitation  

---

### 🛡️ How to Fix Clickjacking
- ✅ Use the `X-Frame-Options` header:  
  - `DENY` → disallow all framing  
  - `SAMEORIGIN` → allow only same-origin framing  
- ✅ Use **Content Security Policy (CSP)** frame-ancestors directive:  
- ✅ Content-Security-Policy: frame-ancestors 'self'
- ✅ Apply frame-busting scripts (secondary defense, not foolproof).  
- ✅ Carefully allow framing only where needed (e.g., widgets) with domain whitelisting.  
- ✅ Regularly test sensitive actions (like account changes or payments) for frame injection.  

