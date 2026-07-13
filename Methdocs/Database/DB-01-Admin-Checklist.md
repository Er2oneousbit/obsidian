# Database Admin Checklist

Quick reference for gathering administrative and architectural information before testing begins.

Related: [[DB-02-Technical-Testing-Checklist]] | [[DB-00-Overview]]

---

## Pre-Engagement

### Engagement Scope
- [ ] Database system name/identifier documented
- [ ] Primary business function understood
- [ ] Environment confirmed (dev/staging/prod)
- [ ] Testing window scheduled
- [ ] Out-of-scope databases/servers documented
- [ ] Emergency contact identified  
- [ ] Rules of engagement signed
- [ ] Data handling restrictions noted
- [ ] Backup/restore plan confirmed

### Access Provided
- [ ] Test account credentials (multiple privilege levels)
  - [ ] Low-privilege: ________________
  - [ ] Mid-privilege: ________________
  - [ ] Admin (read-only): ________________
- [ ] Network access (VPN, jump box)
- [ ] Database connection details
  - [ ] Hostname/IP: ________________
  - [ ] Port: ________________
  - [ ] Instance: ________________
- [ ] Client software available
- [ ] Documentation (ERD, schema, procedures)

---

## Database Platform

### Database Type & Version
- [ ] **Platform**: [MSSQL / MySQL / PostgreSQL / Oracle / MongoDB / Redis / Other]
- [ ] **Version**: ________________
- [ ] **Edition**: [Enterprise / Standard / Express / Community]
- [ ] **Patch Level**: ________________
- [ ] **Architecture**: [32-bit / 64-bit]

### Operating System
- [ ] **OS**: [Windows Server / Linux / Unix]
- [ ] **OS Version**: ________________
- [ ] **Patch Level**: ________________
- [ ] **Domain Joined**: Yes / No
  - [ ] Domain: ________________

---

## Network Architecture

### Network Position
- [ ] **Internet-facing**: Yes / No
- [ ] **Network segment**: ________________
- [ ] **Firewall rules**: Yes / No
  - [ ] Allowed sources: ________________
- [ ] **Network isolation**: [DMZ / Internal / Mixed]
- [ ] **VPN required**: Yes / No
- [ ] **Jump box required**: Yes / No

### Service Exposure
- [ ] **Database port**: ________ (TCP/UDP)
- [ ] **Management port**: ________
- [ ] **Replication port**: ________
- [ ] **Services running**:
  - [ ] Database engine
  - [ ] Browser/Discovery service
  - [ ] Agent services

---

## Authentication & Authorization

### Authentication Methods
- [ ] **SQL Authentication**: Enabled / Disabled
  - [ ] Mixed mode (SQL + Windows): Yes / No
- [ ] **Windows Authentication**: Enabled / Disabled
- [ ] **Integrated Auth (Kerberos/NTLM)**: Yes / No
- [ ] **Certificate-based**: Yes / No
- [ ] **LDAP integration**: Yes / No
- [ ] **Cloud IAM** (if cloud DB): Yes / No

### Password Policies
- [ ] **Password complexity**: Enforced / Not enforced
- [ ] **Minimum length**: ________ characters
- [ ] **Password expiration**: Yes / No
  - [ ] Expiration period: ________ days
- [ ] **Account lockout**: Yes / No
  - [ ] Threshold: ________ failed attempts
  - [ ] Lockout duration: ________ minutes

### User Accounts
- [ ] **Number of accounts**: ________
- [ ] **Default accounts present**: Yes / No
  - [ ] sa (MSSQL)
  - [ ] root (MySQL)
  - [ ] postgres (PostgreSQL)
  - [ ] SYSTEM/SYS (Oracle)
- [ ] **Service accounts documented**: Yes / No
- [ ] **Application accounts**: ________ accounts
- [ ] **Admin accounts**: ________ accounts
- [ ] **Disabled accounts reviewed**: Yes / No

### Roles & Permissions
- [ ] **RBAC implemented**: Yes / No
- [ ] **Custom roles defined**: Yes / No
- [ ] **Roles documented**:
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
- [ ] **Principle of least privilege**: Applied / Not applied
- [ ] **PUBLIC role permissions reviewed**: Yes / No
- [ ] **GRANT WITH GRANT OPTION used**: Yes / No

---

## Database Configuration

### Security Settings (MSSQL)
- [ ] **xp_cmdshell**: Enabled / Disabled
- [ ] **OLE Automation**: Enabled / Disabled
- [ ] **Remote Access**: Enabled / Disabled
- [ ] **CLR Integration**: Enabled / Disabled
- [ ] **Database Mail**: Enabled / Disabled
- [ ] **SQL Server Agent**: Running / Stopped
- [ ] **Ad Hoc Distributed Queries**: Enabled / Disabled

### Security Settings (MySQL)
- [ ] **local_infile**: Enabled / Disabled
- [ ] **secure_file_priv**: Set / Not set
  - [ ] Value: ________________
- [ ] **skip-networking**: Enabled / Disabled
- [ ] **bind-address**: ________________
- [ ] **SSL/TLS**: Required / Optional / Disabled

### Security Settings (PostgreSQL)
- [ ] **Trusted languages**: ________________
- [ ] **Superuser permissions reviewed**: Yes / No
- [ ] **SSL mode**: require / prefer / allow / disable
- [ ] **pg_hba.conf reviewed**: Yes / No
  - [ ] Trust authentication present: Yes / No
  - [ ] Password authentication: md5 / scram-sha-256 / plain

### Security Settings (MongoDB)
- [ ] **Authentication enabled**: Yes / No
- [ ] **Authorization enabled**: Yes / No
- [ ] **TLS/SSL**: Enabled / Disabled
- [ ] **JavaScript enabled**: Yes / No
- [ ] **Bind IP**: ________________ (0.0.0.0 = insecure)

---

## Encryption

### Data at Rest
- [ ] **Transparent Data Encryption (TDE)**: Enabled / Disabled
  - [ ] Databases encrypted: ________________
- [ ] **Column-level encryption**: Used / Not used
- [ ] **Backup encryption**: Enabled / Disabled
- [ ] **Temp DB encryption**: Enabled / Disabled

### Data in Transit
- [ ] **SSL/TLS**: Required / Optional / Disabled
- [ ] **Certificate**: Valid / Self-signed / Expired
  - [ ] Issuer: ________________
  - [ ] Expiration: ________________
- [ ] **Protocol version**: [TLS 1.2 / TLS 1.3 / Older]
- [ ] **Cipher suites**: Strong / Weak / Unknown

---

## Linked Servers & External Connections

### Linked Servers (MSSQL)
- [ ] **Linked servers configured**: Yes / No
- [ ] **Number of links**: ________
- [ ] **Linked server details**:
  - [ ] Name: ________________ | Type: ________________ | Auth: ________________
  - [ ] Name: ________________ | Type: ________________ | Auth: ________________
- [ ] **RPC Out enabled**: Yes / No
- [ ] **Data Access enabled**: Yes / No

### Database Links (Oracle)
- [ ] **Database links present**: Yes / No
- [ ] **Number of links**: ________
- [ ] **Link details**: ________________

### External Connections (PostgreSQL)
- [ ] **Foreign data wrappers**: Yes / No
- [ ] **dblink extension**: Installed / Not installed

---

## Auditing & Logging

### Audit Configuration
- [ ] **Audit enabled**: Yes / No
- [ ] **Audit level**: [Server / Database / Both / None]
- [ ] **Audited events**:
  - [ ] Logins (success/failure)
  - [ ] Schema changes
  - [ ] Data access (SELECT)
  - [ ] Data modification (INSERT/UPDATE/DELETE)
  - [ ] Permission changes
  - [ ] Configuration changes
- [ ] **Audit log location**: ________________
- [ ] **Log retention**: ________ days
- [ ] **Log review process**: Yes / No

### Error Logging
- [ ] **Error log location**: ________________
- [ ] **Verbose errors**: Yes / No
- [ ] **Logs accessible by low-priv users**: Yes / No

---

## Backup & Recovery

### Backup Strategy
- [ ] **Backup type**: [Full / Differential / Incremental / Transaction log]
- [ ] **Backup frequency**:
  - [ ] Full: ________________
  - [ ] Differential: ________________
  - [ ] Transaction log: ________________
- [ ] **Backup location**: ________________
- [ ] **Backup encryption**: Yes / No
- [ ] **Backup compression**: Yes / No
- [ ] **Backup tested**: Yes / No
  - [ ] Last test: ________________

### Recovery Model (MSSQL)
- [ ] **Recovery model**: [Simple / Full / Bulk-logged]
- [ ] **Point-in-time recovery**: Possible / Not possible

---

## Data Classification

### Sensitive Data Types
Database contains (check all that apply):
- [ ] PII (Personally Identifiable Information)
- [ ] PHI (Protected Health Information)
- [ ] PCI (Payment Card Information)
- [ ] Credentials (passwords, API keys)
- [ ] Financial data
- [ ] Trade secrets / IP
- [ ] Customer data
- [ ] Employee data
- [ ] Legal documents
- [ ] Other: ________________

### Data Volume
- [ ] **Total database size**: ________ GB/TB
- [ ] **Number of databases**: ________
- [ ] **Largest tables**: ________________
- [ ] **Record counts**: ________________
- [ ] **Growth rate**: ________ per month

---

## High Availability & Replication

### HA Configuration
- [ ] **High Availability**: Enabled / Disabled
- [ ] **HA Type**: [Always On / Mirroring / Log Shipping / Clustering / Replication / None]
- [ ] **Primary server**: ________________
- [ ] **Secondary server(s)**: ________________
- [ ] **Automatic failover**: Yes / No

### Replication
- [ ] **Replication configured**: Yes / No
- [ ] **Replication type**: [Transactional / Merge / Snapshot / Other]
- [ ] **Replication topology**: [Publisher-Subscriber / Master-Slave / Master-Master]
- [ ] **Replication lag**: ________ seconds

---

## Stored Procedures & Functions

### Stored Code Review
- [ ] **Number of stored procedures**: ________
- [ ] **Number of functions**: ________
- [ ] **Number of triggers**: ________
- [ ] **Extended stored procedures**: ________ (MSSQL)
- [ ] **User-defined functions**: ________ (MySQL)
- [ ] **Dynamic SQL used**: Yes / No / Unknown
- [ ] **Code review completed**: Yes / No

### Dangerous Procedures (if enabled)
- [ ] **xp_cmdshell** (MSSQL)
- [ ] **sp_OACreate** (MSSQL)
- [ ] **xp_regread/xp_regwrite** (MSSQL)
- [ ] **sys_exec** (MySQL UDF)

---

## Application Integration

### Applications Using Database
- [ ] **Primary application**: ________________
- [ ] **Application type**: [Web / Desktop / Mobile / API]
- [ ] **Connection method**: [ADO.NET / JDBC / ODBC / ORM / Native]
- [ ] **Connection pooling**: Yes / No
- [ ] **ORM used**: [Entity Framework / Hibernate / Django ORM / None]

### Connection Strings
- [ ] **Hardcoded credentials**: Yes / No / Unknown
- [ ] **Integrated authentication**: Yes / No
- [ ] **Service account used**: Yes / No
- [ ] **Connection encryption**: Yes / No

---

## Compliance & Regulatory

### Compliance Requirements
- [ ] **HIPAA**: Yes / No
- [ ] **PCI-DSS**: Yes / No
  - [ ] Level: ________________
- [ ] **GDPR**: Yes / No
- [ ] **SOX**: Yes / No
- [ ] **SOC 2**: Yes / No
- [ ] **ISO 27001**: Yes / No
- [ ] **FISMA**: Yes / No
- [ ] **Other**: ________________

### Compliance Controls
- [ ] **Access reviews conducted**: Yes / No
  - [ ] Frequency: ________________
- [ ] **Audit logs reviewed**: Yes / No
  - [ ] Frequency: ________________
- [ ] **Vulnerability scanning**: Yes / No
  - [ ] Last scan: ________________
- [ ] **Penetration testing**: Yes / No
  - [ ] Last test: ________________

---

## Monitoring & Alerting

### Database Monitoring
- [ ] **Monitoring solution**: [SQL Monitor / Datadog / SolarWinds / Nagios / None]
- [ ] **Monitored metrics**:
  - [ ] CPU usage
  - [ ] Memory usage
  - [ ] Disk I/O
  - [ ] Query performance
  - [ ] Failed logins
  - [ ] Deadlocks
  - [ ] Blocking
- [ ] **Alerting configured**: Yes / No
  - [ ] Alert recipients: ________________

### Security Monitoring
- [ ] **SIEM integration**: Yes / No
  - [ ] SIEM platform: ________________
- [ ] **Failed login alerts**: Yes / No
- [ ] **Privilege escalation alerts**: Yes / No
- [ ] **Configuration change alerts**: Yes / No

---

## Patching & Maintenance

### Patch Management
- [ ] **Patching schedule**: ________________
- [ ] **Last patched**: ________________
- [ ] **Pending patches**: ________________
- [ ] **Change window**: ________________
- [ ] **Rollback plan**: Yes / No

### Maintenance
- [ ] **Index maintenance**: Scheduled / Manual / None
- [ ] **Statistics update**: Auto / Manual / None
- [ ] **Integrity checks (DBCC)**: Yes / No
  - [ ] Frequency: ________________
- [ ] **Cleanup jobs**: Yes / No

---

## Previous Security Issues

### Known Vulnerabilities
- [ ] **Previous pentest findings**: Yes / No
  - [ ] Date: ________________
  - [ ] Critical issues: ________________
- [ ] **CVEs applicable**: ________________
- [ ] **Security incidents**: Yes / No
  - [ ] Date: ________________
  - [ ] Type: ________________

---

## Testing Constraints

### Known Limitations
Document any restrictions:
- ________________
- ________________

### Red Lines (Do Not Cross)
- ________________
- ________________

### Performance Concerns
- [ ] **High transaction volume**: Yes / No
- [ ] **Peak hours**: ________________
- [ ] **Resource limits for testing**: ________________

---

## Initial Observations

### Quick Checks
- [ ] **Banner grabbed**: Yes / No
  - [ ] Version disclosed: ________________
- [ ] **Anonymous access possible**: Yes / No
- [ ] **Default port in use**: Yes / No
- [ ] **Visible error messages**: Yes / No

### Security Posture (Initial)
- [ ] Strong / Moderate / Weak
- [ ] Notes: ________________

---

## Kickoff Meeting Notes

**Date**: ________________
**Attendees**: ________________

**Key Discussion Points**:
________________

**Questions to Follow Up**:
- [ ] ________________
- [ ] ________________

---

## Admin Checklist Complete
- [ ] All critical information gathered
- [ ] Scope clearly defined
- [ ] Access confirmed working
- [ ] Testing tools ready
- [ ] Ready to proceed to [[DB-02-Technical-Testing-Checklist|Technical Testing]]

---

## Tags
#admin #discovery #scoping #database-testing

---

## Related Documents
- [[DB-00-Overview|Overview]]
- [[DB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[DB-03-Query-Tracker|Query Tracker]]

---
*Created: 2026-01-22*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
