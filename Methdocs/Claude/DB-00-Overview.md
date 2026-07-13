# Database Penetration Testing Overview

## Purpose
Comprehensive methodology for assessing database security vulnerabilities, with focus on authentication bypass, privilege escalation, SQL injection exploitation, data exfiltration, and configuration weaknesses.

## Document Structure
- [[DB-01-Admin-Checklist]] - Pre-engagement information gathering
- [[DB-02-Technical-Testing-Checklist]] - Hands-on testing methodology
- [[DB-03-Query-Tracker]] - Document successful/failed queries and exploits
- [[DB-04-Evidence-Collection]] - Screenshot and evidence tracking
- [[DB-05-Reporting-Template]] - Finding documentation structure
- [[DB-06-Quick-Reference]] - Fast lookup for common attacks

## Engagement Workflow
1. Complete [[DB-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[DB-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[DB-03-Query-Tracker|Query Tracker]]
4. Capture evidence per [[DB-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[DB-05-Reporting-Template|Reporting Template]]

## Key Concepts

### Attack Surface Areas
- **Authentication** - Default credentials, weak passwords, authentication bypass
- **Authorization** - Privilege escalation, role abuse, permission gaps
- **Network Security** - Open ports, unencrypted connections, exposed services
- **Configuration** - Weak settings, unnecessary features, verbose errors
- **Data Security** - Encryption at rest, sensitive data exposure, backup security
- **Injection** - SQL injection exploitation, command injection via stored procedures
- **Post-Exploitation** - OS command execution, lateral movement, persistence

### Common Database Vulnerability Classes

**Authentication & Access Control**:
- Default/weak credentials
- SQL authentication bypass
- Privilege escalation
- Role manipulation
- Trust relationships abuse

**Configuration Issues**:
- Weak encryption settings
- Excessive permissions
- Unnecessary features enabled (xp_cmdshell, OPENROWSET, etc.)
- Verbose error messages
- Remote access enabled unnecessarily

**Injection Vulnerabilities**:
- SQL injection (when accessible via application)
- Command injection via stored procedures
- XML injection (SQL Server)
- NoSQL injection (MongoDB, etc.)

**Data Exposure**:
- Unencrypted data at rest
- Unencrypted connections
- Backup files accessible
- Sensitive data in logs
- Data in temp tables/files

**Post-Exploitation**:
- OS command execution
- File system access
- Linked server abuse
- Credential harvesting
- Lateral movement via database trust relationships

## Database Types Covered

### Relational Databases (SQL)
- **Microsoft SQL Server** (MSSQL)
- **MySQL / MariaDB**
- **PostgreSQL**
- **Oracle Database**
- **IBM DB2**
- **SQLite**

### NoSQL Databases
- **MongoDB**
- **Redis**
- **Cassandra**
- **CouchDB**
- **Elasticsearch**

### Cloud Databases
- **Amazon RDS** (MySQL, PostgreSQL, MSSQL, Oracle)
- **Amazon Aurora**
- **Azure SQL Database**
- **Google Cloud SQL**

## Tools

### Enumeration & Scanning
- Nmap (port scanning, service detection)
- Metasploit auxiliary modules
- Netcat (banner grabbing)
- Custom scripts (Python, PowerShell)

### Authentication Testing
- Hydra (brute force)
- Medusa (parallel brute force)
- Ncrack (credential stuffing)
- Custom wordlists (SecLists)

### Exploitation
- SQLMap (SQL injection automation)
- Metasploit modules (exploits, post-exploitation)
- PowerUpSQL (SQL Server pentesting)
- NoSQLMap (NoSQL injection)
- Impacket (MSSQL client, Kerberos attacks)

### Database Clients
- DBeaver (universal DB client)
- SQL Server Management Studio (SSMS)
- MySQL Workbench
- pgAdmin (PostgreSQL)
- MongoDB Compass
- Redis CLI

### Post-Exploitation
- PowerUpSQL (privilege escalation, lateral movement)
- Metasploit meterpreter (pivot, port forward)
- Impacket (credential dumping, SMB relay)
- Custom scripts for data exfiltration

## Testing Methodology

### 1. Information Gathering
- Port scanning (default DB ports)
- Service version detection
- Banner grabbing
- Database fingerprinting
- Network topology mapping

### 2. Authentication Testing
- Default credentials testing
- Weak password brute force
- Authentication bypass
- Windows authentication abuse (MSSQL)
- Kerberos attacks (if AD integrated)

### 3. Authorization Testing
- Privilege enumeration
- Vertical privilege escalation
- Horizontal privilege escalation (access other DB users' data)
- Role abuse
- Permission gaps

### 4. Configuration Review
- Review security settings
- Check for dangerous features enabled
- Audit user permissions
- Review trust relationships
- Check encryption settings

### 5. Data Security Assessment
- Encryption at rest verification
- Connection encryption (TLS/SSL)
- Sensitive data discovery
- Backup security review
- Audit log review

### 6. Injection Testing
- SQL injection exploitation (via app or direct)
- Command injection via stored procedures
- XML injection (SQL Server)
- NoSQL injection

### 7. Post-Exploitation
- OS command execution
- File system access
- Credential harvesting
- Linked server pivoting
- Lateral movement
- Persistence mechanisms

## Common Database Ports

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

## Key Attack Vectors

### MSSQL-Specific
- xp_cmdshell (OS command execution)
- OPENROWSET / OPENQUERY (read files, query external sources)
- Linked servers (lateral movement)
- SQL Server Agent jobs (persistence, scheduled command execution)
- sp_OACreate (COM object abuse)
- Service account token impersonation

### MySQL-Specific
- FILE privilege abuse (read/write files)
- LOAD DATA INFILE (read files)
- SELECT INTO OUTFILE (write files, web shells)
- User-defined functions (UDF) for code execution
- GRANT privilege escalation

### PostgreSQL-Specific
- COPY TO/FROM PROGRAM (command execution)
- Untrusted procedural languages (code execution)
- pg_read_file / pg_write_file (file access)
- CREATE EXTENSION (load malicious extensions)
- Superuser escalation

### Oracle-Specific
- DBMS_SCHEDULER (job scheduling for persistence)
- UTL_FILE (file operations)
- DBMS_LOB (large object manipulation)
- Java stored procedures (code execution)
- TNS Listener attacks

### MongoDB-Specific
- NoSQL injection
- Authentication bypass
- Role manipulation
- JavaScript code execution (server-side)
- Backup database access

### Redis-Specific
- No authentication (common misconfiguration)
- CONFIG SET (modify configuration)
- EVAL (Lua script execution)
- Backup file manipulation
- Replication abuse

## Tags for Obsidian
#database-testing #sql #nosql #mssql #mysql #postgresql #oracle #mongodb #methodology #checklist

---
*Last Updated: 2026-01-22*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
