# sqlite3

**Tags:** `#sqlite3` `#sqlite` `#database` `#postexploitation` `#credentialdumping` `#browsers` `#webapps`

SQLite CLI client — reads and queries `.db`, `.sqlite`, `.sqlite3` files found on compromised hosts. SQLite is embedded everywhere: browser credential stores (Firefox, Chrome), web application databases, mobile apps, password managers, configuration databases, and more. No server required — single file, access it directly.

**Source:** Pre-installed on Kali and most Linux distros
**Install:** `sudo apt install sqlite3`

```bash
# Open a SQLite database
sqlite3 /path/to/database.db

# Run a query directly
sqlite3 database.db "SELECT * FROM users;"
```

---

## Common SQLite Database Locations

```bash
# Firefox saved passwords
~/.mozilla/firefox/*.default*/logins.json    # JSON (not SQLite)
~/.mozilla/firefox/*.default*/key4.db        # SQLite — master password / key material
~/.mozilla/firefox/*.default*/places.sqlite  # History, bookmarks

# Chrome / Chromium saved passwords (Linux)
~/.config/google-chrome/Default/Login\ Data  # SQLite
~/.config/chromium/Default/Login\ Data

# Chrome cookies
~/.config/google-chrome/Default/Cookies

# Windows Chrome (on exfilled file)
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies

# Windows Firefox
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\key4.db

# KeePass (not SQLite but common find)
*.kdbx

# Web application databases
/var/www/html/*.db
/var/www/html/*.sqlite
/opt/app/*.db
~/app/database.sqlite

# Android (if analysing APK/device)
/data/data/<package>/databases/*.db
```

---

## Basic Usage

```bash
# Open database (interactive shell)
sqlite3 database.db

# Run query inline (non-interactive)
sqlite3 database.db "SELECT * FROM users;"

# Output as CSV
sqlite3 -csv database.db "SELECT * FROM users;"

# Output with headers
sqlite3 -header database.db "SELECT * FROM users;"

# Both headers and CSV
sqlite3 -header -csv database.db "SELECT * FROM users;" > output.csv

# Run SQL from file
sqlite3 database.db < queries.sql
```

---

## Schema Reconnaissance

```sql
-- List all tables
.tables

-- Show schema for all tables
.schema

-- Schema for specific table
.schema users

-- Table info (columns, types)
PRAGMA table_info(users);

-- List all indexes
.indexes

-- Database file info
PRAGMA database_list;

-- Check for attached databases
PRAGMA database_list;
```

---

## Data Extraction

```sql
-- Dump all rows from a table
SELECT * FROM users;

-- Specific columns
SELECT username, password, email FROM users;

-- Find admin users
SELECT * FROM users WHERE role='admin' OR is_admin=1;

-- Count rows
SELECT COUNT(*) FROM users;

-- Search for keyword in any text column
SELECT * FROM users WHERE username LIKE '%admin%' OR email LIKE '%admin%';

-- All tables one-liner (run from shell)
sqlite3 database.db ".tables" | tr ' ' '\n' | while read t; do
    echo "=== $t ==="; sqlite3 database.db "SELECT * FROM $t LIMIT 20;"; done
```

---

## Browser Credential Extraction

### Chrome / Chromium Login Data

```bash
# Copy Login Data (may be locked if Chrome is open)
cp ~/.config/google-chrome/Default/Login\ Data /tmp/chrome_logins.db

sqlite3 /tmp/chrome_logins.db "SELECT origin_url, username_value, password_value FROM logins;"
```

> [!note] Chrome passwords are DPAPI-encrypted on Windows and uses a local key on Linux (stored in `Local State`). Raw `password_value` from SQLite is encrypted bytes — use [SharpChrome](../Credential%20Dumping/SharpDPAPI.md) on Windows or [LaZagne](../Credential%20Dumping/LaZagne.md) on Linux for decrypted output.

```bash
# Chrome cookies
sqlite3 ~/.config/google-chrome/Default/Cookies \
  "SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%target.com%';"

# Chrome history (useful for recon — reveals internal URLs, apps)
sqlite3 ~/.config/google-chrome/Default/History \
  "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 50;"
```

### Firefox key4.db

```bash
# Firefox uses key4.db for key material — use firefox_decrypt or LaZagne
# key4.db alone doesn't give plaintext — needs logins.json + master password

sqlite3 ~/.mozilla/firefox/*.default*/key4.db ".tables"
sqlite3 ~/.mozilla/firefox/*.default*/key4.db "SELECT * FROM metadata;"
```

---

## Web App Database Patterns

```bash
# Find all SQLite databases on the system
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v proc

# Common web app patterns
sqlite3 app.db ".tables"

# Django default
sqlite3 db.sqlite3 "SELECT username, password FROM auth_user;"

# Flask/SQLAlchemy common pattern
sqlite3 app.db "SELECT * FROM user;"

# Ruby on Rails development DB
sqlite3 db/development.sqlite3 "SELECT * FROM users;"

# Password manager databases
sqlite3 ~/.local/share/keyrings/*.keystore ".tables" 2>/dev/null
```

---

## Modifying Data (Post-Exploitation)

```sql
-- Add a new admin user (if app uses SQLite and you control the file)
INSERT INTO users (username, password, role) VALUES ('hacker', 'hashed_pw', 'admin');

-- Change existing user password
UPDATE users SET password='new_hash' WHERE username='admin';

-- Elevate privilege
UPDATE users SET is_admin=1 WHERE username='lowpriv';

-- Commit (SQLite auto-commits but explicit in transaction)
-- No COMMIT needed outside transactions in SQLite
```

---

## sqlite3 Shell Commands

```
.tables              -- list all tables
.schema [table]      -- show CREATE statements
.headers on/off      -- toggle column headers
.mode column         -- aligned column output
.mode csv            -- CSV output
.output file.txt     -- redirect output to file
.output stdout       -- back to stdout
.read file.sql       -- execute SQL file
.dump                -- dump entire DB as SQL
.dump tablename      -- dump specific table
.quit / .exit        -- exit
```

---

## Dump Entire Database as SQL

```bash
# Full SQL dump (portable — can be imported anywhere)
sqlite3 database.db .dump > database_dump.sql

# Dump specific table
sqlite3 database.db ".dump users" > users_dump.sql

# Restore from dump
sqlite3 new_database.db < database_dump.sql
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
