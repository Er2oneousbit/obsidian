# API Evidence Collection Guide

Systematic approach to capturing, organizing, and documenting evidence during API penetration testing. Proper evidence collection is critical for report writing and demonstrating impact to stakeholders.

Related: [[API-02-Technical-Testing-Checklist]] | [[API-03-Request-Tracker]] | [[API-05-Reporting-Template]]

---

## Evidence Collection Principles

### Why Evidence Matters
- **Proof of concept** - Demonstrates vulnerability exists
- **Reproducibility** - Allows client to verify and fix
- **Legal protection** - Documents authorized testing
- **Report quality** - Visual evidence > walls of text
- **Stakeholder communication** - Executives understand screenshots

### What to Capture
- **Before state** - Normal/expected behavior
- **Attack request** - Exact input sent (Burp screenshot)
- **After state** - Exploited/abnormal behavior
- **Context** - URL, timestamp, user account, HTTP method
- **Impact** - What data was accessed, what action occurred

### Quality Standards
- Screenshots must be **readable** (no tiny text)
- Include **full context** (URL, headers, status code)
- Show **complete request/response** when relevant
- Capture **error messages** verbatim
- Document **exact steps** to reproduce
- Include **cURL commands** for easy PoC

---

## File Naming Convention

**Format**: `[EngagementID]_[Category]_[FindingID]_[SequenceNumber]_[Description].png`

**Examples**:
- `ACME_BOLA_F001_01_Request-User-A-Token.png`
- `ACME_BOLA_F001_02_Response-User-B-Data.png`
- `ACME_SQLi_F003_01_Injection-Payload.png`
- `ACME_BizLogic_F005_01_Before-Balance.png`
- `ACME_BizLogic_F005_02_After-Balance.png`

**Benefits**:
- Sorts chronologically
- Groups by finding
- Self-documenting
- Easy to reference in report

---

## Screenshot Checklist

### Every Screenshot Should Include

- [ ] **Visible URL/endpoint** 
- [ ] **HTTP method** (GET, POST, PUT, DELETE, etc.)
- [ ] **Status code** (200, 401, 403, etc.)
- [ ] **Timestamp** (Burp shows this)
- [ ] **User account/token** (show who's authenticated)
- [ ] **Full request headers** (especially Authorization)
- [ ] **Request body** (if POST/PUT/PATCH)
- [ ] **Response body** (full JSON/XML response)
- [ ] **Readable text** (zoom if needed, use high DPI)

### Screenshots to ALWAYS Capture

- [ ] Initial API behavior (baseline)
- [ ] Attack request in Burp (full request)
- [ ] Attack response in Burp (full response)
- [ ] Successful exploitation result
- [ ] Any error messages or stack traces
- [ ] Privilege escalation proof (before/after)
- [ ] Data exfiltration proof (redacted if needed)
- [ ] Business impact (pricing changes, deleted data, etc)

---

## Evidence Categories

### Discovery & Enumeration

**Purpose**: Document API surface and versions

**Captures**:
- [ ] Swagger/OpenAPI specification
- [ ] Endpoint list (site map)
- [ ] Version endpoints (/api/v1, /api/v2, etc.)
- [ ] HTTP methods supported (OPTIONS response)
- [ ] Deprecated endpoints still active

**Naming**: `[Engagement]_Discovery_[Sequence]_[Description].png`

**Example**:
```
ACME_Discovery_01_Swagger-Spec.png
ACME_Discovery_02_Burp-Site-Map.png
ACME_Discovery_03_Old-API-v1-Active.png
```

---

### Authentication Testing

**Purpose**: Document authentication vulnerabilities

**Captures**:
- [ ] Username enumeration (different responses)
- [ ] Weak password acceptance
- [ ] JWT structure (decoded)
- [ ] JWT manipulation (before/after)
- [ ] Weak secret brute force
- [ ] Session token analysis
- [ ] API key leakage

**Critical Details**:
- Show timing differences (for username enum)
- Show full JWT (header, payload, signature)
- Show decoded JWT claims
- Capture both valid and invalid attempts

**Naming**: `[Engagement]_Auth_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Auth_F001_01_Username-Enum-Valid.png
ACME_Auth_F001_02_Username-Enum-Invalid.png
ACME_Auth_F002_01_JWT-Decoded.png
ACME_Auth_F002_02_JWT-Modified.png
ACME_Auth_F002_03_Access-Granted.png
```

**Reference**: Link to [[API-03-Request-Tracker|Request Tracker]] entry (e.g., RT-101)

---

### BOLA/IDOR Exploitation

**Purpose**: Show unauthorized access to other users' data

**Captures**:
- [ ] **Before**: User A's authentication (show token/session)
- [ ] **Request**: User A requesting User B's resource
- [ ] **Response**: User B's data returned
- [ ] **Impact**: What sensitive data was exposed

**Critical Details**:
- Clearly show User A's credentials/token
- Clearly show User B's ID in request
- Highlight sensitive data in response (PII, PHI, etc.)
- Show ownership (User A ≠ User B)

**Naming**: `[Engagement]_BOLA_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_BOLA_F001_01_User-A-Token.png
ACME_BOLA_F001_02_Request-User-B-ID.png
ACME_BOLA_F001_03_User-B-Data-Leaked.png
ACME_BOLA_F001_04_Burp-Full-Request.png
```

**Visual clarity**:
- Use Burp highlighter to mark User A token
- Use Burp highlighter to mark User B ID
- Circle/annotate PII in response

---

### SQL/NoSQL Injection

**Purpose**: Document injection vulnerabilities

**Captures**:
- [ ] Injection payload in request
- [ ] Error message revealing database info
- [ ] Successful data extraction
- [ ] Burp request/response
- [ ] SQLMap output (if used)

**Critical Details**:
- Show exact payload (single quotes, etc.)
- Capture full error messages (stack traces)
- Show database type/version if leaked
- Show extracted data (table names, columns, values)

**Naming**: `[Engagement]_SQLi_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_SQLi_F003_01_Injection-Payload.png
ACME_SQLi_F003_02_Database-Error.png
ACME_SQLi_F003_03_Data-Extraction.png
ACME_SQLi_F003_04_SQLMap-Output.png
```

---

### Mass Assignment

**Purpose**: Show unauthorized field manipulation

**Captures**:
- [ ] **Normal request**: Expected fields only
- [ ] **Modified request**: Added unauthorized fields
- [ ] **Response**: Unauthorized fields accepted
- [ ] **Verification**: New permissions/data confirmed

**Critical Details**:
- Highlight added fields in request
- Show fields accepted in response
- Demonstrate impact (admin role, verified status, etc.)

**Naming**: `[Engagement]_MassAssign_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_MassAssign_F004_01_Normal-Request.png
ACME_MassAssign_F004_02_Modified-Request-Added-Role.png
ACME_MassAssign_F004_03_Response-Role-Accepted.png
ACME_MassAssign_F004_04_Admin-Access-Verified.png
```

---

### Business Logic Flaws

**Purpose**: Demonstrate financial or workflow impact

**Captures**:
- [ ] **Before state**: Initial balance/price/status
- [ ] Exploitation request
- [ ] **After state**: Manipulated balance/price/status
- [ ] **Proof of impact**: Receipt, confirmation, audit log

**Critical Details**:
- Clear before/after comparison
- Dollar amounts visible (if financial)
- Order/transaction IDs shown
- Timestamps for sequence

**Naming**: `[Engagement]_BizLogic_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_BizLogic_F005_01_Balance-Before-$100.png
ACME_BizLogic_F005_02_Negative-Withdrawal-Request.png
ACME_BizLogic_F005_03_Balance-After-$200.png
ACME_BizLogic_F005_04_Transaction-Log.png
```

---

### Race Conditions

**Purpose**: Document concurrent request exploitation

**Captures**:
- [ ] Burp Turbo Intruder configuration
- [ ] Multiple simultaneous requests sent
- [ ] Multiple successful responses
- [ ] Impact (balance, inventory, etc.)

**Critical Details**:
- Show concurrency settings
- Show multiple responses with same timestamp
- Demonstrate double-spend or double-use
- Show final state (negative balance, oversold items, etc.)

**Naming**: `[Engagement]_RaceCondition_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_RaceCondition_F006_01_Turbo-Intruder-Config.png
ACME_RaceCondition_F006_02_Simultaneous-Requests.png
ACME_RaceCondition_F006_03_Multiple-Successes.png
ACME_RaceCondition_F006_04_Negative-Balance.png
```

---

### Information Disclosure

**Purpose**: Prove sensitive data leakage

**Captures**:
- [ ] Error messages with stack traces
- [ ] Excessive data in API responses
- [ ] PII/PHI exposed
- [ ] Internal fields leaked
- [ ] Version information disclosed

**Critical Details**:
- Highlight sensitive data in screenshot
- Redact real PII/PHI (use test data or blur)
- Show what shouldn't be visible
- Capture full response to show all leaked fields

**Naming**: `[Engagement]_InfoDisc_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_InfoDisc_F007_01_Stack-Trace.png
ACME_InfoDisc_F007_02_Excessive-Data-Response.png
ACME_InfoDisc_F007_03_PII-Leaked-REDACTED.png
```

**IMPORTANT**: Always redact real PII/PHI in evidence!

---

### SSRF

**Purpose**: Document server-side request forgery

**Captures**:
- [ ] SSRF payload in request
- [ ] Response showing internal data
- [ ] Cloud metadata exposure
- [ ] Internal service access

**Critical Details**:
- Show malicious URL in request
- Capture full response (metadata, credentials, etc.)
- Redact actual AWS keys if leaked
- Show internal network access

**Naming**: `[Engagement]_SSRF_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_SSRF_F008_01_AWS-Metadata-Request.png
ACME_SSRF_F008_02_Credentials-Leaked-REDACTED.png
ACME_SSRF_F008_03_Internal-Service-Access.png
```

---

### GraphQL-Specific

**Purpose**: Document GraphQL vulnerabilities

**Captures**:
- [ ] Introspection query
- [ ] Full schema revealed
- [ ] Batching/aliasing exploit
- [ ] Deep nested query DoS

**Critical Details**:
- Show introspection query and response
- Highlight hidden/admin types
- Show query complexity/depth
- Demonstrate performance impact

**Naming**: `[Engagement]_GraphQL_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_GraphQL_F009_01_Introspection-Query.png
ACME_GraphQL_F009_02_Full-Schema.png
ACME_GraphQL_F009_03_Admin-Type-Found.png
```

---

## Burp Suite Evidence

### What to Export from Burp

- [ ] **Full project file** (`.burp`)
- [ ] **Request/response for each finding** (Save Item)
- [ ] **Site map** showing scope
- [ ] **Proxy history** (filtered to target)
- [ ] **Intruder results** (parameter fuzzing)
- [ ] **Repeater tabs** (active exploits)

### Burp Screenshots

**Essential captures**:
- [ ] **Request tab**: Full request with headers and body
- [ ] **Response tab**: Full response
- [ ] **Headers tab**: All request/response headers
- [ ] **Params tab**: For parameter tampering
- [ ] **Repeater tab**: For PoC reproducibility
- [ ] **Intruder tab**: For fuzzing/brute force results

**Naming**: `[Engagement]_Burp_F[###]_[ReqResp]_[Description].png`

**Example**:
```
ACME_Burp_F001_Request_BOLA-Attempt.png
ACME_Burp_F001_Response_User-Data-Leaked.png
ACME_Burp_F003_Request_SQLi-Payload.png
ACME_Burp_F003_Response_Database-Error.png
```

### Exporting Requests/Responses

**In Burp**:
1. Right-click request → **Copy as cURL command**
2. Right-click request → **Save item**

**Save as**:
- `[Engagement]_Burp_F[###]_Request.txt`
- `[Engagement]_Burp_F[###]_Response.txt`
- `[Engagement]_Burp_F[###]_curl.sh`

**Example cURL export**:
```bash
curl -X GET 'https://api.target.com/api/users/101/profile' \
  -H 'Authorization: Bearer eyJhbGc...' \
  -H 'Content-Type: application/json'
```

---

## cURL Command Documentation

For every finding, document reproducible cURL command:

### BOLA Example
```bash
# RT-301: BOLA on user profile endpoint

# User A token (ID: 100)
TOKEN_A="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Request User B's profile (ID: 101) with User A's token
curl -X GET 'https://api.target.com/api/users/101/profile' \
  -H "Authorization: Bearer $TOKEN_A" \
  -H 'Content-Type: application/json' \
  -v

# Expected: 403 Forbidden
# Actual: 200 OK with User 101's PII
```

### SQL Injection Example
```bash
# RT-501: SQL injection on search parameter

curl -X GET 'https://api.target.com/api/products?search=%27+OR+%271%27%3D%271' \
  -H 'Content-Type: application/json' \
  -v

# Payload decoded: ' OR '1'='1
# Result: Returns all products including hidden ones
```

### Mass Assignment Example
```bash
# RT-401: Mass assignment on user registration

curl -X POST 'https://api.target.com/api/users/register' \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password123!",
    "role": "admin"
  }' \
  -v

# Result: Account created with admin role
```

---

## Postman Collections

### When to Create Postman Collection

- [ ] Complex multi-step exploits
- [ ] For client to reproduce findings
- [ ] Automated testing workflows
- [ ] Demonstration purposes

### Collection Structure

```
ACME API Pentest - Findings
├── F001 - BOLA
│   ├── 1. User A - Get own profile (baseline)
│   ├── 2. User A - Get User B profile (BOLA)
│   └── 3. Verification - User B token
├── F002 - JWT Manipulation
│   ├── 1. Original JWT
│   ├── 2. Modified JWT (changed sub)
│   └── 3. Admin access with modified JWT
└── F003 - SQL Injection
    ├── 1. Normal search
    └── 2. SQLi payload
```

**Export as**:
- `[Engagement]_Findings_Collection.json`

---

## Evidence Organization

### Directory Structure

```
[Engagement-Name]-Evidence/
├── 01-Discovery/
│   ├── ACME_Discovery_01_Swagger.png
│   ├── ACME_Discovery_02_Site-Map.png
│   └── ACME_Discovery_03_Old-Version.png
├── 02-Findings/
│   ├── F001-BOLA/
│   │   ├── ACME_BOLA_F001_01_Request.png
│   │   ├── ACME_BOLA_F001_02_Response.png
│   │   ├── ACME_Burp_F001_Request.txt
│   │   ├── ACME_Burp_F001_Response.txt
│   │   └── ACME_F001_curl.sh
│   ├── F002-JWT/
│   │   ├── ACME_Auth_F002_01_Original-JWT.png
│   │   ├── ACME_Auth_F002_02_Modified-JWT.png
│   │   └── ACME_Auth_F002_03_Admin-Access.png
│   └── F003-SQLi/
│       ├── screenshots...
│       └── exploitation scripts...
├── 03-Burp/
│   ├── ACME_API_Project.burp
│   └── exported-items/
├── 04-Postman/
│   └── ACME_Findings_Collection.json
├── 05-Scripts/
│   ├── bola_test.py
│   ├── jwt_brute.py
│   └── race_condition.py
└── 06-Notes/
    ├── API-03-Request-Tracker.md
    └── testing-notes.txt
```

---

## Evidence Tracking Table

Use this table to track all evidence collected:

| Finding ID | Finding Name | Evidence Type | Filename(s) | Date Captured | RT Reference |
|-----------|-------------|--------------|-------------|---------------|-------------|
| F001 | BOLA - User Profile | Screenshots (3) | ACME_BOLA_F001_*.png | 2026-01-21 | RT-301 |
| F001 | BOLA - User Profile | Burp Export | ACME_Burp_F001_*.txt | 2026-01-21 | RT-301 |
| F001 | BOLA - User Profile | cURL | ACME_F001_curl.sh | 2026-01-21 | RT-301 |
| F002 | JWT Manipulation | Screenshots (3) | ACME_Auth_F002_*.png | 2026-01-21 | RT-202 |
| F003 | SQL Injection | Screenshots (4) | ACME_SQLi_F003_*.png | 2026-01-21 | RT-501 |
| F003 | SQL Injection | SQLMap Output | sqlmap_output.txt | 2026-01-21 | RT-501 |
| | | | | | |

---

## Evidence Quality Checklist

Before finalizing evidence collection:

### Completeness
- [ ] Every finding has 2-3 screenshots minimum
- [ ] Critical findings have Burp exports
- [ ] cURL commands documented for all findings
- [ ] All evidence named consistently
- [ ] Directory structure organized
- [ ] Request Tracker references complete

### Quality
- [ ] All text is readable (adequate zoom)
- [ ] Context is clear (URLs, methods, status codes visible)
- [ ] Before/after states captured
- [ ] No extraneous desktop clutter
- [ ] Sensitive data redacted appropriately
- [ ] Timestamps visible

### Documentation
- [ ] Evidence tracking table populated
- [ ] Each file referenced in [[API-03-Request-Tracker]]
- [ ] Findings mapped to evidence in [[API-05-Reporting-Template]]
- [ ] cURL commands tested and working
- [ ] Testing timeline documented

---

## Tools for Evidence Collection

### Screenshot Tools
- **Windows**: Snipping Tool, ShareX, Greenshot
- **Linux**: Flameshot, Spectacle, GNOME Screenshot
- **macOS**: Command+Shift+4, Skitch

### Burp Extensions
- **Logger++**: Enhanced logging with better filtering
- **Copy as cURL**: Easy cURL export
- **Turbo Intruder**: Race condition testing
- **Autorize**: Automatic authorization testing

### API Tools
- **Postman**: Collection creation, automated testing
- **Insomnia**: Alternative to Postman
- **jwt.io**: JWT decoding/encoding
- **jwt_tool**: JWT exploitation

### Scripting
- **Python requests**: Custom PoC scripts
- **curl**: Quick one-liner exploits
- **jq**: JSON parsing and formatting

---

## Tips for High-Quality Evidence

### Do
✅ Capture full request with headers (Authorization!)
✅ Capture full response body
✅ Use high DPI/resolution
✅ Number sequences for multi-step attacks
✅ Annotate screenshots to highlight key details
✅ Include cURL commands
✅ Test reproducibility before finalizing

### Don't
❌ Crop out URLs, headers, status codes
❌ Use low-quality screenshots
❌ Mix evidence from different findings
❌ Forget to export Burp project
❌ Leave real PII/credentials unredacted
❌ Assume you'll remember context later

---

## Evidence Handoff Checklist

Before delivering evidence to client:

- [ ] All evidence organized per directory structure
- [ ] Sensitive data redacted (PII, real credentials)
- [ ] Evidence tracking table complete
- [ ] Burp project file included
- [ ] cURL commands documented
- [ ] Postman collection included (if created)
- [ ] README.txt with instructions
- [ ] Evidence package encrypted (7z with password)
- [ ] Password delivered via separate channel
- [ ] Client confirms receipt

---

## Tags
#evidence #screenshots #documentation #api-testing #burp

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]
- [[API-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
