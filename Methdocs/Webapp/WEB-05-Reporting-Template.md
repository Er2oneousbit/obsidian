# Web Application Penetration Test Reporting Template

Standardized format for documenting findings from web application security assessments. Use this template to ensure consistent, high-quality reporting across engagements.

Related: [[WEB-02-Technical-Testing-Checklist]] | [[WEB-03-Request-Tracker]] | [[WEB-04-Evidence-Collection]]

---

## Report Structure

1. Executive Summary
2. Assessment Overview
3. Findings Summary
4. Detailed Findings
5. Recommendations
6. Appendices

---

## Executive Summary

**Purpose**: High-level overview for non-technical stakeholders (C-suite, business owners)

**Length**: 1-2 pages max

**Include**:
- Testing scope and objectives
- Key findings (Critical/High only)
- Overall risk rating
- Business impact summary
- Top 3-5 recommendations

**Tone**: Business-focused, avoid technical jargon

### Executive Summary Template

```
EXECUTIVE SUMMARY

[Client Name] engaged [Your Company] to conduct a security assessment of their web 
application "[Application Name]" from [Start Date] to [End Date]. The assessment 
identified [X] security vulnerabilities, including [Y] Critical and [Z] High 
severity findings.

KEY FINDINGS:
The most significant security risks identified include:

1. SQL Injection - Attackers can extract sensitive data from the database including 
   usernames, passwords, and customer information.
   
2. Broken Access Control (IDOR) - Users can access other users' data by manipulating 
   ID parameters in URLs, exposing personal and financial information.
   
3. Stored Cross-Site Scripting - Attackers can inject malicious JavaScript that 
   executes in other users' browsers, enabling session hijacking and phishing.

BUSINESS IMPACT:
These vulnerabilities could result in:
- Data breach exposing customer PII/PHI (estimated XX,XXX records)
- Regulatory non-compliance (GDPR, HIPAA, PCI-DSS)
- Financial fraud through business logic manipulation
- Reputational damage and loss of customer trust
- Potential legal liability

RECOMMENDATIONS:
Immediate action items to reduce risk:
1. Implement parameterized queries to prevent SQL injection
2. Add server-side authorization checks for all user-specific resources
3. Implement context-aware output encoding to prevent XSS
4. Enable HttpOnly and Secure flags on session cookies
5. Conduct security training for development team

OVERALL RISK RATING: [CRITICAL / HIGH / MEDIUM]

A detailed breakdown of findings and remediation guidance follows in this report.
```

---

## Assessment Overview

### Engagement Details

| Field | Value |
|-------|-------|
| **Client** | [Company Name] |
| **Application Tested** | [App Name/Version] |
| **Assessment Type** | Black Box / Gray Box / White Box |
| **Testing Period** | [Start Date] - [End Date] |
| **Total Effort** | [X hours] |
| **Tester(s)** | [Name(s)] |
| **Report Date** | [Date] |
| **Report Version** | [v1.0] |

### Scope

**In Scope**:
- [URL/domain 1]
- [URL/domain 2]
- [Specific functionality]

**Out of Scope**:
- [Excluded component 1]
- [Excluded component 2]

### Testing Methodology

The assessment followed the OWASP Testing Guide and included:

1. **Reconnaissance** - Mapped application structure and identified entry points
2. **Authentication Testing** - Evaluated credential policies and session management
3. **Authorization Testing** - Tested access control and privilege escalation
4. **Input Validation** - Tested for injection vulnerabilities (SQL, XSS, Command)
5. **Business Logic** - Assessed workflow manipulation and race conditions
6. **Session Management** - Analyzed cookie security and session handling
7. **File Upload** - Tested for unrestricted upload and path traversal
8. **Client-Side** - Evaluated JavaScript security and DOM-based issues

Reference: [[WEB-02-Technical-Testing-Checklist]]

### Testing Constraints

**Limitations**:
- [e.g., Testing limited to staging environment]
- [e.g., Rate limiting restricted brute force testing]

**Assumptions**:
- [e.g., Testing reflects production configuration]

---

## Findings Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | X | XX% |
| High | X | XX% |
| Medium | X | XX% |
| Low | X | XX% |
| Informational | X | XX% |
| **Total** | **X** | **100%** |

### Findings by Category

| Category | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| Injection (SQLi/XSS/Cmd) | X | X | X | X | X | X |
| Broken Access Control | X | X | X | X | X | X |
| Authentication | X | X | X | X | X | X |
| Session Management | X | X | X | X | X | X |
| Business Logic | X | X | X | X | X | X |
| Configuration | X | X | X | X | X | X |
| **Total** | **X** | **X** | **X** | **X** | **X** | **X** |

### OWASP Top 10 Mapping

| OWASP Category | Findings | Severity |
|----------------|----------|----------|
| A01: Broken Access Control | F001, F002 | Critical, High |
| A03: Injection | F003, F005, F007 | Critical |
| A04: Insecure Design | F008 | Critical |
| A05: Security Misconfiguration | F010 | Medium |
| A07: Authentication Failures | F004, F006 | High |
| [etc.] | | |

---

## Detailed Finding Template

Use this template for each finding.

---

### [F-XXX] Finding Title

**Severity**: Critical / High / Medium / Low / Informational

**Category**: [Injection / Access Control / Authentication / etc.]

**OWASP**: [A01 / A03 / etc.]

**Status**: Open / In Progress / Remediated

**Affected URLs**:
- `https://target.com/vulnerable/endpoint`
- `https://target.com/another/page`

---

#### Description

[Clear, concise description of the vulnerability. What is the issue?]

---

#### Impact

**Technical Impact**:
- [Specific technical consequence 1]
- [Specific technical consequence 2]

**Business Impact**:
- [Business risk 1]
- [Business risk 2]

---

#### Evidence

**Screenshots**: (Reference [[WEB-04-Evidence-Collection]])
- `ACME_Category_F###_01_Description.png`
- `ACME_Category_F###_02_Description.png`

**Request Tracker**: [[WEB-03-Request-Tracker#RT-XXX]]

---

#### Proof of Concept

**Step-by-step reproduction**:

1. Navigate to `https://target.com/vulnerable/page`
2. Enter payload: `[exact payload]`
3. Submit form / Send request
4. Observe result: `[what happens]`

**HTTP Request** (from Burp):
```http
POST /vulnerable HTTP/1.1
Host: target.com
Cookie: session=abc123

param=malicious_payload
```

**Expected Result**: [what should happen - error, rejection]

**Actual Result**: [what actually happens - exploitation]

**Reproducibility**: [100% / 80% / etc.]

---

#### Root Cause

[Technical explanation of why the vulnerability exists]

Example: "The application directly concatenates user input into SQL queries without 
using parameterized statements or input validation, allowing attackers to inject 
arbitrary SQL commands."

---

#### Risk Rating Justification

**CVSS v3.1 Score**: [X.X] ([Severity])

**Vector String**: `CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]`

**Justification**:
- Attack Vector: [Network / Adjacent / Local]
- Attack Complexity: [Low / High]
- Privileges Required: [None / Low / High]
- User Interaction: [None / Required]
- Confidentiality Impact: [High / Low / None]
- Integrity Impact: [High / Low / None]
- Availability Impact: [High / Low / None]

---

#### Recommendations

**Immediate Mitigation** (Short-term):
1. [Quick fix or workaround]
2. [Disable feature temporarily if critical]

**Permanent Remediation** (Long-term):
1. [Code-level fix with example]
2. [Architectural change if needed]
3. [Process improvement]

**Code Example** (if applicable):
```php
// Vulnerable code:
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// Secure code:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
```

---

#### References

- [OWASP Link]
- [CWE Link]
- [Relevant blog post or documentation]

---

## Sample Findings

### [F-001] SQL Injection in Search Functionality

**Severity**: Critical

**Category**: Injection

**OWASP**: A03:2021

**Affected URLs**:
- `https://target.com/search?q=[injection]`

#### Description

The search functionality is vulnerable to SQL injection. User-supplied input in the 
`q` parameter is directly concatenated into SQL queries without proper sanitization 
or parameterization, allowing attackers to execute arbitrary SQL commands.

#### Impact

**Technical Impact**:
- Full database compromise (read, modify, delete)
- Extraction of sensitive data (usernames, passwords, customer info)
- Potential operating system command execution via SQL features

**Business Impact**:
- Data breach affecting [X] customer records
- Regulatory penalties (GDPR fines up to €20M or 4% of revenue)
- Reputational damage and loss of customer trust
- Potential legal liability

#### Evidence

**Screenshots**:
- `ACME_SQLi_F001_01_Injection-Payload.png`
- `ACME_SQLi_F001_02_Database-Error.png`
- `ACME_SQLi_F001_03_Data-Extracted.png`

**Request Tracker**: [[WEB-03-Request-Tracker#RT-401]]

#### Proof of Concept

**Detection**:
```
1. Navigate to https://target.com/search?q=test
2. Modify URL: https://target.com/search?q=test' OR '1'='1
3. All products are returned (including hidden/deleted items)
```

**Data Extraction**:
```
1. URL: https://target.com/search?q=test' UNION SELECT NULL,@@version,NULL--
2. Response shows: "MySQL 5.7.33"
3. Extract database names:
   q=test' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
4. Extract table names:
   q=test' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='app_db'--
5. Extract user credentials:
   q=test' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--
```

**Root Cause**

The application constructs SQL queries by directly concatenating user input:
```php
$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'";
```

#### Risk Rating

**CVSS v3.1 Score**: 9.8 (Critical)

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

#### Recommendations

**Immediate**:
1. Disable search functionality until fixed
2. Implement WAF rules to block SQL injection patterns

**Permanent**:
1. Use parameterized queries (prepared statements)
2. Implement input validation (whitelist allowed characters)
3. Apply principle of least privilege to database user
4. Enable database query logging and monitoring

**Secure Code Example**:
```php
// Use PDO prepared statements
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :search");
$stmt->execute(['search' => '%' . $search . '%']);
$results = $stmt->fetchAll();
```

#### References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

---

### [F-002] Broken Object Level Authorization (IDOR)

**Severity**: High

**Category**: Broken Access Control

**OWASP**: A01:2021

**Affected URLs**:
- `https://target.com/user/profile?id=[user_id]`
- `https://target.com/documents/download?file_id=[id]`
- `https://target.com/api/orders/[order_id]`

#### Description

The application does not verify that the authenticated user is authorized to access 
the requested resource. By manipulating ID parameters, any authenticated user can 
access other users' profiles, documents, and orders.

#### Impact

**Technical Impact**:
- Horizontal privilege escalation
- Unauthorized access to PII/PHI
- Data exfiltration at scale

**Business Impact**:
- Privacy breach affecting all [X] users
- HIPAA violation (if PHI exposed)
- Loss of customer trust
- Potential class-action lawsuit

#### Proof of Concept

```
User A credentials:
- ID: 100
- Session: abc123...

1. User A accesses own profile:
   GET /user/profile?id=100
   Response: User A's data (expected)

2. User A modifies ID to access User B:
   GET /user/profile?id=101
   Response: User B's data including:
   - Full name
   - Email
   - Phone number  
   - Address
   - SSN (last 4 digits)
   - Medical history (if healthcare app)

3. Automated enumeration:
   for id in range(1, 10000):
       access /user/profile?id={id}
   Result: Extracted data for all 9,999 users
```

#### Recommendations

**Immediate**:
1. Add authorization check: `if (profile.user_id != session.user_id) deny()`

**Permanent**:
1. Implement server-side authorization for all resources
2. Use indirect references (e.g., UUID instead of sequential IDs)
3. Implement authorization framework (e.g., RBAC)
4. Audit all endpoints for proper access control

**Secure Code Example**:
```php
// Add authorization check
$profile_id = $_GET['id'];
$current_user_id = $_SESSION['user_id'];

// Check ownership
if ($profile_id != $current_user_id) {
    http_response_code(403);
    die("Access denied");
}

// Proceed with data retrieval
$profile = get_profile($profile_id);
```

---

## Strategic Recommendations

### 1. Implement Secure Development Lifecycle

- Integrate security into SDLC (threat modeling, secure code review)
- Use SAST/DAST tools in CI/CD pipeline
- Require security sign-off before production deployment

### 2. Adopt Security Frameworks

- OWASP Application Security Verification Standard (ASVS)
- OWASP Top 10 as minimum baseline
- Framework-specific security best practices (e.g., Django Security, ASP.NET Security)

### 3. Security Training

- Mandatory secure coding training for all developers
- Regular security awareness training
- Hands-on workshops (e.g., OWASP WebGoat, Damn Vulnerable Web Application)

### 4. Defense in Depth

**Application Layer**:
- Input validation (whitelist approach)
- Output encoding (context-aware)
- Parameterized queries
- Security headers (CSP, HSTS, etc.)

**Infrastructure Layer**:
- Web Application Firewall (WAF)
- Intrusion Detection/Prevention System (IDS/IPS)
- DDoS protection
- Regular patching and updates

**Monitoring & Response**:
- Centralized logging (SIEM)
- Real-time alerting on suspicious activity
- Incident response plan
- Regular security assessments

---

## Appendices

### Appendix A: Testing Methodology Detail

Full reference: [[WEB-02-Technical-Testing-Checklist]]

### Appendix B: Request Tracker

Full reference: [[WEB-03-Request-Tracker]]

### Appendix C: Evidence Archive

All screenshots and Burp exports: [[WEB-04-Evidence-Collection]]

### Appendix D: OWASP Top 10 (2021)

| ID | Category | Description |
|----|----------|-------------|
| A01 | Broken Access Control | Authorization flaws, IDOR |
| A02 | Cryptographic Failures | Weak encryption, plaintext data |
| A03 | Injection | SQL, XSS, Command injection |
| A04 | Insecure Design | Business logic flaws |
| A05 | Security Misconfiguration | Default configs, verbose errors |
| A06 | Vulnerable Components | Outdated libraries, known CVEs |
| A07 | Authentication Failures | Weak passwords, session issues |
| A08 | Data Integrity Failures | Insecure deserialization |
| A09 | Logging Failures | Insufficient monitoring |
| A10 | SSRF | Server-side request forgery |

---

## Tags
#reporting #findings #documentation #web-testing #pentest-report

---

## Related Documents
- [[WEB-00-Overview|Overview]]
- [[WEB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[WEB-03-Request-Tracker|Request Tracker]]
- [[WEB-04-Evidence-Collection|Evidence Collection]]
- [[WEB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
