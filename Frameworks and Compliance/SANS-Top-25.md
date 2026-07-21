# SANS Top 25 Software Security Errors

#SANS #CWE #Weaknesses #VulnClassification #SecureCoding

## What is this?

**SANS Top 25 Most Dangerous Software Security Errors** — Developer-framed view of the 25 most common, dangerous software weaknesses. Emphasis on practical, real-world threats; ranked by prevalence and severity.

> [!note]
> **The "SANS Top 25" and the [[CWE-Top-25]] are the same lineage.** It began as the joint *CWE/SANS Top 25*; today the ranking is maintained by MITRE with CISA as the **CWE Top 25**, and SANS republishes that list rather than producing a separate one. Use [[CWE-Top-25]] for the current ranked list and formal CWE IDs; treat this note as the practical, developer-oriented companion.

---

## Overview

**SANS Top 25 Basics:**
- **Purpose**: Raise awareness of critical software vulnerabilities; guide developer training.
- **Data Source**: Incident response data, penetration testing results, vulnerability databases.
- **Audience**: Developers, security engineers, DevOps, CISOs.

**Relationship to CWE Top 25** (same lineage — see note above):
- **[[CWE-Top-25]]** = the authoritative ranked list with formal CWE IDs.
- **This note** = the same weaknesses framed as practical developer errors.

**Note**: SANS Top 25 and CWE Top 25 overlap significantly but have different emphasis. SANS is slightly broader (includes architecture, deployment issues).

---

## SANS Top 25 (By Category)

### Rank 1–4: Insecure Coding Practices

#### 1. Cross-Site Scripting (XSS)

**SANS Perspective**: Attacker injects malicious scripts; browser executes them. Most common web app vulnerability.

**Common Mistakes**:
- Not validating input (trusting user data).
- Not encoding output (assuming data is safe).
- Trusting third-party libraries (including vulnerable code).

**Prevention**:
- Input validation (whitelist safe input).
- Output encoding (context-specific: HTML, JavaScript, URL).
- Content Security Policy (CSP headers).
- Security headers (X-Frame-Options, X-Content-Type-Options).

---

#### 2. SQL Injection

**SANS Perspective**: Attacker modifies SQL queries; gains unauthorized database access or data theft.

**Common Mistakes**:
- String concatenation in queries (not parameterized).
- Insufficient input validation.
- Trusting client-side validation.

**Prevention**:
- Parameterized queries (prepared statements).
- Input validation (whitelist).
- Principle of least privilege (database users).
- Web Application Firewall (WAF).

---

#### 3. OS Command Injection

**SANS Perspective**: Attacker injects OS commands; achieves remote code execution.

**Common Mistakes**:
- Using shell=True in subprocess calls (Python).
- String interpolation in commands.
- Not validating input before command execution.

**Prevention**:
- Avoid OS command execution (use APIs instead).
- Use subprocess with list of arguments (not shell=True).
- Input validation (whitelist commands, arguments).

---

#### 4. Buffer Overflows

**SANS Perspective**: Attacker overwrites buffer; corrupts memory, crashes program, or achieves RCE.

**Common Mistakes** (C/C++):
- Not checking buffer size (strcpy, gets, scanf without bounds).
- Off-by-one errors.
- Integer overflows leading to buffer issues.

**Prevention**:
- Use safe functions (strncpy, strlcpy).
- Bounds checking (verify size before writing).
- Memory-safe languages (Java, Python, Rust).
- AddressSanitizer (detect at runtime).

---

### Rank 5–8: Authentication & Access Control

#### 5. Broken Access Control

**SANS Perspective**: Users access resources they shouldn't. Horizontal (other users' data) or vertical (privilege escalation).

**Common Mistakes**:
- No authorization checks (trusting client-side validation).
- Predictable IDs (sequential user IDs).
- No separation of duties.

**Prevention**:
- Always check authorization (user owns resource).
- Use unpredictable IDs (UUIDs).
- Separation of duties (no single person controls everything).
- Role-based access control (RBAC).

---

#### 6. Broken Authentication

**SANS Perspective**: Weak authentication; attacker impersonates users.

**Common Mistakes**:
- No MFA (easy to compromise single factor).
- Weak password policy.
- Session management flaws (tokens never expire).
- Hardcoded credentials.

**Prevention**:
- MFA required (especially for sensitive accounts).
- Strong password policy (12+ chars, entropy check).
- Short-lived tokens (15–60 min); refresh tokens.
- Secure session management (HTTPOnly cookies, SameSite flags).

---

#### 7. Weak Cryptography

**SANS Perspective**: Using broken/outdated cryptographic algorithms; data easily decrypted.

**Common Mistakes**:
- Using MD5, SHA1 for passwords (too fast; brute-forceable).
- Using DES for encryption (too weak).
- Using ECB mode (patterns visible in ciphertext).
- Hardcoded encryption keys.

**Prevention**:
- Hash passwords with bcrypt, Argon2 (slow, resistant to brute force).
- Encrypt with AES-256 (strong, NIST-approved).
- Use CBC, GCM mode (not ECB).
- Store keys securely (HSM, key management system).

---

#### 8. Insecure Direct Object References (IDOR)

**SANS Perspective**: Similar to Broken Access Control; attacker changes object ID to access other users' data.

**Common Mistakes**:
- Sequential IDs (/user/123 → /user/456).
- No authorization check.
- Trusting client-side validation.

**Prevention**:
- Always check authorization.
- Use unpredictable IDs (UUIDs).
- Don't trust client-side validation.

---

### Rank 9–12: Data & Information Security

#### 9. Sensitive Data Exposure

**SANS Perspective**: Sensitive data (credentials, PII, health records) exposed due to weak encryption or storage.

**Common Mistakes**:
- Storing plaintext passwords (never hash).
- Unencrypted data at rest (database breach = full data loss).
- Unencrypted data in transit (MITM attack).
- Logging sensitive data (logs become liability).

**Prevention**:
- Encrypt sensitive data (at rest, in transit).
- Hash passwords (bcrypt, Argon2).
- Classify data (what needs encryption?).
- Purge sensitive data (retention policy; delete when no longer needed).

---

#### 10. Insufficient Logging & Monitoring

**SANS Perspective**: No audit trail; breaches go undetected for months.

**Common Mistakes**:
- No logging (can't investigate).
- Logging but not monitoring (nobody looks at logs).
- Logs not retained (evidence destroyed).
- Logs stored on compromised system (attacker deletes them).

**Prevention**:
- Comprehensive logging (all security-relevant events).
- Centralized logging (SIEM; not just local logs).
- Real-time alerting (anomalies detected immediately).
- Log retention (1–7 years; compliance may require longer).

---

#### 11. Improper Input Validation

**SANS Perspective**: Application doesn't validate input; attacker injects malicious data.

**Common Mistakes**:
- Blacklist approach (block known-bad; easy to bypass).
- Client-side validation only (server accepts any input).
- No length checks (buffer overflow).
- No type checks (SQL injection, command injection).

**Prevention**:
- Whitelist validation (only allow known-good values).
- Server-side validation (never trust client).
- Bounds checking (max length, valid characters).
- Type checking (input must be expected type).

---

#### 12. Missing Encryption

**SANS Perspective**: Sensitive data transmitted/stored without encryption.

**Common Mistakes**:
- HTTP instead of HTTPS.
- Plaintext passwords in email.
- Unencrypted backups.
- Unencrypted database fields.

**Prevention**:
- HTTPS only (TLS 1.2+).
- Encrypt sensitive data (at rest, in transit).
- Encrypted backups.
- Full-disk encryption on endpoints.

---

### Rank 13–16: Software Development Process

#### 13. Unvalidated Redirects & Forwards

**SANS Perspective**: Application redirects to attacker-controlled URL; phishing vector.

**Common Mistakes**:
- Redirect to user-supplied URL (not validated).
- Trusting referer header.

**Prevention**:
- Whitelist allowed redirect URLs.
- Validate redirect targets.
- Don't allow open redirects.

---

#### 14. Insecure Deserialization

**SANS Perspective**: Application deserializes untrusted data; attacker achieves RCE.

**Common Mistakes**:
- Using pickle in Python (deserialize untrusted data).
- Using Java serialization (ObjectInputStream).
- No validation of serialized objects.

**Prevention**:
- Avoid deserialization of untrusted data.
- Use JSON (safer than binary serialization).
- Validate deserialized objects.
- Sandboxing (run untrusted deserialization in isolated container).

---

#### 15. Using Components with Known Vulnerabilities

**SANS Perspective**: Using outdated libraries with known vulnerabilities; attacker exploits them.

**Common Mistakes**:
- No dependency tracking.
- Never updating libraries.
- Ignoring security patches.

**Prevention**:
- Dependency scanning (OWASP Dependency-Check, Snyk, npm audit).
- Regular updates (patch critical within 2 weeks).
- Automated scanning (CI/CD pipeline).
- Lock file pinning (know exactly which versions deployed).

---

#### 16. Failure to Restrict URL Access

**SANS Perspective**: Admin/sensitive endpoints accessible without authentication.

**Common Mistakes**:
- Hiding admin URLs (not securing them).
- No authentication on admin endpoints.
- Relying on obscurity.

**Prevention**:
- Authentication on all endpoints (especially sensitive).
- Authorization checks (verify user role).
- Security testing (enumerate all endpoints; test access).

---

### Rank 17–20: System Configuration & Deployment

#### 17. Security Misconfiguration

**SANS Perspective**: Systems configured insecurely; attackers find easy entry points.

**Common Mistakes**:
- Default credentials (admin/admin).
- Debug mode enabled in production.
- Unnecessary services running.
- Missing security headers.

**Prevention**:
- Hardening checklists (CIS Benchmarks).
- Configuration scanning (CIS-CAT, Lynis).
- Minimize services (remove unnecessary attack surface).
- Security headers (CSP, X-Frame-Options, etc.).

---

#### 18. Use of Hard-Coded Credentials

**SANS Perspective**: Credentials in source code; if repo leaked, accounts compromised.

**Common Mistakes**:
- API keys in code (committed to git).
- Database passwords in config files.
- Private keys in repositories.

**Prevention**:
- Environment variables (secrets not in code).
- Secrets management system (Vault, AWS Secrets Manager).
- Secrets scanning (detect before commit).
- Rotate compromised credentials immediately.

---

#### 19. Denial of Service

**SANS Perspective**: Attacker overwhelms system; legitimate users can't access service.

**Common Mistakes**:
- No rate limiting.
- No resource limits.
- Expensive operations (can be abused).
- No timeout on requests.

**Prevention**:
- Rate limiting (requests/user/second).
- Resource quotas (max connections, memory, disk).
- Timeouts (max execution time).
- Input validation (reject expensive patterns).

---

#### 20. Unsafe File Upload

**SANS Perspective**: Attacker uploads malware/web shell; achieves RCE.

**Common Mistakes**:
- No file type validation.
- Uploads in web root (directly accessible).
- No size limits.
- Using original filename (conflicts).

**Prevention**:
- File type validation (MIME type, magic bytes).
- Store outside web root (not accessible via HTTP).
- Size limits.
- Rename files (use UUID).
- Antivirus scanning (ClamAV).

---

### Rank 21–25: Other Critical Issues

#### 21. Insufficient Access Control

**SANS Perspective**: Permissions not properly restricted; users access data they shouldn't.

**Prevention**: Same as Broken Access Control (#5).

---

#### 22. Using Insufficiently Random Values

**SANS Perspective**: Weak random number generation; attacker predicts tokens, session IDs, etc.

**Common Mistakes**:
- Using rand() / random() (predictable).
- Using time-based seeds.
- Using weak algorithms.

**Prevention**:
- Cryptographically secure RNG (os.urandom(), secrets module).
- Never seed with time.
- Use strong algorithms (OpenSSL, etc.).

---

#### 23. XXE (XML External Entity) Injection

**SANS Perspective**: Attacker injects malicious XML entities; LFI, SSRF, or DoS.

**Common Mistakes**:
- Parsing XML from untrusted source.
- XXE processing enabled (default in many XML parsers).

**Prevention**:
- Disable XXE processing (when parsing untrusted XML).
- Use secure XML parsers.
- Input validation.

---

#### 24. CSRF (Cross-Site Request Forgery)

**SANS Perspective**: Attacker tricks authenticated user into performing unwanted action.

**Prevention**: Same as CSRF (#8 in OWASP Top 10).

---

#### 25. Insecure Transport

**SANS Perspective**: Data transmitted without encryption; attacker intercepts.

**Common Mistakes**:
- HTTP instead of HTTPS.
- Downgrade attacks (force HTTP).
- Weak TLS (SSL 3.0, TLS 1.0).

**Prevention**:
- HTTPS only (TLS 1.2+).
- HSTS header (force HTTPS).
- Certificate pinning (prevent MITM).
- Strong ciphers (no RC4, DES).

---

## SANS Top 25 Quick Reference

| Rank | Category | Issue | Prevalence | Severity |
|---|---|---|---|---|
| 1–4 | Coding | XSS, SQL Injection, OS Command Injection, Buffer Overflow | Very High | Critical |
| 5–8 | Auth/Access | Broken Access Control, Weak Auth, Weak Crypto, IDOR | Very High | Critical |
| 9–12 | Data | Data Exposure, Insufficient Logging, Bad Input, Missing Encryption | High | High |
| 13–16 | Development | Unvalidated Redirects, Insecure Deserialization, Known Vulns, No URL Access Control | High | High |
| 17–20 | Config/Deploy | Misconfiguration, Hard-Coded Creds, DoS, Unsafe Upload | High | High |
| 21–25 | Other | Insufficient Access, Weak RNG, XXE, CSRF, Insecure Transport | Moderate–High | High |

---

## SANS vs. OWASP vs. CWE

| Standard | Focus | Level | Detail | Audience |
|---|---|---|---|---|
| **SANS Top 25** | Practical errors (developer perspective) | High | Medium (actionable, not exhaustive) | Developers, DevOps, CISO |
| **OWASP Top 10** | Web app risks (application-level) | High | Medium (scannable for testers) | Web devs, testers, security teams |
| **CWE Top 25** | Technical weaknesses (low-level) | Low | High (technical, detailed) | Security researchers, code reviewers |

**Recommendation**: Use all three:
1. **SANS Top 25** for developer training (most practical).
2. **OWASP Top 10** for web app testing (scannable checklist).
3. **CWE Top 25** for code review (detailed weaknesses).

---

## Using SANS Top 25 in Development

**Secure Coding Training**:
- Train developers on SANS Top 25.
- Use as basis for secure coding guidelines.
- Embed in code review process.

**Testing**:
- Create test cases for each SANS Top 25 error.
- Scan code for known patterns.
- Penetration test against SANS vulnerabilities.

**Prioritization**:
- Focus on high-prevalence, high-severity issues.
- Rank 1–12 are most common/dangerous.
- Allocate testing/remediation effort accordingly.

---

## Resources

- **SANS Institute**: www.sans.org (publishes Top 25 annually).
- **MITRE CWE**: cwe.mitre.org (detailed technical descriptions).
- **OWASP Top 10**: owasp.org (web app focus).

---


## See also

[[CWE-Top-25]], [[OWASP-Top-10]], [[CVSSv4]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
