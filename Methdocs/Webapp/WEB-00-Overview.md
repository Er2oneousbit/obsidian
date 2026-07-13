# Web Application Penetration Testing Overview

## Purpose
Comprehensive methodology for assessing web application security vulnerabilities, with focus on injection attacks, authentication/authorization flaws, business logic abuse, and client-side vulnerabilities.

## Document Structure
- [[WEB-01-Admin-Checklist]] - Pre-engagement information gathering
- [[WEB-02-Technical-Testing-Checklist]] - Hands-on testing methodology
- [[WEB-03-Request-Tracker]] - Document successful/failed requests and payloads
- [[WEB-04-Evidence-Collection]] - Screenshot and evidence tracking
- [[WEB-05-Reporting-Template]] - Finding documentation structure
- [[WEB-06-Quick-Reference]] - Fast lookup for common attacks

## Engagement Workflow
1. Complete [[WEB-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[WEB-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[WEB-03-Request-Tracker|Request Tracker]]
4. Capture evidence per [[WEB-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[WEB-05-Reporting-Template|Reporting Template]]

## Key Concepts

### Attack Surface Areas
- **Authentication** - Login bypass, session management, password policies
- **Authorization** - Privilege escalation, IDOR, forced browsing
- **Input Validation** - Injection attacks (SQL, XSS, Command, XXE)
- **Session Management** - Token hijacking, fixation, prediction
- **File Upload** - Unrestricted upload, path traversal, malicious files
- **Business Logic** - Workflow bypass, race conditions, price manipulation
- **Client-Side** - XSS, DOM manipulation, JavaScript vulnerabilities

### OWASP Top 10 (2021)

**A01:2021 - Broken Access Control**
- IDOR/forced browsing to unauthorized resources
- Missing function-level access control
- Metadata manipulation (tamper with JWTs, cookies)
- CORS misconfiguration

**A02:2021 - Cryptographic Failures**
- Weak encryption algorithms
- Sensitive data in transit without HTTPS
- Poor key management
- Reversible password storage

**A03:2021 - Injection**
- SQL injection
- NoSQL injection
- OS command injection
- LDAP, XPath, XXE injection

**A04:2021 - Insecure Design**
- Missing security controls by design
- Business logic flaws
- Unlimited resource consumption

**A05:2021 - Security Misconfiguration**
- Default credentials
- Unnecessary features enabled
- Verbose error messages
- Missing security headers

**A06:2021 - Vulnerable and Outdated Components**
- Using components with known CVEs
- Unmaintained libraries
- Unnecessary dependencies

**A07:2021 - Identification and Authentication Failures**
- Credential stuffing
- Weak password policies
- Missing MFA
- Insecure session management

**A08:2021 - Software and Data Integrity Failures**
- Insecure deserialization
- Unsigned software updates
- CI/CD pipeline vulnerabilities

**A09:2021 - Security Logging and Monitoring Failures**
- Missing audit logs
- No alerting on suspicious activity
- Insufficient log retention

**A10:2021 - Server-Side Request Forgery (SSRF)**
- Access to internal resources
- Cloud metadata exposure
- Port scanning internal network

Reference: [OWASP Top 10](https://owasp.org/www-project-top-10/)

## Application Types Covered

### Traditional Web Apps
- Server-side rendered (PHP, ASP.NET, Java)
- Session-based authentication
- Form-based interactions

### Single Page Applications (SPAs)
- React, Vue, Angular
- Token-based authentication (JWT)
- Heavy client-side logic

### Progressive Web Apps (PWAs)
- Service workers
- Offline functionality
- Push notifications

### Content Management Systems
- WordPress, Drupal, Joomla
- Known vulnerabilities in plugins/themes
- Admin panel security

## Tools
- Burp Suite Professional (primary)
- OWASP ZAP (alternative/supplemental)
- Browser Developer Tools (Chrome/Firefox DevTools)
- SQLMap (SQL injection automation)
- XSStrike (XSS detection)
- Nikto (web server scanner)
- DirBuster/Gobuster (directory enumeration)
- WPScan (WordPress scanning)
- Nuclei (vulnerability scanner)
- Custom scripts (Python requests, Selenium)

## Testing Methodology

### 1. Information Gathering
- Passive reconnaissance (Google dorking, Shodan)
- Active enumeration (subdomain discovery, tech stack fingerprinting)
- Application mapping (sitemap, functionality inventory)

### 2. Authentication Testing
- Credential policies
- Brute force protection
- Session management
- Multi-factor authentication
- Password reset flows

### 3. Authorization Testing
- Vertical privilege escalation
- Horizontal privilege escalation (IDOR)
- Forced browsing
- Parameter tampering

### 4. Input Validation Testing
- SQL injection (all entry points)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Command injection
- Path traversal
- XML External Entity (XXE)
- Template injection

### 5. Session Management Testing
- Cookie analysis (flags, expiration)
- Token predictability
- Session fixation
- Concurrent sessions
- Logout functionality

### 6. Business Logic Testing
- Workflow bypass
- Race conditions
- Price manipulation
- Account enumeration
- Feature abuse

### 7. Client-Side Testing
- DOM-based XSS
- JavaScript security
- WebSocket security
- CORS issues
- Clickjacking

### 8. File Upload Testing
- Unrestricted file upload
- File type validation bypass
- Path traversal in filenames
- Malicious file content
- File inclusion vulnerabilities

## Tags for Obsidian
#web-testing #owasp #burp #sql-injection #xss #methodology #checklist

---
*Last Updated: 2026-01-22*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
