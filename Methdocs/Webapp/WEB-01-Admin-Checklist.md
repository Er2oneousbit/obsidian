# Web Application Admin Checklist

Quick reference for gathering administrative and architectural information before testing begins.

Related: [[WEB-02-Technical-Testing-Checklist]] | [[WEB-00-Overview]]

---

## Pre-Engagement

### Engagement Scope
- [ ] Application name/identifier documented
- [ ] Primary business function understood
- [ ] Deployment status confirmed (dev/staging/prod)
- [ ] Testing window scheduled
- [ ] Out-of-scope components documented
- [ ] Emergency contact identified
- [ ] Rules of engagement signed
- [ ] Data handling restrictions noted
- [ ] Source code review included: Yes / No

### Access Provided
- [ ] Test account credentials (multiple roles if possible)
  - [ ] Standard user: ________________
  - [ ] Power user: ________________
  - [ ] Admin user (read-only): ________________
- [ ] VPN/network access (if required)
- [ ] Application documentation
- [ ] Architecture diagrams
- [ ] API documentation (if applicable)
- [ ] Source code access (if white-box)

### Initial Documentation Received
- [ ] Application user guide
- [ ] Admin documentation
- [ ] Known security controls
- [ ] Previous security assessments
- [ ] Incident response contact
- [ ] Change control process
- [ ] Deployment pipeline documentation

---

## Application Architecture

### Technology Stack
- [ ] **Frontend Framework**: [React / Vue / Angular / jQuery / Vanilla JS / Other]
- [ ] **Backend Language**: [PHP / Python / Java / .NET / Ruby / Node.js / Go / Other]
- [ ] **Backend Framework**: [Laravel / Django / Spring / ASP.NET / Rails / Express / Other]
- [ ] **Web Server**: [Apache / Nginx / IIS / Tomcat / Other]
- [ ] **Application Server**: ________________
- [ ] **Database**: [MySQL / PostgreSQL / MongoDB / MSSQL / Oracle / Other]
- [ ] **Caching**: [Redis / Memcached / Varnish / None]
- [ ] **CMS**: [WordPress / Drupal / Joomla / Custom / None]
  - [ ] Version: ________________
  - [ ] Plugins/themes documented: Yes / No

### Deployment Architecture
- [ ] **Hosting**: [Cloud / On-prem / Hybrid / Shared hosting]
- [ ] **Cloud Provider**: [AWS / Azure / GCP / N/A]
- [ ] **Region**: ________________
- [ ] **Load Balancer**: Yes / No
  - [ ] Type: ________________
- [ ] **CDN**: Yes / No
  - [ ] Provider: [Cloudflare / Akamai / AWS CloudFront / Other]
- [ ] **WAF**: Yes / No
  - [ ] Provider: ________________
  - [ ] Rule sets: ________________
- [ ] **Containerized**: Yes / No
  - [ ] Platform: [Docker / Kubernetes / Other]

### Network Position
- [ ] **Internet-facing**: Yes / No
- [ ] **Internal network access**: Yes / No
  - [ ] Scope: ________________
- [ ] **VPN required**: Yes / No
- [ ] **IP whitelisting**: Yes / No
  - [ ] Testing IPs added: Yes / No
- [ ] **Subdomain structure**: ________________

---

## Authentication & Authorization

### Authentication Mechanisms
- [ ] **Auth type**: [Form-based / SSO / OAuth / SAML / Certificate / API Token / Multi-factor]
- [ ] **SSO Provider**: ________________ (if applicable)
- [ ] **OAuth Provider**: ________________ (if applicable)
- [ ] **MFA enforced**: Yes / No / Optional
  - [ ] MFA type: [TOTP / SMS / Email / Hardware token]
- [ ] **CAPTCHA**: Yes / No
  - [ ] Type: [reCAPTCHA / hCaptcha / Custom]
  - [ ] Pages: ________________

### Credential Policy
- [ ] **Password requirements**:
  - [ ] Minimum length: ________ characters
  - [ ] Complexity: [Upper / Lower / Numbers / Special]
  - [ ] Dictionary check: Yes / No
  - [ ] Breached password check: Yes / No
- [ ] **Account lockout**: Yes / No
  - [ ] Failed attempts: ________
  - [ ] Lockout duration: ________ minutes
  - [ ] Lockout type: [IP-based / Account-based / Both]
- [ ] **Password reset**: Available / Admin-only
  - [ ] Reset method: [Email / SMS / Security questions]
  - [ ] Token expiration: ________ minutes

### Session Management
- [ ] **Session storage**: [Server-side / Client-side (JWT) / Both]
- [ ] **Session timeout**: ________ minutes (idle)
- [ ] **Absolute timeout**: ________ minutes
- [ ] **Concurrent sessions**: Allowed / Blocked
- [ ] **Session fixation protection**: Yes / No / Unknown
- [ ] **Logout functionality**: Yes / No
  - [ ] Server-side invalidation: Yes / No

### Authorization Model
- [ ] **Authorization type**: [RBAC / ABAC / ACL / Custom]
- [ ] **Roles identified**:
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
- [ ] **Permission granularity**: [Page-level / Function-level / Data-level]
- [ ] **Admin role exists**: Yes / No
  - [ ] Admin features: ________________
- [ ] **Service accounts exist**: Yes / No

---

## Application Mapping

### Public-Facing Pages
- [ ] **Homepage**: ________________
- [ ] **Login page**: ________________
- [ ] **Registration**: Available / Invite-only / Disabled
- [ ] **Password reset**: ________________
- [ ] **Contact/Support**: ________________
- [ ] **API endpoints**: ________________
  - [ ] Documentation: ________________

### Authenticated Features
List main application features (map after initial exploration):
- [ ] ________________
- [ ] ________________
- [ ] ________________

### Admin Panel
- [ ] **Admin URL**: ________________
- [ ] **Separate admin interface**: Yes / No
- [ ] **Admin functions**:
  - [ ] User management
  - [ ] Content management
  - [ ] System configuration
  - [ ] Reporting
  - [ ] Other: ________________

### File Upload Capabilities
- [ ] **File upload available**: Yes / No
- [ ] **Upload locations**:
  - [ ] ________________ (allowed types: ________________)
  - [ ] ________________ (allowed types: ________________)
- [ ] **Max file size**: ________ MB
- [ ] **File type validation**: Yes / No / Unknown
- [ ] **Upload directory**: ________________

---

## Data Handling

### Sensitive Data Types
Application handles (check all that apply):
- [ ] PII (Personally Identifiable Information)
- [ ] PHI (Protected Health Information)
- [ ] PCI (Payment Card Information)
- [ ] Authentication credentials
- [ ] Session tokens
- [ ] Business confidential data
- [ ] Customer data
- [ ] Financial records
- [ ] Legal documents
- [ ] User-generated content
- [ ] Other: ________________

### Data Storage
- [ ] **Database location**: ________________
- [ ] **File storage**: [Local / S3 / Azure Blob / NFS / Other]
- [ ] **Encryption at rest**: Yes / No / Unknown
  - [ ] Method: ________________
- [ ] **Encryption in transit**: Yes / No
  - [ ] HTTPS enforced: Yes / No
  - [ ] HSTS enabled: Yes / No
- [ ] **Backup location**: ________________
- [ ] **Backup frequency**: ________________

### Third-Party Integrations
- [ ] **Payment processor**: ________________
- [ ] **Email service**: ________________
- [ ] **SMS service**: ________________
- [ ] **Analytics**: [Google Analytics / Mixpanel / Other]
- [ ] **Chat/Support**: ________________
- [ ] **Other integrations**:
  - [ ] ________________
  - [ ] ________________

---

## Security Controls

### Input Validation
- [ ] **Server-side validation**: Yes / No / Unknown
- [ ] **Client-side validation**: Yes / No
- [ ] **Validation framework**: ________________
- [ ] **Sanitization**: Yes / No / Unknown
- [ ] **Encoding**: Yes / No / Unknown
- [ ] **Max input length**: Enforced / Not enforced

### Output Encoding
- [ ] **HTML encoding**: Yes / No / Unknown
- [ ] **JavaScript encoding**: Yes / No / Unknown
- [ ] **URL encoding**: Yes / No / Unknown
- [ ] **CSS encoding**: Yes / No / Unknown
- [ ] **Template engine**: ________________
  - [ ] Auto-escaping: Yes / No

### HTTP Security Headers
- [ ] **Content-Security-Policy**: Present / Absent
  - [ ] Policy: ________________
- [ ] **X-Frame-Options**: Present / Absent
  - [ ] Value: ________________
- [ ] **X-Content-Type-Options**: Present / Absent
- [ ] **Strict-Transport-Security (HSTS)**: Present / Absent
  - [ ] Max-age: ________
  - [ ] includeSubDomains: Yes / No
- [ ] **X-XSS-Protection**: Present / Absent
- [ ] **Referrer-Policy**: Present / Absent
- [ ] **Permissions-Policy**: Present / Absent

### CORS Configuration
- [ ] **CORS enabled**: Yes / No
- [ ] **Allowed origins**: ________________
- [ ] **Wildcard origins**: Yes / No
- [ ] **Credentials allowed**: Yes / No

### Error Handling
- [ ] **Custom error pages**: Yes / No
- [ ] **Error verbosity**: [Generic / Detailed / Stack traces]
- [ ] **Debug mode**: Enabled / Disabled / Unknown
- [ ] **Error logging**: Yes / No / Unknown

---

## Monitoring & Logging

### Security Monitoring
- [ ] **WAF/IPS**: Yes / No
  - [ ] Alerting: Yes / No
  - [ ] Blocking: Yes / No
- [ ] **SIEM integration**: Yes / No
- [ ] **Anomaly detection**: Yes / No
- [ ] **Failed login monitoring**: Yes / No
- [ ] **Security alerts**: Yes / No
  - [ ] Alert triggers: ________________

### Application Logging
- [ ] **Access logs**: Yes / No
  - [ ] Retention: ________________
- [ ] **Error logs**: Yes / No
  - [ ] Retention: ________________
- [ ] **Audit logs**: Yes / No
  - [ ] Events logged: ________________
  - [ ] Retention: ________________
- [ ] **Sensitive data in logs**: Yes / No / Unknown

---

## Business Context

### Application Purpose
- [ ] **Primary function**: ________________
- [ ] **User base size**: ________________
- [ ] **Customer-facing**: Yes / No
- [ ] **Revenue-generating**: Yes / No
- [ ] **Business criticality**: [Low / Medium / High / Critical]
- [ ] **Uptime requirement**: ________________ (e.g., 99.9%)

### Compliance Requirements
- [ ] **HIPAA**: Yes / No
- [ ] **PCI-DSS**: Yes / No
  - [ ] Level: ________________
- [ ] **GDPR**: Yes / No
- [ ] **SOX**: Yes / No
- [ ] **SOC 2**: Yes / No
- [ ] **ISO 27001**: Yes / No
- [ ] **Other**: ________________

### High-Value Operations
Critical functions to focus on:
- [ ] ________________ (Impact: ________________)
- [ ] ________________ (Impact: ________________)
- [ ] ________________ (Impact: ________________)

### Impact Scenarios
- [ ] **Financial transactions**: Yes / No
  - [ ] Volume: ________________
  - [ ] Average value: ________________
- [ ] **Data modification**: Yes / No
  - [ ] User data / System data / Both
- [ ] **Data deletion**: Yes / No
- [ ] **External API calls**: Yes / No
- [ ] **Email/notification sending**: Yes / No

---

## Development & Operations

### Development Team
- [ ] **Security champion identified**: Yes / No
  - [ ] Contact: ________________
- [ ] **Dev team contact**: ________________
- [ ] **DevOps contact**: ________________
- [ ] **Incident response contact**: ________________
- [ ] **Bug bounty program**: Yes / No
  - [ ] Platform: ________________

### Security Posture
- [ ] **Previous pentests**: Yes / No
  - [ ] Last test date: ________________
  - [ ] Critical findings from last test: ________________
- [ ] **Vulnerability scanning**: Yes / No
  - [ ] Frequency: ________________
  - [ ] Tool: ________________
- [ ] **Security training**: Yes / No
- [ ] **Secure SDLC**: Yes / No
- [ ] **Code review process**: Yes / No
  - [ ] Security-focused: Yes / No

### CI/CD Pipeline
- [ ] **Code repository**: [GitHub / GitLab / BitBucket / Other]
- [ ] **SAST**: Yes / No
  - [ ] Tool: ________________
- [ ] **DAST**: Yes / No
  - [ ] Tool: ________________
- [ ] **Dependency scanning**: Yes / No
  - [ ] Tool: ________________
- [ ] **Container scanning**: Yes / No
- [ ] **Secrets management**: ________________

### Change Management
- [ ] **Change approval required**: Yes / No
- [ ] **Deployment frequency**: ________________
- [ ] **Rollback capability**: Yes / No
- [ ] **Blue team notification process**: ________________

---

## Testing Constraints

### Known Limitations
Document any restrictions or special considerations:
- ________________
- ________________
- ________________

### Red Lines (Do Not Cross)
- ________________
- ________________
- ________________

### Rate Limiting Concerns
- [ ] **Login attempts**: ________ per ________
- [ ] **API calls**: ________ per ________
- [ ] **Other**: ________________

### Special Notes
________________
________________
________________

---

## Initial Observations

### Technology Fingerprinting
- [ ] **Server headers**:
  - Server: ________________
  - X-Powered-By: ________________
- [ ] **Framework detection**: ________________
- [ ] **JavaScript libraries**: ________________
- [ ] **Detected CMS/platform**: ________________

### Quick Observations
- [ ] Application appears to use: ________________
- [ ] Obvious security controls: ________________
- [ ] Potential weak points: ________________
- [ ] Interesting behaviors: ________________

### Quick Wins Identified
- [ ] ________________
- [ ] ________________

---

## Kickoff Meeting Notes

**Date**: ________________
**Attendees**: ________________

**Key Discussion Points**:
________________
________________

**Questions to Follow Up**:
- [ ] ________________
- [ ] ________________

---

## Administrative Checklist Complete
- [ ] All critical information gathered
- [ ] Scope clearly defined
- [ ] Access confirmed working
- [ ] Testing environment confirmed (prod/staging/dev)
- [ ] Burp configured and capturing traffic
- [ ] Browser configured with proxy
- [ ] Test accounts created/received
- [ ] Ready to proceed to [[WEB-02-Technical-Testing-Checklist|Technical Testing]]

---

## Tags
#admin #discovery #scoping #web-testing

---

## Related Documents
- [[WEB-00-Overview|Overview]]
- [[WEB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[WEB-03-Request-Tracker|Request Tracker]]

---
*Created: 2026-01-22*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
