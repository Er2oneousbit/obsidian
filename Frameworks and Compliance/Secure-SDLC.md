# Secure SDLC (Software Development Lifecycle)

#SecureSDLC #DevSecOps #SSDF #SecureCoding #Development

## What is this?

**Secure Software Development Lifecycle (Secure SDLC)** — Practices and processes integrating security into every phase of software development: requirements, design, development, testing, deployment, maintenance. NIST SP 800-218 (Secure Software Development Framework — SSDF) is authoritative US standard. Shift security left (find issues early; cheaper to fix).

---

## Overview

**Secure SDLC Basics:**
- **Purpose**: Build security into software from day one; prevent vulnerabilities at source.
- **Scope**: Development processes, tools, practices, cultural change.
- **Audience**: Developers, architects, security engineers, DevOps, QA, managers.

**Why SDLC?**
- **Cost**: Fixing bugs in production 100x more expensive than in development.
- **Prevention**: Secure design > trying to patch vulnerabilities later.
- **Compliance**: Standards require secure development (NIST, ISO, PCI-DSS).
- **Trust**: Secure SDLC demonstrates commitment to customers/regulators.

---

## NIST SP 800-218 (SSDF) Framework

### 4 Practice Groups

NIST's SSDF defines **4 practice groups**: **PO** (Prepare the Organization), **PS** (Protect the Software — safeguard code from tampering/unauthorized access), **PW** (Produce Well-Secured Software — secure design, code review, testing), and **RV** (Respond to Vulnerabilities). Practices are numbered within each group (e.g. PW.7 = review/analyze human-readable code):

#### Group 1: Prepare Organization (PO)

**Goal**: Create culture and processes supporting secure development.

**PO.1 — Processes & Practices**
- Secure development policies documented.
- Security training for all developers.
- Tools & infrastructure for secure development.
- Risk assessment integrated into development.

**PO.2 — Secure Tools & Environment**
- Source code repository (Git with access controls).
- Secure build environment (isolated, controlled).
- Dependency management (track all libraries).
- Security scanning tools integrated into pipeline.

**PO.3 — Risk Management**
- Risk assessment for new features.
- Threat modeling during design.
- Security prioritization (critical features reviewed first).
- Compliance requirements identified.

**PO.4 — Supply Chain**
- Third-party code reviewed (open-source libraries).
- Vendor security evaluated.
- Software bill of materials (SBOM) maintained.
- License compliance checked (no GPL in proprietary code).

---

#### Group 2: Protect Software (PS)

**Goal**: Implement secure practices in development.

**PS.1 — Code Review & Analysis**
- Code review by peer (every commit reviewed).
- Static analysis (SAST tools; automated scanning).
- Dynamic analysis (DAST; runtime testing).
- Security checklist used (common vulns to look for).

**PS.2 — Dependency Management**
- All dependencies tracked (lock files, SBOM).
- Known vulnerabilities scanned (dependency scanning).
- Vulnerable dependencies updated/replaced.
- License compliance verified.

**PS.3 — Secure Coding**
- Secure coding practices documented.
- Developers trained on common vulns (OWASP Top 10, CWE).
- Input validation implemented (all inputs checked).
- Output encoding implemented (context-specific).

**PS.4 — Secure Build**
- Build automated (consistent, reproducible).
- Security checks in pipeline (SAST, DAST, scanning).
- Artifacts signed (prove authenticity).
- Build isolated (no access to prod secrets).

---

#### Group 3: Produce Well-Secured Software (PO)

**Goal**: Verify security before release.

**PO.1 — Security Testing**
- Test cases for security (injection, auth, access control).
- Penetration testing (annual).
- Vulnerability scanning (automated).
- Test coverage 80%+ of code.

**PO.2 — Hardening**
- Default configurations hardened.
- Debug features disabled in production.
- Error messages don't leak info.
- Security headers configured.

**PO.3 — Release**
- Release notes include security fixes.
- Version control clean (no secrets, no debug code).
- Artifacts verified (signatures, hashes).
- Deployment tested (rollback capability).

---

#### Group 4: Maintain & Support (MPS)

**Goal**: Support secure software post-release.

**MPS.1 — Incident Response**
- Security vulnerability reports triaged.
- Patches developed & tested quickly.
- Security advisories published.
- Fixes backported to supported versions.

**MPS.2 — Continuous Monitoring**
- Security updates monitored (OS, libraries).
- Vulnerabilities in production tracked.
- Customer feedback on security issues.
- Metrics tracked (time-to-patch, etc.).

**MPS.3 — End-of-Life**
- Support timeline communicated (when version stops getting patches).
- Secure decommissioning of old versions.
- Archive of historical vulnerabilities.

---

## Secure SDLC Phases

### Phase 1: Requirements & Planning

**Activities**:
- Security requirements defined (authentication, encryption, audit logging).
- Threat modeling (identify threats; design mitigations).
- Risk assessment (likelihood × impact).
- Compliance requirements identified (GDPR, HIPAA, PCI-DSS, etc.).
- Security team involved (not left to QA at end).

**Deliverables**:
- Security requirements document.
- Threat model (visual diagram of threats).
- Risk register (prioritized risks).

**Example**:
```
Feature: User login
Security requirements:
- MFA required
- Rate limiting (5 attempts/min)
- Session timeout (15 min inactivity)
- Passwords hashed (bcrypt)
- Brute force detection (lock account after 5 failures)

Threats:
- Brute force attack (attacker guesses password)
- Session hijacking (attacker steals session token)
- Phishing (attacker tricks user into revealing password)

Mitigations:
- MFA blocks brute force
- Secure session tokens prevent hijacking
- User education on phishing
```

---

### Phase 2: Design

**Activities**:
- Security architecture designed (defense-in-depth).
- Component interactions reviewed (is communication secure?).
- Data flow diagrammed (where does sensitive data go?).
- Cryptographic approach selected (algorithms, key management).
- API design reviewed (authentication, authorization, rate limiting).

**Deliverables**:
- Architecture diagram.
- Data flow diagram.
- API specification (with security controls).
- Cryptographic design.

**Example**:
```
Design: File upload

Architecture:
- User → Web server → Validation → Antivirus → Storage
- Storage isolated (not in web root; requires authenticated access)
- File size limited (max 10MB)
- File type validated (MIME type, magic bytes)

Data flow:
- User uploads file → Base64 encoded → Sent over HTTPS
- Server validates → Scans with ClamAV → Stores encrypted
- Retrieved over HTTPS → Served with Content-Disposition: attachment
- (Forces download, not inline render; prevents XSS via file)
```

---

### Phase 3: Development

**Activities**:
- Developers follow secure coding practices.
- Code reviewed by peer (security focus).
- Static analysis (SAST) run during development.
- No hardcoded secrets (use config, environment variables).
- Dependencies scanned for vulnerabilities.

**Deliverables**:
- Clean code (no SAST warnings).
- Code review approvals (peer + security team for critical code).
- Dependency SBOM (software bill of materials).

**Example**:
```
Secure coding checklist:
- [ ] All inputs validated (whitelist, length checks)
- [ ] All outputs encoded (context-specific)
- [ ] Database queries parameterized (no SQL injection)
- [ ] Passwords hashed with bcrypt
- [ ] No secrets in code (API keys in env vars)
- [ ] Error handling doesn't leak info
- [ ] SAST scan clean (no HIGH/CRITICAL warnings)
```

---

### Phase 4: Testing

**Activities**:
- Unit tests include security tests.
- Dynamic analysis (DAST) on staging.
- Penetration testing (external firm or internal team).
- Vulnerability scanning (automated tools).
- Configuration reviewed (no debug mode, hardened).

**Deliverables**:
- Test results (PASS/FAIL per security requirement).
- Pentest report (findings, severity).
- Vulnerability scan results (remediation plan).

**Example**:
```
Security test cases:
- Test authentication: Can unauthenticated user access protected endpoint? → FAIL
- Test authorization: Can regular user access admin endpoint? → FAIL
- Test injection: Can SQL injection be used to bypass login? → FAIL
- Test rate limiting: Can brute force bypass attempt limits? → FAIL
- Test session: Can session be hijacked? → FAIL
```

---

### Phase 5: Deployment

**Activities**:
- Release notes include security fixes.
- Deployment checklist (security focus).
- Configuration hardened (no defaults, debug disabled).
- Rollback capability tested.
- Monitoring enabled (alerts for security events).

**Deliverables**:
- Deployment checklist (signed off).
- Release notes (with CVEs fixed).
- Monitoring dashboards (security metrics).

**Example**:
```
Production deployment checklist:
- [ ] Debug mode disabled
- [ ] Error messages don't leak system info
- [ ] Security headers configured (CSP, HSTS, etc.)
- [ ] HTTPS enforced
- [ ] Database credentials in secure store (not code)
- [ ] Logging enabled (centralized)
- [ ] Alerts configured (unusual activity)
- [ ] Rollback tested (can revert if needed)
```

---

### Phase 6: Maintenance & Support

**Activities**:
- Security updates monitored (OS, libraries).
- Patches developed and tested quickly.
- Vulnerability reports triaged (severity, timeline).
- Security advisories published.
- End-of-life timeline communicated.

**Deliverables**:
- Patch release schedule.
- Security advisories (CVE details, affected versions).
- Vulnerability metrics (time-to-patch, etc.).

**Example**:
```
Security update process:
1. Vulnerability discovered (internal or external report)
2. Triaged (severity, affected versions)
3. Patch developed & tested (on affected versions)
4. Security advisory drafted
5. Patch released (coordinated with vendors if needed)
6. Customers notified (email, security advisory)
7. Metrics tracked (time from discovery to patch: target 30 days for HIGH/CRITICAL)
```

---

## Secure SDLC Tools & Practices

### Development Tools

| Category | Tools | Purpose |
|---|---|---|
| **Source Control** | Git, GitHub, GitLab | Track code, enforce code review, access control |
| **Build** | Jenkins, GitHub Actions, GitLab CI | Automated builds, security gates |
| **Static Analysis (SAST)** | SonarQube, Fortify, Checkmarx | Scan code for vulnerabilities |
| **Dependency Scanning** | Snyk, OWASP Dependency-Check, npm audit | Find vulnerable libraries |
| **Dynamic Analysis (DAST)** | Burp Suite, OWASP ZAP | Test running application |
| **Container Scanning** | Trivy, Grype, Clair | Scan Docker images |
| **Secrets Management** | HashiCorp Vault, AWS Secrets Manager | Secure credential storage |

### Development Practices

| Practice | Purpose | Tools |
|---|---|---|
| **Code Review** | Peer review for security | GitHub/GitLab PRs, pull request approval |
| **Threat Modeling** | Identify threats early | STRIDE, PASTA frameworks; Lucidchart |
| **Secure Coding Training** | Teach developers | OWASP Secure Coding, internal guidelines |
| **Security Testing** | Test security, not just functionality | OWASP Testing Guide, custom tests |
| **Penetration Testing** | Find real vulnerabilities | Internal team or external firm |
| **SBOM** | Track all dependencies | CycloneDX, SPDX format |

---

## Secure SDLC Maturity

### Level 1: Initial
- Minimal security practices.
- No formal secure development process.
- Security addressed at end (QA).
- Ad-hoc testing.

---

### Level 2: Managed
- Secure development policy (documented).
- Code review (all code reviewed).
- SAST tools integrated.
- Dependency scanning.
- Security testing (planned).

---

### Level 3: Optimized
- Threat modeling (standard practice).
- Automated security gates (CI/CD pipeline).
- DAST/penetration testing (regular).
- Security metrics (tracked, trending).
- Continuous improvement.

---

## Secure SDLC Checklist

### Requirements & Planning
- [ ] Security requirements defined.
- [ ] Threat modeling conducted.
- [ ] Risk assessment completed.
- [ ] Compliance requirements identified.
- [ ] Security team involved.

### Design
- [ ] Architecture reviewed (defense-in-depth).
- [ ] Data flow diagrammed.
- [ ] Cryptographic approach defined.
- [ ] API security designed.

### Development
- [ ] Secure coding practices followed.
- [ ] Code review (peer, security-focused).
- [ ] SAST scanning (no HIGH/CRITICAL).
- [ ] Dependency scanning (no vulnerable libs).
- [ ] No hardcoded secrets.

### Testing
- [ ] Security test cases defined.
- [ ] DAST performed.
- [ ] Penetration testing (annual).
- [ ] Vulnerability scanning (remediation plan).

### Deployment
- [ ] Release notes (security fixes).
- [ ] Configuration hardened.
- [ ] Monitoring enabled.
- [ ] Rollback tested.

### Maintenance
- [ ] Security updates monitored.
- [ ] Patches deployed quickly (SLA: 30 days HIGH/CRITICAL).
- [ ] Advisories published.
- [ ] Metrics tracked.

---

## Common Secure SDLC Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| **Security bolted on late** | Most expensive to fix; often skipped due to deadline | Involve security from day one (requirements phase) |
| **No code review** | Vulns missed; quality suffers | Mandatory code review (peer + security for sensitive code) |
| **SAST not integrated** | Vulns found late (in QA); expensive fix | SAST in CI/CD pipeline (block merge if HIGH/CRITICAL) |
| **No threat modeling** | Threats not identified; design is insecure | Threat modeling workshop (1–2 days per feature) |
| **Testing only happy path** | Security tests missed; vulns in prod | Security test cases (injection, auth, access control, rate limiting) |
| **Dependencies not tracked** | Vulnerable libraries go unpatched | SBOM + dependency scanning in pipeline |
| **No incident response** | Patch delays; customers unaware | Patch SLA (30 days); security advisory process |

---

## NIST SP 800-218 vs. Other Standards

| Standard | Focus | Detail |
|---|---|---|
| **NIST SP 800-218 (SSDF)** | Practices & processes | Prescriptive; 4 groups, multiple practices |
| **OWASP Secure Coding** | Developer education | Practical coding examples |
| **ISO/IEC 27034** | Secure development | Process-oriented; certification-heavy |
| **BSA/IAST** | Runtime instrumentation | Find vulns in production (not just testing) |

---

## Resources

- **NIST SP 800-218**: Secure Software Development Framework (official).
- **OWASP Secure SDLC**: Resources, training, tools.
- **OWASP Top 10**: Vulnerabilities to prevent during development.
- **CWE Top 25**: Weaknesses to avoid in secure coding.
- **SBOM**: Software Bill of Materials (track dependencies).

---


## See also

[[OWASP-SAMM]], [[OWASP-Proactive-Controls]], [[OWASP-Secure-Coding-Practices]], [[Supply-Chain-Security]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
