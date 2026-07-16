# HITRUST CSF Reference Guide

**Health Information Trust Alliance (HITRUST) Common Security Framework (CSF)** — comprehensive security/privacy/compliance framework for healthcare. Combines HIPAA, NIST, ISO, and PCI-DSS requirements into a single harmonized standard. De facto "gold standard" in healthcare security.

---

## Overview

HITRUST CSF is **stricter and more granular than HIPAA alone**. It integrates:
- HIPAA Privacy/Security Rules
- NIST Cybersecurity Framework (CSF)
- ISO 27001/27002 controls
- PCI-DSS requirements
- State privacy laws (often stricter than HIPAA)

Compliance typically required for: covered entities, business associates, vendors selling to healthcare, hospital networks.

---

## HITRUST vs. HIPAA

| Aspect | HIPAA | HITRUST CSF |
|---|---|---|
| **Encryption** | Addressable; alternatives exist | **Required** for data at rest & in transit |
| **MFA** | Not required | **Required** for all ePHI access |
| **Access Logs** | Required | **Required + must review regularly** |
| **Incident Response** | Basic procedures | **Detailed workflows, forensics, evidence preservation** |
| **Vendor Management** | BAA required | **BAA + ongoing risk assessments + audit rights** |
| **Password Policy** | Not specified | **12+ characters, complexity, 90-day rotation** |
| **Scope** | Covered entities + BAs | **Entire supply chain; transitives apply** |
| **Certification** | Self-assessment (HIPAA Audit Program, OCR) | **Third-party audit (HITRUST 3rd-party assessor)** |

---

## Control Framework Structure

HITRUST CSF organizes controls into **22 domains**, grouped by function:

### Information Protection (Domain 01-06)

**01 – Data Governance**
- Classification of information (public, internal, confidential, ePHI).
- Retention policies: how long data kept, secure destruction.
- Ownership: who's responsible for each data type.

**02 – Information & Asset Management**
- Asset inventory (hardware, software, data).
- Secure decommissioning (disk wiping, destruction verification).
- Removable media controls (USB, external drives).

**03 – Access Management**
- Least privilege: users get minimum necessary access.
- Segregation of duties: no single person controls entire transaction.
- Access reviews: quarterly or annually depending on role.

**04 – Authentication & Single Sign-On (SSO)**
- Unique user IDs (no shared accounts).
- **MFA required** for: privileged access, remote access, ePHI access.
- Acceptable factors: passwords, tokens (FIDO2), biometrics, PKI certificates.
- Session timeout: 15 minutes inactivity for sensitive data.

**05 – Cryptography**
- **AES-256** (or equivalent) for data at rest.
- **TLS 1.2+** for data in transit; no self-signed certs.
- Key management: centralized (HSM), rotation annually, strong access controls.
- Secure key storage: never hardcoded in code, not stored in logs.

**06 – Data Loss Prevention (DLP)**
- Email encryption for ePHI.
- USB/removable media restrictions or encryption.
- Endpoint DLP: block exfiltration of sensitive data.
- Data watermarking or classification tagging.

### Infrastructure Protection (Domain 07-09)

**07 – Transmission Security**
- Encryption for all ePHI in transit.
- Secure protocols: HTTPS, SFTP, VPN.
- No unencrypted email, FTP, or HTTP for sensitive data.

**08 – Network Security**
- Firewalls: default-deny inbound, default-allow outbound.
- Segmentation: ePHI isolated from untrusted networks.
- Network diagram required; reviewed annually.
- IDS/IPS: intrusion detection/prevention on critical segments.

**09 – Physical & Environmental Security**
- Controlled access to server rooms (badge, lock, biometric).
- Visitor logs; escorted access.
- Environmental controls: cooling, fire suppression, power backup.
- Video surveillance recommended.

### Personnel Security (Domain 10-12)

**10 – Security Awareness & Training**
- Annual training for all staff (mandatory).
- Topics: ePHI handling, passwords, phishing, breach procedures.
- Contractors/vendors receive training before access granted.
- Training tracked; failed staff get remedial training.

**11 – Personnel Security**
- Background checks before hire (criminal + verification).
- Non-disclosure agreements (NDAs).
- Acceptable use policy (signed).
- Termination procedures: access revoked within 1 hour, equipment recovered.

**12 – Workforce Security**
- Role-based access control (RBAC).
- User provisioning/deprovisioning workflows.
- Exception procedures if someone needs elevated access (documented, temporary).

### Technical Safeguards (Domain 13-16)

**13 – Audit, Logging & Monitoring**
- Logging on all ePHI systems (database, firewall, servers, applications).
- Log retention: 3 years recommended (HIPAA: 6 years minimum).
- Centralized logging (SIEM) with alerting.
- Log reviews: weekly by security team, annually by management.

**14 – Security Testing & Assessment**
- Vulnerability scanning: quarterly (internal + external).
- Penetration testing: annually (internal + external); after major changes.
- Code review: security code review for custom development.
- Risk assessment: annually; document findings + remediation.

**15 – Configuration Management**
- Configuration baseline: document all systems.
- Change management: test changes before deployment, track approvals.
- Hardening: remove unnecessary services, secure defaults.

**16 – Threat & Vulnerability Management**
- Patch management: critical within 15 days, standard within 30 days.
- Security alerts: process for reviewing/triaging vendor advisories.
- Malware protection: anti-malware on all systems, real-time scanning.

### Incident Management (Domain 17-19)

**17 – Incident Response & Management**
- Incident response plan: written, roles defined, reviewed annually.
- Incident detection: automated alerting + manual monitoring.
- Incident investigation: preserve evidence, forensic analysis, root cause.
- Remediation: fix root cause, document lessons learned.

**18 – Business Continuity & Disaster Recovery**
- BCP/DRP plan: written, tested annually, updated after changes.
- Backup strategy: daily incremental, weekly full; encrypted; tested for recoverability.
- Recovery time objective (RTO): defined (typical: <4 hours for critical systems).
- Recovery point objective (RPO): defined (typical: <1 hour).

**19 – Third-Party Management**
- Business Associate Agreements: required + specify HITRUST compliance.
- Vendor risk assessment: before onboarding + annually.
- Vendor audit rights: right to audit vendor controls.
- Subcontractors: vendor responsible for subcontractor compliance (transitives).

### Governance & Management (Domain 20-22)

**20 – Compliance & Risk Management**
- Risk management program: identify, assess, mitigate, monitor risks.
- Compliance audits: internal (annual) + external (for certification).
- Regulatory changes: monitor legal/regulatory updates; adjust policies accordingly.

**21 – Information & Security Program Management**
- Security governance: CISO or equivalent, reports to executive/board.
- Security policy framework: top-level policies + detailed procedures.
- Information security strategy: documented, aligned with business goals.

**22 – Third-Party Oversight**
- Vendor management: contracts, SLAs, performance metrics.
- Incident notification: SLA for vendors to notify of breaches (24 hours common).
- Termination procedures: data return/destruction, access revocation.

---

## HITRUST Certification Levels

### Validated (Highest Assurance)

- Third-party assessor conducts on-site audit.
- 2-year assessment cycle; must address all 19 control domains.
- Requirements: ≥75% pass rate; can have minor findings.
- Cost: $5K–$100K+ depending on org size.
- Carries significant compliance weight (often required by enterprise customers).

### Certified (Standard)

- Organization can self-certify OR use third-party assessor.
- Less rigorous than Validated; shorter assessment.
- Requirements: ≥60% pass rate.
- Cost: $2K–$20K.

### Submitted (Self-Reported)

- Organization completes CSF questionnaire; HITRUST reviews.
- No on-site audit.
- Least assurance level.
- Cost: minimal.

---

## Implementation Roadmap

### Phase 1: Assessment (Weeks 1-4)
- Conduct gap analysis: current state vs. HITRUST requirements.
- Prioritize findings by severity/impact.
- Assign owners for each control domain.

### Phase 2: Remediation (Weeks 5-12)
- Address critical gaps (encryption, MFA, logging).
- Update policies/procedures.
- Deploy technical controls (firewalls, DLP, SIEM).

### Phase 3: Hardening (Weeks 13-16)
- Implement remaining controls.
- Conduct internal audit.
- Fix low-severity findings.

### Phase 4: Certification Preparation (Weeks 17-20)
- Select assessor.
- Prepare evidence (policy documentation, audit logs, training records).
- Conduct mock audit.
- Remediate assessor findings.

### Phase 5: Certification (Weeks 21-24)
- Third-party assessment.
- Address findings; re-test.
- Receive certification (valid 2 years).

---

## Common Gaps in HITRUST Compliance

| Gap | Impact | Fix |
|---|---|---|
| MFA not required for admins | High-risk | Mandate MFA for all ePHI access |
| Email unencrypted | Critical | Deploy S/MIME or appliance encryption |
| Logs not centralized | Medium | Deploy SIEM; parse logs daily |
| Vendors not assessed | High-risk | Audit vendor controls; request attestation |
| Patch delays | Critical | Automate patching; 15-day SLA |
| No incident response plan | Critical | Write IRP; test quarterly |
| Contractor access not logged | Medium | Deploy access logging; monthly review |
| Configuration drift | Medium | Deploy configuration management tool |

---

## HITRUST vs. Other Frameworks

| Framework | Scope | Rigor | Cost |
|---|---|---|---|
| **HIPAA** | Privacy/Security | Low–Medium | $0 (self-audit) |
| **HITRUST** | Security + Compliance + Governance | High | $5K–$100K (3rd-party) |
| **ISO 27001** | Generic information security | High | $10K–$50K |
| **SOC 2 Type II** | Generic controls + operational security | Medium–High | $10K–$30K |
| **PCI-DSS** | Payment card data only | Medium | $0–$20K |

**For healthcare**: HITRUST is the standard. Use it unless you have specific reason not to (e.g., you're **only** holding HIPAA data and have no enterprise customers requiring certification).

---

*Created: 2026-07-15*
