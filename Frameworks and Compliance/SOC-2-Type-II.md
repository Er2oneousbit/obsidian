# SOC 2 Type II

#Compliance #SOC2 #TrustServiceCriteria #Audit #SaaS

## What is this?

**Service Organization Control (SOC) 2 Type II** — US framework for auditing security, availability, processing integrity, confidentiality, and privacy controls of service organizations. De facto requirement for SaaS vendors, cloud providers, and managed service providers (MSPs). Conducted by CPAs; non-regulatory but customer-mandated.

---

## Overview

SOC 2 is **auditor-verified** (unlike HIPAA self-audit or PCI-DSS questionnaire). A third-party CPA firm audits your controls over a period of time (typically 6-12 months) and issues a report.

**Type I vs. Type II:**
- **Type I**: Point-in-time audit; tests controls exist at a single moment.
- **Type II**: Period audit; tests controls operated effectively over time (6–12 months minimum observation).

**Type II is the standard** — customers want proof controls work continuously, not just exist on paper.

---

## The 5 Trust Service Criteria

SOC 2 audits against **one or more of these 5 criteria**; most common is **CC (Common Criteria) + A (Availability) + P (Privacy)** or just **CC + A**.

### CC: Common Criteria (Security)

"Controls to protect customer data and systems from unauthorized access, use, or disclosure."

**Key Controls:**
- Access management: unique IDs, MFA, least privilege, segregation of duties.
- Encryption: data at rest (AES-256), in transit (TLS 1.2+).
- Logical/physical security: firewalls, intrusion detection, access controls.
- Change management: testing, approval, rollback procedures.
- Incident response: detection, investigation, remediation.
- Audit logging: comprehensive logs, retention, review.

> *Note: "Common Criteria" is SOC 2 terminology; don't confuse with CC ratings in other contexts.*

### A: Availability

"Controls to ensure the system is available for operation and use as committed."

**Key Controls:**
- Uptime commitments: SLA defined and monitored (e.g., 99.9%).
- Backup & recovery: daily backups, tested recovery procedures.
- Incident management: mean time to recovery (MTTR) tracked.
- Monitoring: real-time alerting for outages.
- Redundancy: failover systems, geographic distribution.

> *Tip: High availability is expensive; most SaaS targets 99.5–99.99% SLA.*

### PI: Processing Integrity

"Controls to ensure that system processing is complete, accurate, timely, and authorized."

**Key Controls:**
- Input validation: data format checks, range validation.
- Error handling: graceful failures, error logging.
- Processing controls: transactions logged, audit trail maintained.
- Data quality: reconciliation procedures, completeness checks.

> *Note: Often bundled with CC; less commonly audited standalone.*

### C: Confidentiality

"Controls to restrict access to confidential information."

**Key Controls:**
- Access restrictions: role-based, need-to-know.
- Encryption: sensitive data encrypted.
- Masking: PII redacted in logs/reports.
- Segregation: confidential data isolated from non-sensitive systems.

### P: Privacy

"Controls to collect, retain, disclose, and dispose of personal information consistent with privacy notices and commitments."

**Key Controls:**
- Data classification: identify what's personal data.
- Consent: documented user consent for data collection.
- Retention: data kept only as long as needed.
- Disclosure: controls on who can access personal data, with audit trail.
- Right to access: users can request their data.
- Data deletion: secure purge procedures.

> *Note: P is increasingly required by customers; overlaps with GDPR/HIPAA/CCPA.*

---

## SOC 2 Audit Process

### Pre-Audit (Month 0)

1. **Select Auditor**: Big 4 (Deloitte, EY, KPMG, PwC) or mid-size CPA firm.
   - Cost: $5K–$50K+ depending on org size.
   - Engagement letter: defines scope, criteria, observation period.

2. **Define Scope**: Which systems/services in scope? (Often just customer-facing app; may exclude legacy systems).

3. **Kickoff Meeting**: Auditor meets your team, understands architecture, identifies key controls.

### Observation Period (Months 1–12)

- **Auditor observes** controls in operation; doesn't test every transaction.
- **You document** control activities: who did what, when, why.
- **Auditor interviews** staff, reviews logs, traces transactions through system.
- **Testing samples**: auditor tests sample of transactions (e.g., 20 access requests out of 1000).

### Post-Audit (Month 13)

- **Fieldwork completion**: auditor finalizes testing, discusses findings.
- **Management response**: you respond to any control gaps found.
- **Report issuance**: auditor issues SOC 2 Type II report (valid 1 year; expires, not revoked).

---

## SOC 2 Report Sections

### Management's Assertion

You (management) state: "We've designed and maintained controls over [criteria] such that they were operating effectively."

### Auditor's Opinion

Auditor states: "In our opinion, [organization] maintained effective controls over [criteria] for the period [date–date]."

**Opinion Types:**
- **Unqualified (Clean)**: No issues; all controls effective.
- **Qualified**: Minor issues; controls mostly effective with exceptions noted.
- **Adverse**: Major control gaps; controls not effective.
- **Disclaimer**: Unable to assess (rare; usually data unavailable).

> *Tip: Customers want "unqualified" opinions; qualified is a red flag.*

### Detailed Control Testing

Auditor describes each control, how it operates, and test results:

**Example:**
- **Control**: "User access provisioning requires manager approval."
- **Test**: Auditor sampled 30 new user accounts; verified 28 had manager approval; 2 lacked evidence.
- **Result**: Control operating effectively with noted exception.

---

## Key SOC 2 Controls (CC Criterion)

### Access Controls

- Unique user IDs (no shared accounts).
- MFA for sensitive access (admin, database, ePHI if applicable).
- Password policy: 12+ characters, complexity, 90-day rotation.
- Access reviews: quarterly or annually; managers confirm access is still needed.
- Offboarding: access revoked within 1 hour of termination.
- Segregation of duties: developer ≠ approval ≠ deployment.

### Encryption

- **At rest**: AES-256 (or equivalent) for customer data + keys.
- **In transit**: TLS 1.2+ for all ePHI/PII; no self-signed certs in production.
- **Key management**: centralized, rotation annually, access logged.

### Change Management

- Change request: describe what's changing, why, risk assessment.
- Approval: change advisory board (CAB) or manager signs off.
- Testing: test in staging before production; rollback plan documented.
- Deployment: change tracked; post-deployment verification.
- Emergency changes: fast-tracked but still documented; formal review within 24 hours.

### Logging & Monitoring

- Logging: all ePHI access, admin actions, failed login attempts, config changes.
- Retention: 1 year minimum (auditor will check log age).
- Centralized logging (SIEM): not required but strongly recommended.
- Review: logs reviewed weekly by security team; monthly reports to management.

### Incident Response

- Written plan: detection, investigation, containment, remediation.
- Incident log: what happened, root cause, resolution, lessons learned.
- Testing: IR plan tested annually; findings addressed.

### Third-Party Management

- Vendor contracts: specify data protection, security requirements, audit rights.
- Risk assessments: before onboarding; ongoing monitoring.
- Audit rights: you have right to audit vendor controls (or demand SOC 2 from them).

---

## Common SOC 2 Findings

| Finding | Severity | Example | Fix |
|---|---|---|---|
| No MFA | Critical | Admins login with password only | Mandate MFA for all sensitive access |
| Weak password policy | High | Passwords can be 6 characters | Enforce 12+ characters, complexity |
| No change log | High | Can't prove who deployed what | Implement change tracking in deployment tool |
| Access not reviewed | High | User still has access after 2 years | Quarterly access review process |
| Logs not retained | High | Logs deleted after 30 days | Archive to long-term storage; 1 year retention |
| No incident response plan | Critical | No procedures for security events | Write IRP; test it |
| Vendor not audited | Medium | Cloud provider has unknown controls | Request SOC 2 from vendor or audit them |

---

## SOC 2 vs. Other Frameworks

| Framework | Audited | Time | Customer Acceptance | Cost |
|---|---|---|---|---|
| **SOC 2 Type II** | Yes (CPA) | 6–12 months | High (gold standard) | $5K–$50K |
| **ISO 27001** | Yes (3rd party) | Ongoing | High (global) | $10K–$100K |
| **HITRUST** | Yes (assessor) | 2 years | High (healthcare) | $5K–$100K |
| **HIPAA self-audit** | No | Continuous | Low (HIPAA minimum) | $0 |
| **PCI-DSS self-assessment** | No (unless merchant) | Annual | Medium (payment only) | $0–$20K |

**Why SOC 2 is popular:**
- Auditor-backed (customers trust third-party verification).
- Flexible scope (can audit just security, or also availability/privacy).
- Not prescriptive (auditor assesses *your* controls, not a checklist).
- Fast timeline (12 months for Type II vs. 2 years for HITRUST/ISO).

---

## Preparation Checklist (6 Months Before Audit)

- [ ] Select auditor; sign engagement letter.
- [ ] Define scope (which systems/services).
- [ ] Document control architecture (network diagram, data flows).
- [ ] Implement key controls: access management, encryption, logging, change management.
- [ ] Configure audit logging (ensure 1 year retention).
- [ ] Create/update incident response plan.
- [ ] Get audit rights into vendor contracts (or request SOC 2 from vendors).
- [ ] Quarterly access reviews; document and retain evidence.
- [ ] Monthly security incident log (if any incidents).
- [ ] Test disaster recovery / backup recovery.
- [ ] 3 months before: kickoff meeting with auditor.
- [ ] Monthly: review control activities with team.

---

## Post-Report: Maintaining Compliance

SOC 2 reports expire after 1 year. Plan for:

- **Months 11–12**: Begin planning next audit (auditor can do continuous updates, less expensive).
- **Continuous**: Maintain control effectiveness; document changes.
- **Annual**: Complete access reviews; incident log retained.
- **Monitor**: Keep controls operating; if major outage/incident occurs, be ready to disclose.

> *Note: If you have a control failure between audits and a customer asks, you must disclose. SOC 2 is not a "pass this once" — it's an ongoing commitment.*

---

## Common Misconceptions

| Myth | Reality |
|---|---|
| SOC 2 is a compliance requirement | **False** — it's customer-driven, not regulatory (except HIPAA/GDPR markets) |
| SOC 2 audit is pass/fail | **False** — report details findings; qualified opinion still acceptable |
| We're compliant if we pass SOC 2 | **False** — SOC 2 assesses controls, not necessarily all regulatory requirements (e.g., GDPR requires SOC 2 + more) |
| SOC 2 guarantees no breaches | **False** — SOC 2 audits controls, not outcomes; a breach doesn't invalidate the report (it shows a control failure) |
| We only need SOC 2 if we're SaaS | **False** — any service provider benefits (MSPs, cloud, APIs) |

---


## See also

[[ISO-27001-27002]], [[NIST-CSF]], [[HITRUST]], [[PCI-DSS-v4]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
