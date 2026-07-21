# GLBA (Gramm-Leach-Bliley Act)

#Compliance #Privacy #GLBA #Financial #Regulatory

## What is this?

**Gramm-Leach-Bliley Act (GLBA)** — US federal law regulating financial institutions and protecting consumer financial privacy. Applies to banks, credit unions, insurance companies, and any organization handling consumers' financial information (account numbers, Social Security numbers, payment card data, credit history).

---

## Overview

**GLBA Basics:**
- **Scope**: Any organization that provides financial services or handles consumer financial data.
- **Fines**: Up to $100K+ per violation; potential criminal liability.
- **Focus**: Privacy, security, and safeguarding of non-public personal information (NPI).

**Key Distinction from HIPAA/GDPR:**
- **HIPAA** = health data only.
- **GDPR** = any personal data of EU residents.
- **GLBA** = financial data specifically; US focus, but applies globally to financial institutions operating in the US.

**Versions**: Original GLBA (1999); Privacy Rule & Safeguards Rule enforced since 2001. Safeguards Rule substantially updated in 2023 (new comprehensive security standards).

---

## Who Must Comply?

### Financial Institutions
- Banks, credit unions, thrifts.
- Insurance companies, brokers, agents.
- Securities brokers, investment advisors, mutual funds.
- Real estate appraisers, mortgage brokers.
- Check cashers, auto dealers financing sales.

### Non-Financial Businesses Handling Financial Data
- Payment processors, billing services.
- Companies that collect SSN/account numbers (even if not the primary business).

### Key Threshold
- If you handle consumers' "non-public personal information" (financial data tied to an individual), GLBA likely applies.

---

## GLBA's Core Rules

GLBA's three classic components are the **Financial Privacy Rule**, the **Safeguards Rule**, and the **Pretexting Provisions** (criminalizing obtaining someone's financial information under false pretenses). The FTC's 2023 Safeguards amendment also added a **security-event notification** duty (below).

### 1. Financial Privacy Rule

**Goal**: Limit disclosure of consumer financial information to third parties.

**Requirements:**
- Provide privacy notice at account opening and annually thereafter.
- Privacy notice must disclose:
  - What information is collected.
  - How information is used.
  - With whom it's shared.
  - Consumer rights (opt-out).

**Consumer Rights:**
- **Opt-out**: Consumer can request you don't share their info with non-affiliated third parties.
- Must honor opt-out requests within 30 days.
- Opt-out must be "clear and conspicuous" (easy to do, not buried).

**Limitations:**
- Can share with service providers (if you've contracted for their services) without consent.
- Can share for legal/regulatory reasons (subpoena, court order).
- Can share with joint marketing partners (if consumer agreed).

**Exceptions:** Medical/health info, investment recommendations, credit reports (covered by separate laws).

---

### 2. Safeguards Rule (Revised 2023)

**Goal**: Implement comprehensive security to protect financial data from unauthorized access, theft, misuse.

**Requirements:**
- Develop and maintain a comprehensive information security program.
- Designate a Chief Information Security Officer (CISO) or equivalent.
- Conduct annual risk assessments identifying security vulnerabilities.
- Implement safeguards to protect against identified risks.

**2023 Safeguards Rule Updates** (significantly stricter):

#### Multi-Factor Authentication (MFA)
- MFA required for all user access to systems containing NPI.
- No exceptions for "trusted" locations.

#### Encryption
- Encryption required for data at rest (AES-256 or equivalent).
- Encryption required for data in transit (TLS 1.2+).
- Encryption key management: secure key storage, key rotation.

#### Access Control
- Implement least privilege; users get only necessary access.
- Separate duties (no single person controls critical transactions end-to-end).
- Disable unused accounts within 90 days.
- Privileged account management (PAM) for admin access.

#### Monitoring & Logging
- Enable logging on all systems; retain logs for at least 2 years.
- Monitor for suspicious activity (failed logins, privilege escalation).
- Review logs weekly at minimum.
- Implement intrusion detection/prevention (IDS/IPS).

#### Incident Response
- Written incident response plan.
- Plan must cover detection, investigation, containment, eradication, recovery.
- Notify consumers within reasonable time if breach occurs (typically within 30 days).
- Notify FTC and potentially credit bureaus if 500+ consumers affected.

#### Third-Party Management
- Audit third parties handling NPI (vendors, service providers, subprocessors).
- Contracts must include data protection and security requirements.
- Assess vendor security regularly (annually or per risk level).
- Terminate contract if vendor has material breach.

#### Secure Development
- Security built into software development lifecycle.
- Code review before deployment.
- Testing (static analysis, dynamic testing) before production.
- Security patches applied promptly (critical within 30 days).

#### Risk Assessment
- Annual risk assessment minimum (more frequently for high-risk systems).
- Identify threats, vulnerabilities, likelihood, impact.
- Document remediation plans for identified risks.
- Re-assess after security incidents or significant changes.

---

### 3. Security-Event Notification (2023 Safeguards Amendment)

The FTC's amended Safeguards Rule added a breach/security-event notification duty, effective **May 2024**:

- **Notify the FTC** of a "notification event" involving the **unencrypted NPI of 500+ consumers**, as soon as possible and **no later than 30 days** after discovery (via the FTC's online portal).
- The report covers the nature of the event, number of consumers affected, and the data involved.

> [!note]
> GLBA itself does **not** mandate direct-to-consumer breach notification — that is driven by **state breach-notification laws** (all 50 states) and, for banks, by prudential regulators (OCC/FDIC/Fed interagency guidance). Determine consumer-notification timing from the applicable state law, not GLBA.

---

## GLBA Compliance Checklist

### Organizational Structure
- [ ] CISO or equivalent designated; roles & responsibilities documented.
- [ ] Privacy officer appointed.
- [ ] Board/executive oversight of information security program.
- [ ] Security team dedicated (or outsourced to MSSP).

### Privacy Program
- [ ] Privacy notice written, clear, and provided to customers.
- [ ] Opt-out mechanism implemented (easy for customers to opt out).
- [ ] Privacy policy reviewed annually; updated if practices change.
- [ ] Customer opt-out requests honored within 30 days.

### Risk Assessment
- [ ] Annual risk assessment performed (documented, written).
- [ ] Threats identified (external attacks, insider threats, natural disasters).
- [ ] Vulnerabilities identified (weak authentication, unpatched systems, misconfigurations).
- [ ] Likelihood and impact estimated.
- [ ] Remediation roadmap created for identified risks.

### Access Control
- [ ] MFA implemented for all user access to systems containing NPI.
- [ ] Least privilege enforced (users have only necessary permissions).
- [ ] Accounts reviewed quarterly; excess access revoked.
- [ ] Admin accounts separate from regular accounts; privileged access managed (PAM).
- [ ] Inactive accounts disabled within 90 days.

### Encryption
- [ ] Data at rest encrypted (AES-256); keys managed securely (HSM).
- [ ] Data in transit encrypted (TLS 1.2+).
- [ ] Encryption keys rotated annually.
- [ ] Key storage and access restricted (separation of duties).

### Monitoring & Logging
- [ ] Logging enabled on all systems; logs centralized (SIEM, log aggregator).
- [ ] Logs retained for 2+ years (regulatory may require longer).
- [ ] Real-time alerting for suspicious activity (SIEM rules, thresholds).
- [ ] Weekly manual log review (documented).
- [ ] IDS/IPS deployed on network perimeter and critical systems.

### Patch Management
- [ ] Vulnerability scanning performed monthly (internal) and quarterly (external).
- [ ] Critical patches applied within 30 days.
- [ ] High-priority patches within 60 days.
- [ ] All patches tested in staging before production.
- [ ] Patch deployment tracked and audited.

### Secure Development (If Building Financial Apps)
- [ ] Secure coding standards documented and enforced.
- [ ] Code review required before deployment.
- [ ] Static analysis (SAST) tools used to detect vulnerabilities.
- [ ] Dynamic testing (DAST) and penetration testing performed pre-release.
- [ ] Security testing results documented.

### Third-Party Management
- [ ] Vendor inventory maintained (all third parties handling NPI).
- [ ] Vendor security requirements defined in contracts.
- [ ] Vendor security questionnaires completed.
- [ ] SOC 2/ISO 27001 certifications verified.
- [ ] Annual vendor security audits scheduled.
- [ ] Subprocessor agreements in place (vendors' vendors also vetted).
- [ ] Incident notification SLA defined (24–72 hours).

### Incident Response
- [ ] Written incident response plan (documented, distributed).
- [ ] Incident response team identified and trained.
- [ ] Incident severity levels defined (P1/P2/P3).
- [ ] Escalation procedures documented.
- [ ] Incident response drills conducted at least annually.
- [ ] Forensics capability available (evidence preservation, log analysis).
- [ ] Post-incident root cause analysis (RCA) and lessons learned documented.

### Breach Notification
- [ ] Breach notification procedures documented.
- [ ] Consumer notification template prepared.
- [ ] FTC notification process defined.
- [ ] Credit bureau notification procedures ready.
- [ ] Incident investigation timeline (30-day default).

### Training & Awareness
- [ ] Annual security training for all staff (mandatory).
- [ ] Role-specific training (developers on secure coding, admins on hardening, finance on phishing).
- [ ] Training attendance tracked and documented.
- [ ] Phishing simulations conducted monthly; coaching for repeat offenders.
- [ ] Data handling procedures trained and reinforced.

### Vendor & Contractor Management
- [ ] Contracts include security clauses (data protection, breach notification, audit rights).
- [ ] Contractors/vendors trained on GLBA/data handling before access.
- [ ] Access revoked immediately upon contract termination.
- [ ] Equipment returned; data destroyed securely.

---

## GLBA Enforcement

### Regulators

**Primary enforcers:**
- **FTC** (Federal Trade Commission): Enforces for most institutions.
- **OCC** (Office of the Comptroller of the Currency): Federal banks.
- **Federal Reserve**: Bank holding companies.
- **FDIC** (Federal Deposit Insurance Corp): Federally insured banks.
- **Consumer Financial Protection Bureau (CFPB)**: Consumer financial services.

### Penalties

| Violation Type | Penalty |
|---|---|
| **Per-violation civil penalty** | Up to $100,000 |
| **Failure to safeguard NPI** | Up to $100K per violation; can compound across customers |
| **Criminal violation** (pretexting) | Fines + up to 5 years imprisonment (up to 10 for aggravated cases) |
| **Breach with 500+ customers** | Mandatory FTC/credit bureau notification; reputational damage; potential class-action lawsuits |

### Real-World Examples

- **Equifax (2019)**: up to $700M settlement (FTC/CFPB/states) for the 2017 breach exposing ~147M consumers.
- **Morgan Stanley (2020 & 2022)**: OCC ($60M) and SEC ($35M) penalties for failing to protect customer data when decommissioning storage devices.
- **FTC Safeguards Rule actions**: mortgage and fintech firms penalized for missing encryption, MFA, and access controls.

---

## GLBA vs. Other Financial Privacy Laws

| Law | Scope | Fines | Focus |
|---|---|---|---|
| **GLBA** | US financial institutions; financial data | Up to $100K+ per violation | Privacy notice, opt-out, security safeguards |
| **PCI-DSS** | Payment card data (any org processing cards) | Up to $100K+ per violation; card processor liability | Secure handling of payment card data |
| **HIPAA** | Health data only | Up to $1.5M per violation category/year | Privacy, security, breach notification |
| **GDPR** | Any personal data of EU residents | Up to €20M or 4% revenue | Stricter privacy controls, consent-based |
| **CCPA/CPRA** | Personal data of California residents | Up to $7.5K per violation | Consumer rights, disclosure, data portability |

**Key Difference**: GLBA is **prescriptive** on security (tells you what controls to implement); GDPR is **principle-based** (tells you privacy principles; you choose how to implement).

---

## GLBA for Penetration Testers

**How GLBA applies to pentesting:**

1. **Scope**: If testing a financial institution or any system handling NPI, GLBA compliance testing is critical.
   - MFA for all access?
   - Encryption at rest/in transit?
   - Logging enabled and reviewed?
   - Access control properly scoped?

2. **Finding Categories**:
   - **Critical**: Unencrypted NPI in transit, plaintext storage, no MFA for admin access, no logging, excessive access permissions.
   - **High**: Weak encryption (SSL 3.0, TLS 1.0), missing IDS/IPS, poor patch management, inadequate vendor management.
   - **Medium**: Missing specific controls (e.g., no formal privacy notice, no annual risk assessment, inadequate incident response plan).

3. **Regulatory Framing**:
   - Map findings to specific GLBA requirements (e.g., "Safeguards Rule 2023: MFA not implemented for NPI-containing systems").
   - Frame as compliance risk + security risk.

4. **Remediation Guidance**:
   - Use GLBA checklist items as roadmap; clients understand compliance language.
   - Example: "Implement Safeguards Rule requirements: enable MFA, encrypt data at rest/transit, deploy logging/SIEM, conduct quarterly access reviews."

---

## Quick Implementation Roadmap

### Phase 1: Quick Wins (Month 1)
- [ ] Designate CISO; assign roles/responsibilities.
- [ ] Enable MFA for all user access to NPI systems.
- [ ] Implement encryption (at rest: full-disk; in transit: TLS 1.2+).
- [ ] Configure basic logging; centralize logs.
- [ ] Write incident response plan; distribute to team.

### Phase 2: Maturity (Months 2–3)
- [ ] Conduct risk assessment; document findings.
- [ ] Implement access control (RBAC); quarterly access reviews.
- [ ] Deploy SIEM for monitoring/alerting.
- [ ] Vendor security audit; sign security addendums to contracts.
- [ ] Write/update privacy notice; implement opt-out mechanism.

### Phase 3: Compliance (Months 4–6)
- [ ] Annual training for all staff.
- [ ] Quarterly vulnerability scans; patch management SLA.
- [ ] Annual incident response drill.
- [ ] Documentation package for audit (risk assessment, SSP, logs, incident records).

---

## Common GLBA Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No MFA | Easy account takeover; NPI theft | Mandate MFA for all NPI system access |
| Unencrypted NPI in transit | Breach via MITM attack | Enforce TLS 1.2+ on all financial data transfers |
| Unencrypted NPI at rest | Breach if server compromised | Full-disk encryption (BitLocker); encrypt databases |
| No logging | Can't investigate breach; audit failure | Centralize logs; retain 2+ years; weekly review |
| Poor vendor management | Breach via third party (supply chain) | Vendor SOC 2/ISO 27001; annual audits; SLAs in contracts |
| No privacy notice | Violation of Privacy Rule | Write clear privacy notice; provide at account opening + annually |
| Slow breach response | Regulatory penalties; trust loss | Document incident response plan; 30-day investigation timeline |
| Inadequate access control | Excessive permissions; insider threat | RBAC; quarterly access reviews; separate dev/prod admin access |

---


## See also

[[GDPR]], [[HIPAA]], [[FERPA]], [[SOC-2-Type-II]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
