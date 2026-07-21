# HIPAA

#Compliance #Healthcare #HIPAA #PHI #Privacy #Regulatory

## What is this?

**Health Insurance Portability and Accountability Act** — US federal law requiring privacy, security, and breach notification safeguards for protected health information (PHI). Applies to covered entities (healthcare providers, plans, clearinghouses) and business associates.

---

## Overview

HIPAA comprises three main rules; compliance requires addressing all three:
1. **Privacy Rule** — controls use/disclosure of PHI
2. **Security Rule** — technical/physical/administrative safeguards for ePHI (PHI in electronic form)
3. **Breach Notification Rule** — notification requirements if PHI is compromised

---

## Who Must Comply?

### Covered Entities
- Healthcare providers (hospitals, clinics, doctors, dentists).
- Health plans (insurance, HMOs, employer plans, Medicare/Medicaid).
- Healthcare clearinghouses (intermediaries processing claims).

### Business Associates
- Any entity accessing, processing, or storing PHI on behalf of a covered entity.
- Examples: IT vendors, billing companies, cloud storage providers, transcription services.
- **Business Associate Agreement (BAA) required** between covered entity and associate.

> *Note: If you process healthcare data for a client, you need a BAA or you're violating HIPAA.*

---

## Privacy Rule

Controls how PHI can be used and disclosed.

### Permitted Uses & Disclosures

**Treatment, Payment, Operations (TPO):**
- Use PHI for treatment (diagnosis, care coordination).
- Use PHI for payment (billing, insurance claims).
- Use PHI for operations (management, training, audits).
- No explicit patient authorization needed for TPO.

**With Patient Authorization:**
- Disclosure outside TPO requires signed, dated authorization.
- Authorization must specify: what info, to whom, for what purpose, expiration date.
- Patient can revoke authorization in writing (effective upon receipt).

**Incidental Disclosure:**
- "Minimum necessary" standard: use/disclose only what's needed for stated purpose.
- Incidental disclosures (overheard conversations, glimpsed records) allowed if safeguards in place.

### Prohibited Disclosures

- **Marketing communications** — requires separate authorization.
- **Sale of PHI** — requires authorization; exceptions for treatment/operations.
- **Psychotherapy notes** — stricter protection; separate authorization required.
- **Genetic information** — separate authorization required.

### Patient Rights

- **Right to Access**: patient can request copy of their PHI (within 30 days, reasonable fee allowed).
- **Right to Amend**: patient can request correction of inaccurate records.
- **Right to Accounting of Disclosures**: patient can request list of who accessed their PHI (within 6 years, one per year free).
- **Right to Restrict**: patient can request limitation on use/disclosure (not binding for treatment).
- **Right to Confidential Communications**: patient can request alternative contact methods.

---

## Security Rule

Technical and administrative safeguards for ePHI.

### Administrative Safeguards

**Security Management Process:**
- Risk analysis: identify vulnerabilities and threats to ePHI.
- Risk mitigation: implement safeguards; document process.
- Sanctions policy: consequences for security violations.
- Information systems review: periodic evaluation of security effectiveness.

**Assigned Security Responsibility:**
- Security officer or equivalent designated.
- Responsible for implementing security policies and procedures.

**Workforce Security:**
- User IDs unique; access based on role.
- Emergency procedures for access authorization/termination.
- Separation of duties enforced (no one person controls entire chain).

**Information Access Management:**
- Access based on job classification.
- Minimum necessary principle: access limited to needed data.
- Access reviewed and updated regularly; revoked upon role change.

**Security Awareness Training:**
- Annual training for all staff accessing ePHI.
- Topics: security protocols, password management, phishing, breach procedures.
- Training documented.

**Security Incident Procedures:**
- Written procedures for identifying, reporting, investigating breaches.
- Incident log maintained (what happened, who handled it, outcome).
- Forensic analysis for significant incidents.

### Physical Safeguards

**Facility Access Control:**
- Physical access to servers, databases restricted (badge access, locks).
- Visitor logs maintained.
- Workstations positioned to prevent unauthorized viewing.

**Workstation Use & Security:**
- Policies define appropriate workstation use.
- Automatic logoff after inactivity.
- Screen privacy (privacy screens for sensitive data).
- USB/removable media restrictions.

**Device & Media Controls:**
- Inventory of devices containing ePHI.
- Secure disposal procedures (encryption, physical destruction).
- Reuse procedures if devices are repurposed.

### Technical Safeguards

**Encryption & Decryption:**
- ePHI at rest: encrypted (AES-256 or equivalent).
- ePHI in transit: TLS 1.2+ or VPN.
- Encryption keys managed securely.

**Audit Controls & Logging:**
- All access to ePHI logged (user, what data, when, what action).
- Log retention: minimum 6 years.
- Logs reviewed regularly for suspicious activity.

**Access Controls:**
- Unique user IDs for all ePHI access.
- Password requirements: minimum 8 characters, change every 90 days.
- Multi-factor authentication recommended (not required, but best practice).
- Emergency access procedures documented (break-glass accounts).

**Integrity Controls:**
- Mechanisms to ensure ePHI is not improperly altered or destroyed.
- Checksums, digital signatures, or version control.

**Transmission Security:**
- Encryption for data in transit (email, file transfer).
- Secure protocols (HTTPS, SFTP, not HTTP or FTP).
- VPN or equivalent for remote access.

---

## Breach Notification Rule

Required actions if unsecured PHI is lost, stolen, or accessed.

### What Constitutes a Breach?

- **Unauthorized acquisition, access, use, or disclosure** of PHI that compromises security/privacy.
- **Exception**: "Low probability that PHI has been compromised" (encryption, access logs showing no unauthorized access).

### Notification Timeline

- **Individuals**: within 60 calendar days of discovery of breach.
- **Media**: within 60 days if 500+ individuals affected (local/national press).
- **Secretary of HHS**: within 60 days if 500+ individuals affected; for breaches under 500, log and report annually (within 60 days after the calendar year ends).

### Notification Content

- **What happened**: describe the breach (what type of data, how it occurred, when).
- **Data exposed**: what PHI was compromised (names, SSNs, medical IDs, etc.).
- **Steps to take**: credit monitoring, fraud alerts, password changes.
- **Organization's response**: what's being done to prevent future incidents.

### Exceptions to Notification

- **Inadvertent disclosure** to authorized personnel in normal course of business.
- **Encrypted data** (if encryption key was not compromised).
- **Low risk of harm** (access logs show data was not actually viewed).

> *Note: If breach is discovered years later, notification still required. HIPAA has no statute of limitations.*

---

## Compliance by Organization Type

### Healthcare Providers
- Privacy & Security Rule: full compliance.
- Breach Notification: report to individuals + HHS + media (if applicable).
- Audit: documentation of privacy/security practices, incident logs.
- **Key focus**: patient access to records, secure messaging, staff training.

### Health Plans
- Privacy & Security Rule: full compliance.
- Special rule: coordination of benefits, claims processing.
- **Key focus**: claims database security, member communication security.

### Business Associates
- Bound by Business Associate Agreement (BAA).
- Security Rule compliance required (administrative, physical, technical safeguards).
- Breach Notification: notify the covered entity without unreasonable delay and no later than 60 days from discovery (BAAs often require faster contractually); the covered entity handles external notification.
- **Key focus**: subcontractor agreements (if you work with another vendor, they need a BAA too).

---

## Key HIPAA Misunderstandings

| Myth | Reality |
|---|---|
| HIPAA requires encryption | Only "addressable" - encryption recommended but de-identification alternative exists |
| HIPAA requires MFA | No; MFA recommended but not mandated; complex password + access controls acceptable |
| HIPAA requires 2-year breach notification window | **Wrong** — 60 calendar days from discovery, no limit on how old the breach is |
| Deidentified data is not PHI | Correct if 18 safe harbor identifiers removed + statistical verification; unclear if re-identification risk remains |
| HIPAA only applies to healthcare | **Wrong** — applies to anyone processing health data for covered entities (IT vendors, etc.) |
| Employee breach = no liability for employer | **Wrong** — employer liable if safeguards inadequate |

---

## Common Compliance Gaps

- No Business Associate Agreements with vendors.
- Email communication of PHI without encryption.
- Weak password policies (no complexity, infrequent changes).
- No access logs for ePHI databases.
- Missing breach response procedures.
- Inadequate staff training on PHI handling.
- Unsecured backups or archival.
- No audit trail for who accessed what data.
- Using personal devices without MDM (Mobile Device Management).

---

## Penalties for Non-Compliance

| Violation Type | Fine Range | Example |
|---|---|---|
| Unknowing violation | $100–$50,000 per violation | Discovered during audit; gaps in controls |
| Willful neglect (not corrected within 30 days) | $10,000–$1.5M per violation category per year | Ignored breach notification requirements |
| Criminal violations (knowingly obtaining/disclosing PHI) | Up to $250,000 fine + 10 years imprisonment | Selling patient data, unauthorized access |

> *Note: OCR (Office for Civil Rights) has actively pursued enforcement; average settlement is $1-10M.*

---


## See also

[[HITRUST]], [[GDPR]], [[GLBA]], [[FERPA]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
