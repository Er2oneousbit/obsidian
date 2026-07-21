# GDPR

#Compliance #Privacy #GDPR #DataProtection #Regulatory

## What is this?

**General Data Protection Regulation (GDPR)** — EU regulation protecting personal data of EU residents. Applies to any organization processing EU residents' data, **regardless of where the organization is located**. Fines up to €20M or 4% of global revenue (whichever is higher).

---

## Overview

GDPR is **stricter than HIPAA/CCPA** and **applies globally**. If you have even one EU resident as a customer/user, GDPR applies to you.

**Key Principle: Data Minimization** — collect only what's necessary; keep only as long as needed; give users control over their data.

---

## Who Must Comply?

### Controllers & Processors

- **Controller**: organization determining how/why personal data is processed (e.g., your SaaS company).
- **Processor**: organization processing data on behalf of controller (e.g., your cloud provider, payment processor).
- **Data Protection Officer (DPO)**: required if processing involves large-scale systematic monitoring or sensitive data processing. Many EU orgs appoint one voluntarily for credibility.

**Data Processing Agreement (DPA):** If you use processors (cloud, vendors), they need a signed DPA specifying data protection obligations.

---

## Core GDPR Principles

### 1. Lawfulness, Fairness, Transparency
- Processing must have a legal basis.
- Users must be informed (privacy policy).
- No deception.

### 2. Purpose Limitation
- Collect data for a specific purpose (e.g., "to fulfill your order").
- Don't repurpose data later without new consent or legal basis.
- Example: collect email for newsletter → later sell to third party = VIOLATION.

### 3. Data Minimization
- Collect only what's necessary.
- Don't collect "just in case."
- Example: e-commerce doesn't need birth date if not required for service.

### 4. Accuracy
- Keep personal data accurate & up-to-date.
- Remove inaccurate data.

### 5. Storage Limitation
- Keep data only as long as needed for the purpose.
- Example: if order fulfilled, don't keep order details indefinitely.
- Retention policy required; specify how long each data type is kept.

### 6. Integrity & Confidentiality
- Protect data from unauthorized access, modification, loss.
- Encryption, access controls, backups.

### 7. Accountability
- Prove compliance.
- Document decisions, processing activities, impact assessments.

---

## Legal Bases for Processing

You need **at least one** legal basis to process personal data:

### Consent
- User explicitly agrees to processing (checkbox, signature).
- Consent must be freely given, specific, informed, unambiguous.
- **Pre-ticked boxes = INVALID** (must be active consent).
- Consent can be withdrawn anytime.

**When to use**: optional data, newsletters, cookies for tracking.

### Contract
- Processing necessary to fulfill a contract with the user.
- Example: shipping address to deliver an order.
- **No consent needed** if it's necessary for the service.

**When to use**: customer info, billing, service delivery.

### Legal Obligation
- Processing required by law (tax, healthcare reporting, compliance audits).
- Example: keeping accounting records for 7 years.

**When to use**: regulatory/legal requirements.

### Vital Interests
- Processing necessary to protect someone's life or health.
- Example: emergency contact info in medical app.

**When to use**: rare; emergencies/safety.

### Public Task
- Processing necessary for a task carried out in the public interest.
- Example: government agencies, public institutions.

**When to use**: government/public sector only.

### Legitimate Interests
- Processing is in the organization's legitimate interest, **and** doesn't override user interests.
- Requires balancing test: does user have reasonable expectation of processing?
- Example: fraud prevention for payment processing (legitimate).
- Non-example: selling customer data to third party (not legitimate; user didn't expect it).

**When to use**: operational needs (fraud, security, improvement), but must balance against user interests.

---

## User Rights (The Right to...)

### 1. Access (Right to Know)
- User can request: "What personal data do you have on me?"
- Organization must provide: copy of data, in machine-readable format.
- Timeline: 30 days (can extend to 90 if complex).
- No fee (unless request is excessive).

### 2. Rectification (Right to Correct)
- User can request correction of inaccurate data.
- Organization must update within 30 days.
- No fee.

### 3. Erasure (Right to be Forgotten)
- User can request deletion of their data.
- Organization must delete **unless** there's a legitimate reason to keep it (legal obligation, fraud prevention, etc.).
- Timeline: 30 days.
- No fee.

### 4. Restrict Processing
- User can request: "Stop processing my data, but don't delete it."
- Organization must mark data as restricted; can only process if user consents or legal obligation exists.
- Use when user disputes accuracy but deletion isn't warranted.

### 5. Data Portability (Right to Move Data)
- User can request: "Give me my data in a portable format so I can move to another service."
- Format: machine-readable (CSV, JSON), not PDF.
- Organization must provide within 30 days.
- No fee.

### 6. Object
- User can object to processing on legitimate interests basis.
- Example: "Stop sending me marketing emails."
- Organization must stop (unless overriding interest, e.g., legal obligation).

### 7. Automated Decision-Making
- User can object to decisions based purely on automated processing (algorithms).
- Example: credit scoring, job application filtering.
- Organization must provide human review.

### 8. Withdraw Consent
- User can withdraw consent to processing anytime.
- Must be as easy to withdraw as to give.

---

## GDPR Compliance Requirements

### Privacy Policy
- Clear, plain language (not legal jargon).
- State: what data collected, why (legal basis), how long kept, who can access, user rights.
- Available at time of data collection.
- "Cookie consent" banners must link to detailed policy.

### Data Processing Agreement (DPA)
- If using processors (cloud, vendors, payment processors), they need signed DPA.
- DPA must specify: data types, processing scope, duration, security measures, confidentiality, liability.
- Standard DPA templates available (e.g., EU Commission template).

### Privacy Impact Assessment (DPIA)
- Required if processing involves high risk (large-scale collection, sensitive data, automated decision-making).
- Document: data types, recipients, risk assessment, mitigation measures.
- Keep for audits.

### Data Breach Notification
- If personal data is breached (unauthorized access/disclosure):
  - Notify supervisory authority within **72 hours**.
  - Notify affected users (unless data was encrypted/pseudonymized and key wasn't compromised).
  - Notification must include: what happened, data affected, likely consequences, steps taken.
- No notification needed if data was encrypted and attacker didn't obtain encryption key.

### Data Protection Officer (DPO)
- **Required if:**
  - You're a public authority.
  - Your core business involves large-scale systematic monitoring (e.g., surveillance).
  - You process special categories of data at scale.
- **Recommended if:**
  - You process lots of personal data.
  - You want to demonstrate commitment to GDPR.

---

## Special Categories of Data (Higher Protection)

Certain data gets **extra protection** — stricter rules on processing:

- **Biometric data**: fingerprints, facial recognition (high risk of discrimination).
- **Genetic data**: DNA analysis.
- **Health data**: medical records, diagnoses, treatment.
- **Race/Ethnicity**: can lead to discrimination.
- **Political opinions, religious beliefs**: freedom of thought concerns.
- **Trade union membership**: freedom of association.
- **Criminal data**: criminal convictions, offenses.

**General rule**: Don't process special category data unless you have explicit legal basis (explicit consent, or legal obligation like medical treatment).

---

## GDPR Enforcement & Penalties

### Supervisory Authorities
- Each EU country has a data protection authority (DPA).
- Example: Germany = Bundesdatenschutzamt (BfD).
- Users can file complaints with their national DPA.
- DPA investigates and can issue fines.

### Fines

| Violation Category | Fine Range | Example |
|---|---|---|
| **Lower tier** (Art. 83(4)) | Up to €10M or 2% of global annual turnover | Records/DPO/processor-agreement failures, weak security |
| **Upper tier** (Art. 83(5)) | Up to €20M or 4% of global annual turnover | Breaching core principles, legal basis, consent, or data-subject rights |

**Notable fines:**
- Amazon: €746M (2021, Luxembourg CNPD) — personalized advertising without valid consent; largest GDPR fine to date.
- Meta (Facebook): €1.2B (2023, Irish DPC) — unlawful EU→US personal-data transfers.
- Google: €50M (2019, France's CNIL) — lack of transparency and no valid consent for ad personalization.

---

## GDPR vs. Other Privacy Frameworks

| Framework | Scope | Geographic | Fines | Rigor |
|---|---|---|---|---|
| **GDPR** | Broad (any personal data) | EU/Global | Up to €20M or 4% | Very High |
| **CCPA/CPRA** | Broad (California residents) | California/US | Up to $7.5K per violation | High |
| **HIPAA** | Health data only | US | Up to $1.5M per violation category/year | High |
| **LGPD** | Broad (Brazil residents) | Brazil | Up to 2% annual revenue | High |
| **UK GDPR / DPA 2018** | Post-Brexit version of GDPR | UK | Up to £17.5M or 4% | Very High |

**Key difference**: GDPR is the strictest globally; CCPA/CPRA following similar model for US.

---

## Common GDPR Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No legal basis for processing | GDPR violation; DPA complaint possible | Document legal basis (consent, contract, etc.); update privacy policy |
| No DPA with vendors | GDPR violation; joint liability | Get signed DPA from all processors |
| Cookie consent not actually "consent" | GDPR violation (cookies need opt-in, not opt-out) | Implement proper consent banner; default deny cookies until user agrees |
| No retention policy | Data kept indefinitely (storage limitation violation) | Document retention periods per data type; auto-delete old data |
| Selling data without consent | GDPR violation (purpose limitation) | Only process data for stated purpose; get new consent for new purposes |
| Slow breach notification | GDPR violation; additional fines | Establish incident response process; 72-hour clock starts from discovery |
| No privacy policy | GDPR violation (transparency) | Write clear, plain-language privacy policy; publish before collecting data |

---

## Implementation Checklist (For SaaS / Website)

**Before Launch:**
- [ ] Identify all personal data you collect (name, email, IP, cookies, etc.).
- [ ] Document legal basis for each data type (consent, contract, legitimate interest, etc.).
- [ ] Write privacy policy; publish before collecting data.
- [ ] Implement consent banners (for cookies, marketing).
- [ ] Get DPA from all vendors/processors.
- [ ] Establish data retention policy; automate deletion if possible.
- [ ] Document processing activities (what data, why, how long, who can access).
- [ ] Conduct DPIA if processing high-risk data.
- [ ] If required, appoint Data Protection Officer.

**Ongoing:**
- [ ] Process user requests (access, deletion, portability) within 30 days.
- [ ] Monitor compliance; internal audits annually.
- [ ] Keep incident response plan updated; test incident notification process.
- [ ] Update privacy policy if processing changes.
- [ ] Train staff on GDPR (especially data handling, breach procedures).

---

## GDPR for Penetration Testers

**Security testing & GDPR:**
- Penetration testing requires explicit legal authorization (rules don't change for testing).
- If pentest involves personal data, document the legal basis (e.g., client authorization, contract clause).
- Use pseudonymized/anonymized data for testing when possible.
- Breach during pentest = must notify client within 72 hours.
- Client may have GDPR liability for your pentest; ensure contract includes liability clause.

---


## See also

[[HIPAA]], [[GLBA]], [[FERPA]], [[SOC-2-Type-II]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
