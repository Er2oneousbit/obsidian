# FERPA (Family Educational Rights and Privacy Act)

#Compliance #Privacy #FERPA #DataProtection #Regulatory

## What is this?

**Family Educational Rights and Privacy Act (FERPA)** — US federal law protecting student educational records and privacy. Applies to schools, colleges, and universities that receive federal education funding. Gives students and parents rights to access, review, and challenge records; restricts disclosure to third parties.

---

## Overview

**FERPA Basics:**
- **Scope**: Educational records (grades, transcripts, disciplinary records, financial aid, psychological evaluations, health info).
- **Who it applies to**: Any school/college receiving federal education funding (virtually all US institutions).
- **Penalties**: Loss of federal education funding (death knell for schools); not monetary fines like GDPR/GLBA.
- **Focus**: Student privacy, parental/student access rights, restrictions on disclosure.

**Key Distinction:**
- **FERPA** = education records; education-specific law.
- **HIPAA** = health records; requires separate medical privacy compliance.
- **GDPR/CCPA** = broader personal data; FERPA is narrower but stricter for education sector.

**Enforcement**: U.S. Department of Education, Student Privacy Policy Office (SPPO).

---

## Who Must Comply?

### Schools & Institutions
- Elementary, middle, high schools (public and private).
- Colleges and universities.
- School districts.
- Educational service agencies.

### Key Threshold
- Must receive federal education funding (Title IV funds, grants, subsidized student loans, etc.).
- Nearly all US institutions receive some federal funding, so FERPA applies.

### Non-Educational Service Providers
- Vendors (software, testing, tutoring) that schools use may handle student data but are typically not directly subject to FERPA (school is liable; requires contract/DPA).

---

## Core FERPA Principles

### 1. Right to Access & Review

**Students and Parents have the right to:**
- Access student educational records within 45 days of request.
- Review contents and receive copies.
- Request clarification/correction if inaccurate.

**Who can access:**
- **Student** (if 18+ or attending post-secondary institution).
- **Parent** (if student under 18).
- **Authorized school staff** (need-to-know for job responsibility).

**School must provide**: Copies of records, clarifications, opportunity to challenge inaccuracy.

---

### 2. Restrictions on Disclosure

**Schools cannot disclose student records without consent, except to:**

#### Authorized School Personnel
- Teachers, counselors, staff with educational interest (curriculum planning, grading, discipline).

#### Parents/Students
- Upon request; no restrictions (they own their records).

#### Other Schools/Districts
- If student transfers; no parental consent needed if transferring to enroll.

#### School Officials with Legitimate Educational Interest (LEI)
- Staff who need records for job responsibilities.
- Must be defined in school policy (not unlimited).

#### Judicial Orders / Subpoenas
- Court order, subpoena, or law enforcement request.

#### Directory Information (Exception)
- Schools can disclose directory info (name, address, phone, email, dates of attendance, degrees/honors) without consent **unless student opts out**.
- Must provide opt-out mechanism.

#### Public Records Exemption (Limited)
- Disciplinary records of registered sex offenders (law enforcement request).

#### Health/Safety Emergency
- If imminent danger to student or others, schools can disclose to appropriate parties.

---

### 3. Parental/Student Rights

#### Right to Inspect and Review
- Access records within 45 days.
- School may request written request; cannot charge excessive fees.

#### Right to Seek Amendment
- If student/parent believes record is inaccurate/misleading:
  1. Request amendment in writing.
  2. School has 30 days to respond.
  3. If school refuses: student has right to hearing; can add statement to record.

#### Right to Restrict Disclosure
- Parents/students can restrict "directory information" disclosure via opt-out.
- Can also request other disclosures be restricted (no consent = no release).

#### Right to FERPA Complaint
- If school violates FERPA, student/parent can file complaint with U.S. Department of Education SPPO.

---

## FERPA Compliance Requirements

### Administrative Safeguards

#### Written Policy
- [ ] FERPA policy documented and provided to parents/students at least annually.
- [ ] Policy must explain:
  - Types of educational records maintained.
  - Student/parent access rights.
  - What is directory information (and opt-out process).
  - Who can access records without consent (LEI).
  - Procedures for amendment requests.

#### Authorized Personnel Only
- [ ] Define "legitimate educational interest" (LEI) in writing.
- [ ] Train staff on what records they can access.
- [ ] Separate access by role (teachers only see their classes; counselors may see all).

#### Opt-Out Mechanism
- [ ] Provide easy mechanism for parents/students to opt out of directory information disclosure.
- [ ] Honor opt-out requests; no records disclosed without consent.

---

### Technical Safeguards

#### Access Control
- [ ] Authentication: users must log in (username + password).
- [ ] Authorization: access based on role (teacher sees own class; admin sees all).
- [ ] Least privilege: staff access only what they need.
- [ ] Inactive accounts disabled (30–90 days).

#### Encryption
- [ ] Data at rest: student records encrypted (AES-256) on servers, laptops, backups.
- [ ] Data in transit: HTTPS (TLS 1.2+) for all access to student information systems.
- [ ] Encryption keys: stored securely; rotated regularly.

#### Audit Logging
- [ ] Log all access to student records (who accessed what, when).
- [ ] Retain logs for at least 2 years.
- [ ] Monitor for unusual access patterns (teacher accessing wrong class, after-hours access).
- [ ] Investigate suspicious access; document findings.

#### Network Security
- [ ] Firewall protecting student information systems.
- [ ] Intrusion detection (IDS) for anomalous access.
- [ ] VPN for remote access to student records.
- [ ] Network segmentation (student data isolated from public-facing systems).

#### Backup & Recovery
- [ ] Regular backups (daily/weekly) of student records.
- [ ] Backups encrypted and stored off-site.
- [ ] Test restores to ensure backups work.
- [ ] Define RTO/RPO for student information systems.

---

### Breach Notification

> [!note]
> **FERPA itself imposes no breach-notification requirement** and no monetary penalties. The steps below are best practice; actual notification duties come from **state breach-notification laws** (triggered when SSNs/PII are exposed). FERPA's own remedy for improper disclosure is potential loss of federal funding — which the Department of Education has never actually invoked.

**If student records are breached (unauthorized access/disclosure):**

#### Notification Timeline
- Without unreasonable delay (typically interpreted as 30 days).
- Notify affected students and parents.

#### What to Include
- Description of the breach.
- Type of records accessed/disclosed.
- Steps students can take (credit monitoring if SSN was in records).
- School's response (how breach was discovered, steps to prevent future breaches).

#### Additional Notices
- Follow applicable **state** breach-notification law (FERPA has no federal breach-reporting duty).
- Notify law enforcement if criminal activity involved.
- Consider credit monitoring service (especially if SSN disclosed).

---

## FERPA vs. HIPAA

**Confusion Point**: Student health/medical records.

| Area | FERPA | HIPAA |
|---|---|---|
| **Scope** | All educational records | Health records only |
| **Student health records (in school clinic)** | Primarily FERPA | Also HIPAA (if school operates clinic as healthcare provider) |
| **Psychoeducational evaluations (for special ed)** | FERPA | Not HIPAA (not medical treatment) |
| **School counselor notes** | FERPA | Not HIPAA (counseling, not medical) |
| **Parent access** | Broad (can access most records) | Limited (therapist notes privileged) |
| **Disclosure without consent** | Limited exceptions | More exceptions (health/safety, treatment coordination) |

**For school health clinics:** Comply with **both** FERPA and HIPAA.

---

## FERPA Compliance Checklist

### Policies & Procedures
- [ ] FERPA policy written and distributed annually.
- [ ] LEI definition documented.
- [ ] Directory information defined; opt-out mechanism published.
- [ ] Amendment/challenge procedures documented.
- [ ] Breach notification procedures written.
- [ ] Record retention/destruction policy documented.

### Access Control
- [ ] All staff trained on FERPA; training documented.
- [ ] Access based on role; least privilege enforced.
- [ ] Staff know what records they can access and why.
- [ ] Privileged accounts (admin) separate from staff accounts.
- [ ] Inactive accounts disabled within 90 days.
- [ ] Contractor access (tutors, vendors) restricted to necessary records.

### Technical Security
- [ ] MFA for all access to student information systems.
- [ ] Encryption at rest (AES-256); keys in HSM or secure key store.
- [ ] HTTPS (TLS 1.2+) for all web access.
- [ ] Logging enabled; all access to student records logged.
- [ ] Logs retained 2+ years; reviewed regularly.
- [ ] Firewall protecting student data systems.
- [ ] IDS/IPS monitoring for intrusions.
- [ ] Antivirus on all systems; real-time scanning.
- [ ] Patch management: critical patches within 30 days.

### Vendor Management
- [ ] Contracts with vendors include data protection clauses.
- [ ] Vendors (software, testing, tutoring) must comply with FERPA.
- [ ] Service agreements (SLAs) define data security requirements.
- [ ] Vendor access restricted to necessary records only.
- [ ] Vendor security audits conducted annually.
- [ ] Incident notification SLA (24–48 hours).

### Backup & Disaster Recovery
- [ ] Daily/weekly backups of student records.
- [ ] Backups encrypted and stored off-site (geographic separation).
- [ ] Test restore procedures; document results.
- [ ] RTO/RPO defined for student information systems.

### Student/Parent Access
- [ ] Parents/students can request access within 45 days.
- [ ] Opt-out mechanism for directory information (easy, clear).
- [ ] Amendment request process documented; 30-day response timeline.
- [ ] Records tracking (who accessed what).

### Breach Response
- [ ] Incident response plan includes breach notification procedures.
- [ ] Investigation timeline (30 days from discovery).
- [ ] Notification template prepared.
- [ ] SPPO notification procedure documented.
- [ ] Credit monitoring service arranged (if SSN in breach).

---

## Common FERPA Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No access control (all staff can see all records) | Unauthorized access; privacy violation | Implement RBAC; train staff on LEI; audit access logs |
| No encryption | Breach if system compromised; data stolen | Encrypt data at rest (full-disk, database); TLS in transit |
| Directory info disclosed without opt-out | FERPA violation | Publish directory info definition; provide easy opt-out; track opt-outs |
| No logging | Can't detect unauthorized access; audit failure | Log all access; retain logs 2+ years; review regularly |
| Slow breach response | Regulatory violation; reputational damage | Document incident response plan; 30-day investigation timeline |
| Vendor access not restricted | Vendor accesses data unnecessarily; breach risk | Limit vendor access to specific records; audit vendor access; SLA in contracts |
| No FERPA training | Staff violate FERPA unknowingly | Mandatory annual training; track attendance; role-specific training |
| Paper records not secured | Physical breach; records stolen | Lock filing cabinets; limit physical access; destroy old records securely |

---

## FERPA Enforcement

### Complaint Process
1. **Student/parent files complaint** with U.S. Department of Education SPPO.
2. **SPPO investigates** (30–60 days typical).
3. **School responds** to SPPO findings.
4. **If violation found**: SPPO orders corrective action; may recommend loss of federal funding.

### Consequences
- **Loss of federal education funding** (most severe; many schools can't survive without it).
- **Reputational damage** (breach becomes public; enrollments decline).
- **Civil liability** (students can sue for damages).
- **No monetary fines**, but funding loss is existential threat for schools.

### Real-World Examples

- **K-12 and university breaches** (ransomware, misconfigured student information systems) have repeatedly exposed student records, drawing Department of Education scrutiny and corrective-action plans.
- Note: in practice FERPA enforcement is corrective action, not funding withdrawal — the Department has never actually cut a school's funding over FERPA.

---

## FERPA for Penetration Testers

**How FERPA applies to pentesting:**

1. **Scope**: Testing any school/college student information system requires FERPA compliance assessment.
   - Access control properly implemented?
   - Encryption enabled?
   - Logging/monitoring adequate?
   - Vendor access restricted?

2. **Critical Findings** (FERPA-specific):
   - **Unencrypted student records in transit** (no HTTPS).
   - **No authentication** for student system access.
   - **Excessive access permissions** (all staff can see all records; violates LEI).
   - **No logging** (can't track who accessed records).
   - **Unencrypted backups** (containing student data).
   - **Vendor access uncontrolled** (vendor can see all student records).

3. **Regulatory Framing**:
   - Map findings to FERPA requirements.
   - Example: "No HTTPS on student information system violates FERPA data protection requirement; student records transmitted in plaintext."

4. **Remediation**:
   - Frame using school/education language (not just security jargon).
   - Example: "Implement FERPA-compliant access control: define LEI roles, restrict staff access to records they need, audit access logs monthly."

---

## Quick Implementation Roadmap

### Phase 1: Immediate (Month 1)
- [ ] Write/update FERPA policy; distribute to staff/parents.
- [ ] Enable encryption on student data systems (at rest + in transit).
- [ ] Implement access control (role-based; staff see only what they need).
- [ ] Enable logging for all student record access.
- [ ] Establish breach notification procedure.

### Phase 2: Operational (Months 2–3)
- [ ] Train all staff on FERPA (annual training, documented).
- [ ] Audit vendor contracts for FERPA compliance.
- [ ] Set up regular access log review (monthly).
- [ ] Test backup/restore procedures.
- [ ] Implement incident response drill.

### Phase 3: Compliance (Months 4–6)
- [ ] Quarterly vulnerability scans on student systems.
- [ ] Annual audit of access control (who has what access).
- [ ] Vendor security assessment.
- [ ] Incident response tabletop exercise.
- [ ] Documentation package for SPPO (if audit required).

---

## Directory Information & Opt-Out

**Directory Information** (schools can disclose without consent unless opted out):
- Student name
- Address
- Telephone number
- Email address
- Dates of attendance
- Degrees/honors received
- Class schedule

**Opt-Out Mechanism:**
- Schools must provide easy opt-out (checkbox on form, online portal, etc.).
- No penalties for opting out.
- Opt-out affects only directory info; other records still protected.

**Best Practice**: Get explicit opt-in (instead of opt-out) to be extra cautious; overcomplies with FERPA.

---


## See also

[[GDPR]], [[HIPAA]], [[GLBA]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
