# NIST SP 800-53

#NIST #SP80053 #SecurityControls #Federal #Compliance

## What is this?

**NIST Special Publication 800-53** — Comprehensive catalog of security controls for federal information systems. Contains **1000+ controls** across 20+ families (Access Control, Audit, Cryptography, etc.). Prescriptive, detailed, and the de-facto standard for US federal contractors, DoD, and high-security organizations.

---

## Overview

**NIST SP 800-53 vs. Related Standards:**
- **NIST CSF** = high-level framework (6 functions); tells you what to do.
- **NIST SP 800-53** = detailed control catalog (1000+ controls); tells you how to implement it; prescriptive.
- **NIST SP 800-171** = tailored subset of 800-53 for non-federal contractors (CMMC, DoD). More digestible; ~110 controls.
- **ISO 27001** = international, process-focused; fewer controls (~93) but more flexible.

**When you need 800-53**: Federal contracts, DoD work, FISMA compliance, high-security environments (financial, healthcare, critical infrastructure).

**Versions:** 800-53 Rev. 4 (2013), **Rev. 5 (Sept 2020, current)** — flattened hierarchy, integrated privacy controls, added the SR and PT families, removed redundancy.

---

## Control Organization

800-53 Rev 5 organizes ~1000 base controls (1,190+ with enhancements) into **20 families**, each with a two-letter prefix:

| Family | Prefix | Focus |
|---|---|---|
| Access Control | AC | Who can access what; least privilege, session mgmt |
| Awareness & Training | AT | Staff training, awareness programs |
| Audit & Accountability | AU | Logging, audit trails, non-repudiation |
| Assessment, Authorization & Monitoring | CA | Security testing, FISMA authorization, ConMon |
| Configuration Management | CM | System baselines, change control, software integrity |
| Contingency Planning | CP | Backups, disaster recovery, business continuity |
| Identification & Authentication | IA | User identification, authentication (MFA), session mgmt |
| Incident Response | IR | Incident response procedures, testing, reporting |
| Maintenance | MA | System maintenance, patching, tools |
| Media Protection | MP | Data media handling, destruction, labeling |
| Physical & Environmental Protection | PE | Physical access, surveillance, environmental controls |
| Planning | PL | Security & privacy plans, rules of behavior |
| Program Management | PM | Organization-wide security program governance |
| Personnel Security | PS | Background checks, termination, position risk |
| PII Processing & Transparency | PT | Privacy: consent, purpose, PII handling (new in Rev 5) |
| Risk Assessment | RA | Risk assessment methodology, vuln scanning |
| System & Services Acquisition | SA | Secure SDLC, procurement, developer testing |
| System & Communications Protection | SC | Encryption, segmentation, boundary protection |
| System & Information Integrity | SI | Malware, monitoring, flaw remediation |
| Supply Chain Risk Management | SR | Third-party/vendor security (new in Rev 5) |

---

## Control Structure

Each control has:

**Control ID**: AC-2 (family + number)
**Title**: Account Management
**Statement**: What the control requires (the "must do").
**Guidance**: Implementation guidance, examples, considerations.
**Control Enhancements (CEs)**: Optional additional requirements (e.g., AC-2(1) Automated Account Mgmt).

### Control Baseline Levels

Controls are grouped into three **impact baselines** (FIPS 199):

- **Low Impact**: Non-critical systems (basic availability, no major confidentiality risk). ~149 controls (per SP 800-53B).
- **Moderate Impact**: Important systems (significant availability/confidentiality/integrity impact). ~287 controls.
- **High Impact**: Critical systems (major impact if compromised). ~370 controls.

Most federal systems target **Moderate** baseline.

---

## Major Control Families (Summary)

### AC — Access Control (10+ controls)

**Goal**: Implement least privilege; control who accesses what.

**Key Controls:**
- **AC-2 Account Management**: Provision/deprovision accounts; privileged accounts separate; disable inactive accounts.
- **AC-3 Access Enforcement**: Role-based access control (RBAC); enforce least privilege.
- **AC-4 Information Flow Enforcement**: Control data flow between systems (no unauthorized data movement).
- **AC-5 Separation of Duties**: No single person controls critical transactions end-to-end.
- **AC-6 Least Privilege**: Users get minimum access needed; need-to-know basis.

**Implementation**: LDAP/Active Directory for identity; RBAC for authorization; regular access reviews; privileged account management (PAM).

---

### AT — Awareness & Training (3+ controls)

**Goal**: Train staff on security; reduce human error.

**Key Controls:**
- **AT-1 Security Awareness & Training Program**: Mandatory annual training for all staff.
- **AT-2 Specialized Training**: Role-specific training (developers on secure coding, admins on hardening).
- **AT-3 Role-Based Training**: Training tailored to job function.

**Implementation**: Security awareness platform (KnowBe4, Proofpoint); annual training; track attendance; phishing simulations.

---

### AU — Audit & Accountability (10+ controls)

**Goal**: Log everything; retain audit trails; detect/investigate incidents.

**Key Controls:**
- **AU-2 Audit Events**: Define what to log (failed logins, privilege changes, file access, config changes).
- **AU-3 Content of Audit Records**: Logs must include: who, what, when, where, outcome, source.
- **AU-4 Audit Storage Capacity**: Logs retained; storage doesn't overflow (will lose audit trail).
- **AU-6 Audit Review, Analysis, & Reporting**: Regular review of logs (weekly/monthly); investigate anomalies.
- **AU-12 Audit Generation**: Enable logging on all systems and applications.

**Implementation**: Centralized logging (Splunk, ELK, Azure Monitor); log retention policy (1-7 years); SIEM for alerting; monthly audit log review.

---

### CA — Assessment & Authorization (5+ controls)

**Goal**: Test security; authorize systems for operation (FISMA ATO process).

**Key Controls:**
- **CA-2 Security Assessments**: Conduct security testing (vulnerability scans, penetration tests).
- **CA-6 Authorization**: Formal authorization to operate; ATO letter from authorizing official.
- **CA-7 Continuous Monitoring**: Ongoing security testing; track compliance continuously (not just at authorization).

**Implementation**: Annual vulnerability scans + penetration tests; FISMA SSP (System Security Plan) documentation; authority to operate letters; quarterly compliance reporting.

---

### CM — Configuration Management (7+ controls)

**Goal**: Maintain system baselines; control changes; prevent unauthorized modifications.

**Key Controls:**
- **CM-1 Configuration Change Control**: Formal change management; changes approved by CCB (Change Control Board) before implementation.
- **CM-2 Baseline Configuration**: Define baseline for each system type (OS, applications, firewall rules).
- **CM-3 Configuration Change Control**: Test changes in staging; approve before prod; rollback procedures.
- **CM-5 Configuration Control Implementation**: Enforce baselines via configuration management tools (Ansible, Puppet).
- **CM-6 Configuration Settings**: Configure systems per approved baseline; remove unnecessary services.

**Implementation**: Configuration management tool (Ansible, Puppet, Chef); version-control for configs; staging/prod environments; change review board; automated compliance checking.

---

### IA — Identification & Authentication (5+ controls)

**Goal**: Verify who users are; require strong authentication.

**Key Controls:**
- **IA-2 Authentication**: Require authentication for all users; use strong methods (passwords + MFA).
- **IA-4 Identifier Management**: Unique identifiers for users; inactive accounts disabled.
- **IA-5 Authentication Mechanisms**: Password policy (12+ chars, complexity, rotation every 60–90 days); support MFA (TOTP, hardware tokens).

**Implementation**: LDAP/AD for centralized identity; enforce MFA (Duo, Okta); password manager; disable accounts after 60 days inactivity.

---

### IR — Incident Response (8+ controls)

**Goal**: Prepare for incidents; respond quickly; learn from incidents.

**Key Controls:**
- **IR-1 Incident Response Policy**: Incident response plan; roles, procedures, escalation.
- **IR-4 Incident Handling**: Procedures for containment, eradication, recovery.
- **IR-6 Incident Reporting**: Report incidents to oversight authorities (if breach).
- **IR-8 Incident Response Testing**: Annual incident response drills (tabletop, simulation).

**Implementation**: Incident response runbooks; incident response team; 24/7 on-call rotation; incident tracking system; annual IR drills.

---

### MA — Maintenance (3+ controls)

**Goal**: Maintain systems securely; prevent unauthorized modifications during maintenance.

**Key Controls:**
- **MA-2 Controlled Maintenance**: Maintenance activities logged; maintenance tools secured.
- **MA-4 Remote Maintenance**: Remote access restricted (VPN + MFA); session recording.

**Implementation**: Remote maintenance via bastion host + VPN; session recording; maintenance window approvals; audit logs of all maintenance activities.

---

### PE — Physical & Environmental Protection (14+ controls)

**Goal**: Secure data centers; control physical access; monitor for environmental hazards.

**Key Controls:**
- **PE-2 Physical Access**: Badge access to data centers; visitor logs; segregated secure areas.
- **PE-3 Physical Access Devices**: Badge readers, biometric access, multi-factor physical access.
- **PE-6 Monitoring Physical Access**: CCTV surveillance; alerts for unauthorized entry.
- **PE-12 Emergency Lighting**: Backup power; egress signs; evacuation procedures.
- **PE-13 Fire Protection**: Fire suppression (sprinklers, FM-200 gas for server rooms).
- **PE-14 Temperature, Humidity, Air Quality**: Environmental controls; alerting for out-of-range conditions.

**Implementation**: Secured server room with badge access + CCTV; biometric access for sensitive areas; environmental monitoring (temperature, humidity); backup generators.

---

### PL — Planning (4+ controls)

**Goal**: Plan security upfront; establish security strategy.

**Key Controls:**
- **PL-1 Security Planning**: Organization-wide security plan; roles, responsibilities, strategic direction.
- **PL-2 System Security Plan**: Per-system security plan; scope, threat model, controls selected, residual risk.
- **PL-10 System Security Plan (Security Categorization)**: Categorize systems by impact level (Low/Moderate/High).

**Implementation**: Security strategy document; per-system SSPs (System Security Plans); FIPS 199 categorization; security architecture reviews.

---

### SA — System & Services Acquisition (9+ controls)

**Goal**: Ensure security in procurement and development.

**Key Controls:**
- **SA-3 System Development Life Cycle (SDLC)**: Security requirements in every SDLC phase (requirements, design, implementation, testing, deployment).
- **SA-4 Acquisition Process**: Procurement includes security requirements; vendor SOC 2/ISO 27001 attestation requested.
- **SA-11 Developer Testing & Analysis**: Code review, static analysis, dynamic testing in development (not just in production).
- **SA-15 Development Process, Standards & Tools**: Use secure development practices; code repositories version-controlled; automated CI/CD with security gates.

**Implementation**: Secure SDLC (OWASP Secure Coding, NIST SP 800-218); code review process; automated security testing (SAST/DAST); vendor security questionnaires; procurement security requirements.

---

### SC — Systems & Communications Protection (15+ controls)

**Goal**: Protect data in transit; segment network; encrypt sensitive data.

**Key Controls:**
- **SC-4 Information Confidentiality & Integrity**: Encryption for data at rest (AES-256) and in transit (TLS 1.2+).
- **SC-7 Boundary Protection**: Network boundary enforcement (firewall); DMZ for public systems; internal network protected.
- **SC-8 Transmission Confidentiality & Integrity**: Encrypt data in transit (TLS); protect against MITM attacks.
- **SC-12 Cryptographic Key Establishment & Management**: Key generation, rotation, storage in HSM; key escrow procedures.
- **SC-13 Cryptography**: Use NIST/NSA-approved algorithms (AES, SHA-256, RSA); no weak ciphers.

**Implementation**: TLS 1.2+ on all HTTPS; IPsec for site-to-site; full-disk encryption; HSM for key storage; network segmentation.

---

### SI — System & Information Integrity (10+ controls)

**Goal**: Detect/prevent malware; monitor system health; keep systems updated.

**Key Controls:**
- **SI-2 Flaw Remediation**: Patch management; critical patches within 15 days, non-critical within 30 days.
- **SI-3 Malware Protection**: Antivirus on all endpoints; real-time scanning; signature updates automatic.
- **SI-4 Information System Monitoring**: Continuous monitoring for intrusions, anomalies; alerting.
- **SI-7 Software, Firmware & Information Integrity**: File integrity monitoring (Tripwire, ossec); detect unauthorized changes.
- **SI-12 Information Handling & Retention**: Data classification; handling procedures per classification.

**Implementation**: Vulnerability scanner; automated patching; antivirus; SIEM for monitoring; file integrity monitoring; data classification system.

---

### SR — Supply Chain Risk Management (New in Rev. 5)

**Goal**: Manage third-party risk.

**Key Controls:**
- **SR-1 Supply Chain Risk Management**: Policies for vendor security; risk assessment of suppliers.
- **SR-3 Third-Party Assessment & Management**: Request SOC 2/ISO 27001 from vendors; audit vendor security.
- **SR-5 Acquisition Process**: Procurement includes security requirements; contracts specify data protection, breach notification.

**Implementation**: Vendor security questionnaires; SOC 2/ISO 27001 verification; audit rights in contracts; incident notification SLA (24–72 hours).

---

## NIST SP 800-171 (Tailored for Non-Federal Contractors)

A **subset of 800-53** protecting Controlled Unclassified Information (CUI) on non-federal systems (defense contractors, DoD supply chain). **Rev 3 (May 2024)** reduced the control count from **110 (Rev 2)** to **97** and re-aligned with 800-53 Rev 5.

**Key points:**
- Far fewer controls than full 800-53; focused specifically on protecting CUI.
- The three **maturity levels** belong to **CMMC** (Cybersecurity Maturity Model Certification) — Level 1 Foundational, Level 2 Advanced, Level 3 Expert — **not** to 800-171 itself. CMMC Level 2 is built on the 800-171 control set.
- Often required for DoD contracts.

**Quick reference**: If you need federal compliance, start with 800-171 (more digestible than full 800-53), then expand to 800-53 for high-security systems.

---

## FISMA Authorization Process (ATO)

Organizations using 800-53 typically follow the FISMA (Federal Information Security Management Act) authorization process:

### Step 1: System Categorization (FIPS 199)
- Determine impact level: Low, Moderate, or High.
- Based on confidentiality, integrity, availability impact if system compromised.

### Step 2: Security Planning
- Write System Security Plan (SSP) documenting:
  - System scope, architecture, controls selected.
  - Threat model, risk assessment.
  - How controls map to 800-53 families.

### Step 3: Security Assessment
- Conduct security assessment: vulnerability scans, penetration tests, configuration review.
- Assess compliance with selected controls.
- Document findings in Security Assessment Report (SAR).

### Step 4: Authorization (ATO)
- Present SSP + SAR to authorizing official.
- Authorizing official approves (or conditionally approves with remediation plan).
- Issue Authority to Operate (ATO) letter.

### Step 5: Continuous Monitoring
- Ongoing security testing, compliance monitoring.
- Annual security assessment; remediate gaps.
- Re-authorize every 3 years.

---

## Control Baselines by System Impact

### Low Impact (~149 controls)

**Example systems**: Internal admin tools, development/test systems, non-critical applications.

**Focus**: Basic security; access control, minimal logging, basic cryptography.

**Sample controls**: AC-2, AC-3, AU-12, IA-2, SI-2, SI-3.

---

### Moderate Impact (~287 controls)

**Example systems**: Federal information systems (most federal systems), customer-facing applications, databases with sensitive data.

**Focus**: Strong access control, comprehensive logging, encryption, incident response.

**Sample controls**: AC-2 (all enhancements), AC-3, AC-5, AU-6, CA-2 (annual pen test), CM-3, IA-2 (MFA), SC-7, SI-4.

---

### High Impact (~370 controls)

**Example systems**: Critical infrastructure, defense/intelligence systems, systems with classified data.

**Focus**: Maximum security; redundancy, continuous monitoring, advanced threat detection.

**Sample controls**: All controls from Moderate, plus enhanced versions (e.g., AC-3 (9) Controlled Release, SC-8 (2) Transmission w/ Cryptographic Mechanisms).

---

## Common 800-53 Implementation Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No clear system scope | Unclear which controls apply | Define system boundary in SSP; categorize per FIPS 199 |
| Control checklist mentality | Compliance without understanding | Map each control to actual risk; implement thoughtfully |
| Incomplete logging | Can't investigate incidents | Enable logging on all systems; centralize; retain 1-3 years minimum |
| No continuous monitoring | ATO becomes stale; compliance drifts | Schedule quarterly/annual compliance re-assessment; automated scanning |
| Weak cryptography | Data compromised despite "encryption" | Use NIST-approved algorithms only (AES, SHA-256); TLS 1.2+; disable legacy ciphers |
| No change management | Unauthorized/untested changes break security | Implement formal CM process; test in staging; approval before prod |
| No incident response plan | Slow response; damage amplifies | Write IR plan; assign team; annual drills |
| Vendor risk unmanaged | Breach through third-party | Assess vendors per SR controls; get SOC 2/ISO 27001; audit contracts |

---

## 800-53 for Penetration Testers

**How to use 800-53 in pentesting:**

1. **Scope alignment**: Understand which 800-53 controls the client claims to implement; test whether they're actually effective.
2. **Finding categorization**: Map vulnerabilities to 800-53 controls ("AC-3 Access Enforcement not implemented" is more useful than "excessive access").
3. **Risk justification**: Frame findings in terms of control failures and residual risk (FISMA/ATO language).
4. **Remediation guidance**: 800-53 provides implementation guidance; include it in recommendations.

**Example pentest finding:**
- **Vulnerability**: Excessive file shares (user1 has access to all project files).
- **800-53 Control**: AC-3 (Access Enforcement); AC-5 (Separation of Duties).
- **Risk**: Violates least privilege; increases insider threat risk.
- **Remediation**: Implement RBAC; restrict file access to role-required permissions; monthly access reviews.

---

## Quick Reference: Key 800-53 Controls by Role

| Role | Critical Controls |
|---|---|
| **System Admin** | CM-2/3 (baselines, change control), SC-7 (boundary protection), SI-2/3 (patching, malware), AU-12 (logging) |
| **Network Admin** | SC-7 (boundary protection), SC-12 (cryptographic keys), SC-13 (cryptography), SI-4 (monitoring) |
| **Developer** | SA-3/11 (secure SDLC), SI-7 (code integrity), SC-4 (encryption), AC-3 (access enforcement in code) |
| **Database Admin** | AC-3/5 (access control, separation of duties), AU-6 (audit review), SI-2/3 (patching, malware), SC-4 (encryption at rest) |
| **Security Officer** | PL-2 (SSP), CA-2 (assessments), IR-1/4 (incident response), RA-3 (risk assessment) |

---

## Resources

- **NIST SP 800-53B**: Control mappings, profiles, and implementation specifics (technical reference).
- **NIST SP 800-53A**: Security assessment procedures (how to test controls).
- **NIST SP 800-171**: Tailored subset for non-federal contractors (easier to digest).
- **NIST SP 800-218**: Secure Software Development Framework (SSDF) — 4 security practices for development teams.
- **FedRAMP**: Government cloud authorization program using 800-53 baseline.

---


## See also

[[NIST-CSF]], [[FedRAMP]], [[ISO-27001-27002]], [[CIS-Controls]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
