# FedRAMP

#Compliance #FedRAMP #Cloud #Federal #NIST

## What is this?

**FedRAMP (Federal Risk and Authorization Management Program)** — U.S. government program standardizing security authorization for cloud services. Cloud providers (AWS, Azure, Google Cloud, etc.) or cloud-based SaaS platforms undergo FedRAMP assessment; once authorized, the authorization package can be reused across federal agencies without a separate full assessment ("do once, use many times").

---

## Overview

**FedRAMP Basics:**
- **Purpose**: Standardize cloud security authorization across federal government (eliminates 50+ different agency authorization processes).
- **Scope**: Cloud Information Systems (IaaS, PaaS, SaaS) offering federal agencies.
- **Authorization**: Third-party (3PAO) assessment, then an agency sponsor grants an ATO (Authority to Operate) that other agencies can reuse. (Historically the **JAB** issued a Provisional ATO; the FedRAMP Authorization Act of 2022 dissolved the JAB in 2024 in favor of a single FedRAMP authorization overseen by the new **FedRAMP Board**.)
- **Compliance Standard**: Uses NIST SP 800-53 controls as baseline.

**Cost to Cloud Provider**: $50K–$500K+ (depending on system complexity, assessment firm, ongoing monitoring).

**Versions**: FedRAMP 1.0 (2011); ongoing updates; latest guidance published on fedramp.gov.

---

## FedRAMP Authorization Levels (Impact Levels)

FedRAMP uses FIPS 199 impact categories to define authorization rigor:

### Low Impact
**Example**: Non-sensitive federal data, administrative tools. (FedRAMP also offers **Li-SaaS / Tailored**, a lighter Low baseline for low-risk SaaS.)

**Baseline**: ~156 NIST SP 800-53 Rev 5 controls.

**Assessment**: Faster, lower cost (~3–6 months, $50K–$100K).

---

### Moderate Impact
**Example**: Sensitive federal data (personally identifiable info, financial records, law enforcement data). The large majority of FedRAMP authorizations are Moderate.

**Baseline**: ~323 NIST SP 800-53 Rev 5 controls.

**Assessment**: Standard FedRAMP process (~6–12 months, $100K–$300K).

---

### High Impact
**Example**: Data where loss could be catastrophic — law enforcement, emergency services, financial, and health systems.

**Baseline**: ~410 NIST SP 800-53 Rev 5 controls.

**Assessment**: Rigorous, specialized (~12–24 months, $300K–$500K+).

> [!note]
> **Don't confuse FedRAMP Low/Moderate/High (FIPS 199) with DoD Impact Levels (IL2/IL4/IL5/IL6).** Those are a separate DoD Cloud Computing SRG construct — IL2 ≈ FedRAMP Moderate, and IL4/IL5/IL6 add DoD "FedRAMP+" controls on top for CUI and national-security workloads. Classified systems use those DoD paths, not FedRAMP.

---

## FedRAMP Authorization Process

### Phase 1: Pre-Authorization (Weeks 1–4)

**Activities:**
- Cloud provider determines FedRAMP readiness (staff, budget, controls).
- Cloud provider selects a 3PAO (Third Party Assessment Organization) — FIPs/FedRAMP-certified auditor firm (e.g., Deloitte, Ernst & Young, Coalfire).
- System Security Plan (SSP) drafted.

**Deliverables:**
- FedRAMP initiation form submitted to FedRAMP PMO (Project Management Office).

---

### Phase 2: Security Assessment (Months 2–8)

**Activities:**
- 3PAO conducts security assessment per NIST SP 800-53A (assessment procedures).
  - Review controls (documentation review).
  - Test controls (hands-on testing, vulnerability scans, penetration testing).
  - Interview staff.
  - Evaluate evidence.

**Scope Includes:**
- Cloud infrastructure (servers, networks, storage).
- Cloud provider's personnel/processes (access control, incident response, patch management).
- Third-party services used by cloud provider (vendors, subprocessors).
- Environmental/physical security of data centers.

**Deliverables:**
- Security Assessment Report (SAR) documenting findings.
- Control Assessment Summary (CAS).

---

### Phase 3: System Security Plan (SSP) & Documentation (Ongoing)

**Cloud provider must document:**
- System architecture and data flows.
- Controls selected per impact level; implementation status.
- Threat model, risk assessment.
- Incident response plan, disaster recovery plan.
- Personnel security (background checks, training).
- Change management procedures.
- Configuration management baselines.

**Deliverables:**
- Updated System Security Plan (reflects all findings, remediation).
- Ready for FedRAMP PMO review.

---

### Phase 4: FedRAMP PMO Review & Authorization (Months 9–12)

**FedRAMP PMO conducts review:**
- Verification that all controls are implemented correctly.
- Assessment of SAR quality and rigor.
- Risk acceptance (residual risk acceptable for impact level?).

**Authorization granted** (agency ATO, reusable by other agencies):
- Maintained continuously via ConMon — no fixed expiry; annual assessment + monthly monitoring keep it live.
- Indicates the cloud service is approved for federal use at that impact level.

> [!note]
> Governance modernized recently: the **JAB P-ATO** path ended in 2024 (JAB dissolved under the 2022 FedRAMP Authorization Act; the **FedRAMP Board** now oversees the program), and the **FedRAMP 20x** initiative (2025) is streamlining authorization toward automation and continuous validation. Expect process and terminology to keep shifting.

---

### Phase 5: Continuous Monitoring (Years 1–3)

**Post-authorization, cloud provider must:**
- Conduct annual security assessment (SAR, focused on control changes/new findings).
- Monthly monitoring reports (vulnerability scans, patch status, control compliance).
- Quarterly plan of action and milestones (POA&M) updates (tracking remediation of findings).
- Real-time incident notification (any security incident or significant change).

**Deliverables:**
- Annual Assessment Report (AAR).
- Monthly monitoring dashboards.
- Continuous POA&M.

**FedRAMP PMO reviews** annually; may recommend removal if compliance lapses.

---

## FedRAMP Controls Overview

FedRAMP baselines (Low/Moderate/High) directly map to NIST SP 800-53 controls. See the NIST-SP-800-53 note for detailed control families.

**High-priority FedRAMP controls** (always required, any impact level):

| Control Family | FedRAMP Critical Controls |
|---|---|
| **AC** (Access Control) | AC-2 Account Management, AC-3 Access Enforcement, AC-5 Separation of Duties, AC-6 Least Privilege, AC-11 Session Lock |
| **AU** (Audit & Accountability) | AU-2 Audit Events, AU-3 Content of Audit Records, AU-6 Audit Review & Analysis, AU-12 Audit Generation |
| **IA** (Identification & Authentication) | IA-2 Authentication, IA-4 Identifier Management, IA-5 Authentication Mechanisms (strong passwords, MFA) |
| **SC** (Systems & Communications Protection) | SC-7 Boundary Protection, SC-8 Transmission Confidentiality, SC-13 Cryptography (AES, TLS 1.2+) |
| **SI** (System & Information Integrity) | SI-2 Flaw Remediation (patching), SI-3 Malware Protection, SI-4 System Monitoring, SI-12 Information Handling |

---

## Key FedRAMP Requirements

### Multi-Factor Authentication (MFA)
- **Required** for all remote access to cloud system (admin, monitoring, etc.).
- All federal users must use MFA to access cloud application.

### Encryption
- **Data at rest**: AES-256 or equivalent.
- **Data in transit**: TLS 1.2+ (no SSL 3.0, TLS 1.0/1.1).
- **Key management**: Keys stored securely (HSM); rotated regularly; key escrow (government recovery).

### Logging & Monitoring
- **All system access logged**: who, what, when, where.
- **Centralized logging**: logs sent to secure SIEM; protected from tampering.
- **Real-time alerting**: suspicious activity detected and investigated immediately.
- **Log retention**: 2+ years minimum (often 5-7 years for federal systems).

### Incident Response
- **Incident response plan** required; reviewed annually.
- **Breach notification**: FedRAMP PMO and affected agencies within 24 hours (or faster for active attacks).
- **Incident investigation**: root cause analysis, preventive actions.

### Patch Management
- **Critical patches**: applied within 15 days.
- **High-priority patches**: within 30 days.
- **Patch testing**: validated in staging before production.
- **Patch tracking**: documented; evidence retained.

### Vulnerability Management
- **Monthly vulnerability scans** (both cloud provider and independent scanning).
- **Penetration testing**: at least annually (more frequently for High-impact systems).
- **Vulnerability remediation**: tracked in POA&M; critical/high findings remediated quickly.

### Physical & Environmental Security
- **Data center security**: badge access, CCTV, visitor logs, segregated secure areas.
- **Environmental controls**: temperature/humidity monitoring, backup power, fire suppression.
- **Hardware disposal**: secure destruction (shredding, degaussing); certificates of destruction.

### Disaster Recovery / Business Continuity
- **Backup procedures**: regular backups (daily incremental, weekly full).
- **Off-site storage**: backups stored geographically separated (different region).
- **Restoration testing**: restore procedures tested at least annually; success documented.
- **RTO/RPO**: defined and communicated to agencies.

### Personnel Security
- **Background checks**: all staff handling federal data vetted.
- **Clearances**: staff with access to sensitive data may require security clearance.
- **Training**: annual security training; role-specific training for developers, admins.
- **Termination procedures**: access revoked immediately; equipment secured; data returned/destroyed.

### Third-Party / Subprocessor Management
- **Vendor security**: subprocessors (AWS regions, third-party tools) undergo security assessment.
- **Contracts**: include FedRAMP security requirements, breach notification, audit rights.
- **Continuous monitoring**: vendors' security posture monitored; flagged if degraded.

---

## Continuous Monitoring (Ongoing)

### Monthly
- Vulnerability scans (internal & external).
- System performance metrics.
- Security incident reports (any unauthorized access, data exposure, etc.).

### Quarterly
- Plan of Action and Milestones (POA&M) update: track remediation of findings.
- Access control review (who has what access; remove stale access).
- Policy/procedure review (any changes?).

### Annually
- Full security assessment (similar to initial authorization, but abbreviated).
- Penetration testing (independent; assess new attack vectors).
- Incident response drill (test capabilities).
- Risk assessment update (threat landscape changed?).

### Real-Time
- Incident notification: any security incident, breach, or significant system change reported immediately to FedRAMP PMO.

---

## FedRAMP vs. Agency-Specific Authorization

**Pre-FedRAMP**: Each federal agency (DoD, HHS, Treasury, etc.) had its own authorization process.
- DoD: DIACAP → RMF process (very rigorous).
- HHS: ATO per agency.
- Result: Cloud provider needed separate authorizations for each agency (expensive, slow).

**Post-FedRAMP**: One P-ATO covers all agencies.
- Agencies recognize FedRAMP P-ATO; issue own ATO based on P-ATO.
- Significant cost savings and time reduction.

**Current Status**: FedRAMP now widely accepted; many agencies require FedRAMP authorization for cloud procurement (especially Moderate/High-impact systems).

---

## FedRAMP Marketplace & Authorized Systems

**FedRAMP Marketplace** (fedramp.gov/marketplace) lists all authorized cloud systems:
- **Authorized** systems (P-ATO issued): AWS, Azure, Google Cloud, ServiceNow, Salesforce, Microsoft 365, etc.
- **In Process**: systems undergoing assessment.
- **Withdrawn**: systems that failed or chose not to pursue.

**Search** by impact level, service type (IaaS/PaaS/SaaS), vendor.

---

## Common FedRAMP Failures

| Issue | Impact | Cause |
|---|---|---|
| **Failed authorization** (P-ATO not issued) | Can't sell to federal government | Inadequate controls, insufficient staff/budget, poor assessment quality |
| **Removal from authorization** (P-ATO revoked) | Loss of federal revenue | Incident/breach, failed continuous monitoring, deliberate non-compliance |
| **Slow authorization** (>24 months) | Business delay; cost overruns | Underestimating control implementation effort, poor 3PAO selection, resource constraints |
| **Expensive assessment** (>$500K) | Financial burden | System complexity, multiple cloud regions, inadequate pre-assessment readiness |
| **Incident during assessment** (breach while under review) | Failed assessment | Inadequate interim controls before authorization |

---

## FedRAMP for Penetration Testers

**How FedRAMP applies to pentesting:**

1. **Scope**: If testing a FedRAMP-authorized system (or one pursuing authorization):
   - Verify controls are actually implemented (not just documented).
   - Test MFA for all remote access.
   - Validate encryption (at rest + in transit).
   - Assess logging/monitoring effectiveness.
   - Review incident response capability.

2. **Critical Findings** (FedRAMP-specific):
   - **No MFA for remote access** (critical FedRAMP requirement).
   - **Weak encryption** (TLS 1.0, self-signed certs, no AES at rest).
   - **Missing/inadequate logging** (can't investigate incidents).
   - **No incident response capability** (can't respond to breach in 24 hours).
   - **Unvetted subprocessors** (vendor using unauthorized third party).

3. **Assessment Timing**:
   - **Pre-authorization**: Pentest informs SSP/SAR; helps identify gaps before 3PAO assessment.
   - **Continuous monitoring**: Annual pentest as part of ongoing compliance.

4. **Reporting**:
   - Use NIST 800-53 control language (FedRAMP stakeholders understand it).
   - Map findings to specific controls (AC-2 Account Management failure, etc.).
   - Frame as compliance risk + security risk.

---

## Quick Authorization Roadmap

### Pre-Assessment (Months 1–2)
- [ ] Assess system readiness (architecture, controls, documentation).
- [ ] Select 3PAO (FedRAMP-certified auditor).
- [ ] Draft System Security Plan (SSP).
- [ ] Conduct internal pentest; remediate findings.

### Assessment Phase (Months 3–8)
- [ ] 3PAO conducts security assessment.
- [ ] Implement any findings from assessment.
- [ ] Update SSP, controls documentation.

### Authorization Phase (Months 9–12)
- [ ] Submit to FedRAMP PMO.
- [ ] FedRAMP PMO review.
- [ ] P-ATO issued.

### Continuous Monitoring (Years 2–3)
- [ ] Monthly scans, incident reporting.
- [ ] Quarterly POA&M updates.
- [ ] Annual assessment (SAR).
- [ ] Annual pentest.

---

## Key Contacts & Resources

- **FedRAMP PMO**: fedramp.gov
- **FedRAMP Marketplace**: List of authorized systems.
- **3PAOs**: FedRAMP-accredited assessment firms (Deloitte, EY, Coalfire, Optiv, etc.).
- **NIST SP 800-53**: Control baseline (detailed).
- **NIST SP 800-53A**: Assessment procedures.
- **NIST SP 800-171**: Tailored for non-federal contractors (often precursor to FedRAMP).

---


## See also

[[NIST-SP-800-53]], [[NIST-CSF]], [[Cloud-Security]], [[SOC-2-Type-II]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
