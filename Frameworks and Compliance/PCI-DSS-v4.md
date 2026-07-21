# PCI-DSS v4.0

#Compliance #PCIDSS #PaymentSecurity #Regulatory #CardholderData

## What is this?

**Payment Card Industry Data Security Standard (PCI-DSS)** — mandatory framework for organizations that store, process, or transmit cardholder data. Maintained by the PCI Security Standards Council (PCI SSC). v4.0 was published March 2022; the current point release is **v4.0.1** (June 2024, clarifications only, no new requirements). v3.2.1 was retired **March 31, 2024**, and the ~51 future-dated v4.0 requirements became mandatory **March 31, 2025**.

---

## Overview

PCI-DSS keeps its long-standing structure: **12 core requirements** grouped under **6 goals** (control objectives). v4.0 did not replace the 12 requirements — it reorganized/renamed some (e.g. "firewalls and routers" → "network security controls (NSCs)"; the goal "Protect Cardholder Data" → "Protect Account Data") and added new requirements focused on stronger authentication, targeted risk analysis, and continuous (rather than point-in-time) security.

| Goal | Requirements |
|---|---|
| 1. Build and Maintain a Secure Network and Systems | Req 1–2 |
| 2. Protect Account Data | Req 3–4 |
| 3. Maintain a Vulnerability Management Program | Req 5–6 |
| 4. Implement Strong Access Control Measures | Req 7–9 |
| 5. Regularly Monitor and Test Networks | Req 10–11 |
| 6. Maintain an Information Security Policy | Req 12 |

> [!note]
> The **cardholder data environment (CDE)** — systems that store/process/transmit account data plus anything connected to them — defines PCI scope. Effective segmentation shrinks the CDE and therefore the assessment scope.

---

## Goal 1 — Build and Maintain a Secure Network and Systems

### Requirement 1: Install and Maintain Network Security Controls (NSCs)
- NSC (firewall/router/cloud security group) rulesets documented, justified, and reviewed at least every 6 months.
- Default-deny inbound to the CDE; outbound restricted to what is required.
- Network diagram and data-flow diagram maintained showing all CDE connections.

### Requirement 2: Apply Secure Configurations to All System Components
- Change all vendor default passwords/settings before deploying; remove/disable unnecessary accounts and services.
- Configuration ("hardening") standards for every component, aligned to industry benchmarks (CIS, vendor guides).
- Manage wireless securely (strong encryption WPA2/WPA3, changed defaults) or prohibit it in the CDE.

---

## Goal 2 — Protect Account Data

### Requirement 3: Protect Stored Account Data
- Retain cardholder data (CHD) only as long as necessary; define and enforce retention/disposal.
- **Never store sensitive authentication data (SAD)** — full track, CVV/CVC, PIN — after authorization.
- Render stored PAN unreadable: strong cryptography (e.g. AES-128+), truncation, tokenization, or hashing with keyed hashes.
- Key management: keys stored securely (HSM/KMS preferred), split knowledge/dual control, rotation defined, access restricted with separation of duties.

### Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission
- Encrypt CHD in transit over open/public networks with TLS 1.2+ (or equivalent); validate certificates (no self-signed in production).
- Prohibit weak protocols/ciphers: SSL, early TLS, WEP, null ciphers.
- Never send unprotected PAN via end-user messaging (email, SMS, chat).

---

## Goal 3 — Maintain a Vulnerability Management Program

### Requirement 5: Protect All Systems and Networks from Malicious Software
- Anti-malware on all systems commonly affected; kept current with real-time/scheduled scanning.
- Periodic evaluation of systems "not commonly affected" by malware.
- Users cannot disable or alter anti-malware without documented, time-bound authorization.

### Requirement 6: Develop and Maintain Secure Systems and Software
- Patch management: install security patches within **30 days**; **critical/high** patches within **15 days** (compensating controls + risk analysis if not).
- Secure SDLC: developer training, code review, and protection against common attacks (injection, etc.).
- Public-facing web apps protected by an automated technical solution (WAF) or reviewed regularly.

---

## Goal 4 — Implement Strong Access Control Measures

### Requirement 7: Restrict Access by Business Need to Know
- Least privilege: access to system components and CHD limited to roles that require it.
- Deny-by-default access control system; documented role-to-privilege assignments.

### Requirement 8: Identify Users and Authenticate Access
- Unique ID for every user (no shared/generic accounts); actions traceable to individuals.
- **MFA required for all access into the CDE** and for all remote/administrative access (a v4.0 expansion — password-only access to the CDE is no longer sufficient).
- Strong authentication policy: password length/complexity minimums or phishing-resistant methods (e.g. FIDO2); revoke access promptly on termination; disable inactive accounts within 90 days.

### Requirement 9: Restrict Physical Access to Cardholder Data
- Control and log physical entry to facilities and areas holding CHD (badges, visitor logs, escorts).
- Protect and inventory media containing CHD; destroy it securely when no longer needed.
- Protect POI/POS devices from tampering and substitution (periodic inspection).

---

## Goal 5 — Regularly Monitor and Test Networks

### Requirement 10: Log and Monitor All Access
- Enable audit logging across CDE components (systems, DBs, apps, network devices); link all access to individual users.
- Retain logs at least **12 months**, with **at least 3 months immediately available** for analysis.
- Review logs (automated SIEM recommended); time-synchronize systems (NTP); protect logs from tampering.

### Requirement 11: Test Security of Systems and Networks Regularly
- Internal + external vulnerability scans at least quarterly and after significant change; external scans by an **ASV**.
- **Penetration testing** (internal + external) at least annually and after significant change; segmentation testing (annually for merchants, every 6 months for service providers).
- Deploy change-/tamper-detection and intrusion detection/prevention.

---

## Goal 6 — Maintain an Information Security Policy

### Requirement 12: Support Information Security with Organizational Policies and Programs
- Maintain an overall information security policy; perform **targeted risk analyses** (new in v4.0) to justify frequency-based controls.
- Security awareness training at least annually for all personnel; defined roles and responsibilities.
- Manage third-party service providers (TPSPs): due diligence, written agreements, and a documented responsibility matrix for who owns which PCI requirement.
- Maintain and test an **incident response plan** (Req 12.10): detection, escalation, containment, and breach notification to card brands/acquirers and per applicable law.

---

## Key Changes in v4.0 (vs. v3.2.1)

| Area | v3.2.1 | v4.0 | Impact |
|---|---|---|---|
| MFA | Required for remote + admin access to CDE | **Required for all access into the CDE** | Stronger authentication across the board |
| Authentication | Fixed password rules | Password minimums **or** phishing-resistant/passwordless; risk-based options | More flexibility, higher assurance |
| Terminology | Firewalls/routers; "Cardholder Data" | **Network Security Controls**; "Account Data" | Cloud/architecture-neutral language |
| Risk approach | Prescriptive only | **Customized Approach** + targeted risk analysis allowed | Meet the objective via alternative controls |
| Continuous security | Point-in-time | Ongoing "business-as-usual" expectations, roles assigned | Compliance treated as continuous |
| Documentation | Policies + procedures | + defined roles/responsibilities per requirement | Clearer accountability |

> [!note]
> v4.0 introduced two ways to meet a requirement: the **Defined Approach** (the traditional prescriptive control) and the **Customized Approach** (design your own control that meets the stated objective, validated by the assessor).

---

## Compliance Validation

| Method | Who | What |
|---|---|---|
| **SAQ** (Self-Assessment Questionnaire) | Smaller merchants / eligible setups | Self-attestation; type (A, A-EP, B, B-IP, C, C-VT, D, P2PE) depends on how cards are handled |
| **ASV scan** | All externally-facing merchants/providers | Quarterly external vulnerability scan by an Approved Scanning Vendor |
| **QSA / ROC** | Larger merchants, all service providers | On-site assessment by a Qualified Security Assessor producing a Report on Compliance + Attestation of Compliance |

> [!note]
> Merchant **levels (1–4)** are set by each card brand based on annual transaction volume and determine whether an SAQ or a full QSA-led ROC is required. Service providers face stricter/more frequent requirements (e.g. 6-month segmentation testing).

---

## Common Implementation Mistakes

- Treating v4.0 as "6 pillars" or otherwise ignoring the actual 12-requirement structure an assessor tests against.
- Applying MFA to only some CDE access instead of **all** access into the CDE.
- Storing SAD (CVV, full track, PIN) after authorization — never permitted.
- Weak transmission crypto (< TLS 1.2, null ciphers) or unvalidated certificates.
- Poor segmentation, leaving the entire network in scope as the CDE.
- Missing the 15-day critical-patch window; relying on compensating controls instead of fixing root cause.
- No targeted risk analysis to justify frequency-based controls (a v4.0 requirement).


## See also

[[ISO-27001-27002]], [[SOC-2-Type-II]], [[CIS-Controls]], [[NIST-SP-800-53]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
