# PCI-DSS v4.0 Reference Guide

**Payment Card Industry Data Security Standard (PCI-DSS)** — mandatory framework for organizations that accept, transmit, or store credit card data. v4.0 effective March 31, 2025; v3.2.1 support ends March 31, 2025.

---

## Overview

PCI-DSS v4.0 reorganizes requirements around 6 pillars instead of the old 12-requirement structure. Focus areas include: secure network, access control, regular monitoring, strong authentication, and vulnerability management.

---

## Pillar 1: Secure the Network

Establish and maintain a secure network environment.

### 1.1: Firewall Configuration Standards
- Firewall rules document required; maintained and reviewed regularly.
- Default-deny rule for inbound traffic; default-allow for outbound (or documented exceptions).
- Configuration standards prevent unauthorized access to cardholder data environment (CDE).

### 1.2: Network Segmentation & Architecture
- CDE isolated from untrusted networks via firewalls or router ACLs.
- Segment networks to limit cardholder data access to only systems that need it.
- Document network architecture; diagram showing data flows required.

### 1.3: Prohibited Technologies & Services
- Wireless access points: implement strong encryption (WPA2/WPA3) or prohibit.
- Modems and remote access: prohibited unless explicitly authorized and documented.
- Peer-to-peer technology: prohibited unless risk-assessed and authorized.

> *Note: v4.0 strengthens wireless requirements; open networks near CDE are high-risk.*

---

## Pillar 2: Apply Strong Access Controls

Protect cardholder data through strong authentication and access controls.

### 2.1: Unique User Identification
- All users have unique user ID (no shared accounts).
- User identity traceable to individual.
- System prevents reuse of old passwords (minimum 4 previous passwords remembered).

### 2.2: Strong Authentication
- **Multi-factor authentication (MFA) required for**:
  - Admin access to CDE
  - Remote access to CDE
  - Any access to cardholder database
- Acceptable factors: something you know (password), something you have (token/card), something you are (biometric).
- Passwordless methods accepted if approved (e.g., FIDO2 keys).

> *Note: v4.0 significantly expands MFA requirements; password-only access to CDE is no longer sufficient.*

### 2.3: User Access Management
- Principle of least privilege: users have minimum necessary access.
- Access restricted by role; admin accounts limited to administrative functions.
- Access revoked within 24 hours of termination.
- Inactive accounts disabled after 90 days of no use.

### 2.4: Default Credentials
- All system default usernames, passwords, and access strings changed.
- Vendor defaults documented; change justified and logged.

---

## Pillar 3: Protect Cardholder Data

Encrypt and securely handle card data at all stages.

### 3.1: Data Classification & Retention
- Cardholder data (CHD) and sensitive authentication data (SAD) identified and classified.
- Retention period defined; data not retained longer than necessary.
- Purge procedures in place; archival encrypted.

### 3.2: Encryption of Cardholder Data
- Data in transit: TLS 1.2+ or equivalent encryption.
  - End-to-end encryption if data passes untrusted networks.
  - Certificate validation required (no self-signed in production).
- Data at rest: AES-256, 3DES, or equivalent (minimum 128-bit).
- Key management (see below).

### 3.3: Strong Cryptography & Encryption Key Management
- Encryption algorithm strength: minimum 128-bit key length.
- Cryptographic protocols: TLS 1.2+, SSH v2, IPsec, or equivalent.
- Weak protocols prohibited: SSL, early TLS versions, WEP, null encryption.
- Encryption key management:
  - Keys stored securely (hardware security module or key management appliance preferred).
  - Key rotation at least annually or upon suspected compromise.
  - Key access restricted; separation of duties enforced.

---

## Pillar 4: Maintain Vulnerability & Security Posture

Continuously monitor, detect, and defend against security threats.

### 4.1: Malware Protection
- Anti-malware installed on all systems that could be affected.
- Real-time protection enabled; regular scans scheduled.
- Malware detection logs retained for at least 12 months.
- Policy prevents users from disabling or modifying protection.

### 4.2: Security Patch Management
- Security patches installed within 30 days of release (critical patches: 15 days).
- Patching process documented; testing before deployment.
- Systems not patched within timeframe: risk assessment and compensating controls required.

### 4.3: Vulnerability Scans & Penetration Testing
- Quarterly vulnerability scans (internal + external).
- Penetration testing (external + internal) annually; after significant network changes.
- Scan/test results reviewed; remediation tracked.
- High-risk vulnerabilities: re-tested after remediation.

### 4.4: Security Configuration Standards
- Configuration standards for all system components documented.
- Standards include: hardening, removal of unnecessary services, secure defaults.
- Standards reviewed and updated annually.

---

## Pillar 5: Maintain an Incident Response Plan

Detect, investigate, and respond to security events.

### 5.1: Incident Response Plan
- Written plan in place; roles and responsibilities defined.
- Plan includes: detection procedures, escalation, investigation, containment, remediation.
- Plan tested annually; findings documented and remediated.

### 5.2: Breach Notification (PCI-DSS + Law)
- Suspected breach investigated within 30 days.
- Card brands (Visa, Mastercard, etc.) notified of confirmed breaches.
- Consumer notification as required by law (varies by jurisdiction).
- Notification includes: what happened, date range, data exposed, steps to take.

### 5.3: Monitoring & Logging
- Logging enabled on all systems (firewall, databases, apps, servers).
- Log retention: minimum 3 months (online), 1 year (archival).
- Logs reviewed for suspicious activity (automated SIEM recommended).
- User activity logged and monitored; exception investigations documented.

---

## Pillar 6: Foster a Strong Security Culture

Build organizational security awareness and governance.

### 6.1: Security Awareness Program
- Annual training for all personnel (staff, contractors, temporary employees).
- Training covers: cardholder data protection, company policies, incident procedures.
- Training completion documented; refresher annually.

### 6.2: Roles & Responsibilities
- Security officer or equivalent appointed; responsible for PCI-DSS compliance.
- Responsibility assignment: who owns each requirement.
- Escalation path clear for security issues.

### 6.3: Third-Party/Vendor Management
- Vendors handling cardholder data: PCI-DSS compliance verified.
- Contracts include: data protection requirements, access controls, incident reporting.
- Vendor compliance monitored; re-assessment at least annually.

---

## Key Changes in v4.0

| Requirement | v3.2.1 | v4.0 | Impact |
|---|---|---|---|
| MFA | Recommended for remote admin | **Required** for all CDE admin & remote access | Significantly stronger authentication |
| Wireless | Detect + manage | Explicitly approved or prohibited with encryption | More restrictive on unsecured networks |
| Vulnerability Scans | Quarterly (network) | Quarterly (internal + external) + annual pen test | Broader vulnerability coverage |
| Encryption Keys | Managed | Strict access + rotation + auditing | Tighter key lifecycle control |
| Patch Timeline | 30 days | Critical: 15 days, standard: 30 days | Faster response to critical vulnerabilities |
| Compensating Controls | Allowed for all | **Restricted** to specific scenarios | Less flexibility; fewer "workarounds" |
| Documentation | Policies + procedures | **Policies + procedures + architecture diagrams** | More detailed system documentation |

> *Note: v4.0 is stricter; many v3.2.1 compliance approaches will not meet v4.0 requirements.*

---

## Compliance Assessment Approaches

### SAQ (Self-Assessment Questionnaire)
- Merchants with <6M transactions/year can use SAQ (if not using external processors or storing card data).
- SAQ categories: A, A-EP, B, B-IP, C, C-VT, D (based on payment setup).
- Annual completion + attestation required.

### ASV (Approved Scanning Vendor)
- External quarterly vulnerability scans required for all merchants.
- ASV-run scans mandatory; internal scans optional.

### QSA (Qualified Security Assessor)
- Annual on-site assessment for large merchants or service providers.
- QSA conducts compliance audit; produces Attestation of Compliance (AOC).

### Service Providers
- Additional requirements: 6-month penetration testing, more rigorous monitoring, responsibility for customer data protection.

---

## Common Implementation Mistakes

- Implementing MFA only for some CDE access (must be **all** admin + remote).
- Using weak encryption (< TLS 1.2, null ciphers).
- Failing to segment CDE from untrusted networks.
- Not rotating encryption keys or retaining them centrally without HSM.
- Delaying critical patches beyond 15-day deadline.
- Relying on compensating controls instead of fixing underlying issues.

---

*Created: 2026-07-15*
