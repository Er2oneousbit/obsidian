# CIS Controls

#Compliance #Frameworks #CISControls #SecurityControls #Hardening

## What is this?

**CIS Controls** — Prioritized list of 18 security best practices and technical controls recommended by the Center for Internet Security (CIS). Designed for rapid implementation with immediate risk reduction. Used by SOCs, DevOps teams, and organizations seeking quick wins without the overhead of ISO 27001 or NIST CSF deep dives.

---

## Overview

**CIS Controls vs. Other Frameworks:**
- **NIST CSF** = high-level "what to do"; flexible.
- **ISO 27001** = process-focused management system; certification-heavy.
- **CIS Controls** = tactical, prescriptive checklist; "do these 18 things first"; actionable immediately.

CIS Controls prioritize by **Implementation Groups (IGs)**: IG1 (foundational, quick wins), IG2 (intermediate), IG3 (advanced/specialized).

**Versions:** CIS Controls v7 (2019), v8 (2021), **v8.1 (2024, current)** — v8 reorganized the old 20 controls into 18; v8.1 added a governance emphasis and minor updates.

---

## The 18 Controls (v8)

CIS v8 has 18 controls containing **153 Safeguards** (specific, testable actions). The Safeguards — not the controls — are tiered into three **Implementation Groups**: **IG1** (56 safeguards, essential cyber hygiene for every org), **IG2** (adds ~74 more), **IG3** (the rest, for high-risk orgs).

> [!warning]
> **Implementation Groups are safeguard-level, not control-level.** IG1 is *not* "controls 1–6" — it is a set of 56 safeguards spread across most of the 18 controls (Controls 7, 8, and 14 all contain IG1 safeguards). The walkthrough below groups controls in numeric order for readability only; it does **not** mean an IG1 org implements just the first six controls.

### Controls 1–6: Assets, Data & Access

Foundational hygiene — asset/software inventory, data protection, secure configuration, and account/access control.

---

#### Control 1: Inventory and Control of Assets

**Goal**: Know what hardware, software, and cloud assets exist in your organization.

**IG1 Actions:**
- Maintain a complete hardware inventory (servers, workstations, IoT, network devices).
- Inventory all software licenses and running applications.
- Track cloud resources (AWS/Azure/GCP VMs, databases, storage).
- Assign ownership to each asset.

**Why it matters**: You can't protect what you don't know about. Rogue shadow-IT systems and unpatched old hardware are common breach vectors.

**Quick win**: Export hardware list from your MDM/asset management tool; version-control it; update monthly.

---

#### Control 2: Software Asset Management

**Goal**: Manage software licenses, track installed versions, and remove unauthorized/unused software.

**IG1 Actions:**
- Maintain a list of approved software (whitelist).
- Remove unlicensed, unapproved, or obsolete software.
- Track software versions for all systems.
- Block installation of unapproved apps (via Group Policy, MDM, etc.).

**Why it matters**: Unlicensed software often carries malware; untracked software can't be patched or audited.

**Quick win**: Run Software Inventory tools (Lansweeper, Absolute, Microsoft SCCM) to scan systems; audit against approved list; remove outliers.

---

#### Control 3: Data Protection

**Goal**: Classify data, encrypt sensitive information, and prevent unauthorized access/leakage.

**IG1 Actions:**
- Classify data: Public, Internal, Confidential, Restricted.
- Encrypt sensitive data at rest (AES-256) and in transit (TLS 1.2+).
- Implement DLP (Data Loss Prevention) to block exfiltration (email, USB, cloud upload).
- Define data retention and deletion policies.

**Why it matters**: A breach with encrypted data is less damaging than unencrypted; DLP catches insider threats.

**Quick win**: Enable full-disk encryption (BitLocker/FileVault) on laptops; enforce TLS on web apps; configure email DLP rules.

---

#### Control 4: Secure Configuration Management

**Goal**: Document and enforce secure system configurations; remove unnecessary services/features.

**IG1 Actions:**
- Define secure baselines for all system types (Windows, Linux, cloud VMs, network devices).
- Remove or disable unnecessary services (disable SMBv1, turn off telemetry, etc.).
- Configure local firewalls (Windows Defender Firewall, iptables).
- Implement Configuration Management (Ansible, Puppet, Chef) to enforce consistency.

**Why it matters**: Default configurations often include open services and weak settings; hardening dramatically reduces attack surface.

**Quick win**: Use CIS Benchmarks (freely available) to configure Windows/Linux; automate via Ansible; scan with tools like Lynis or Microsoft SCCM Compliance.

---

#### Control 5: Account Management

**Goal**: Manage the lifecycle of accounts (create, use, disable, delete) so only valid, authorized accounts exist.

**IG1 Actions:**
- Implement Role-Based Access Control (RBAC) — group users by job function; assign permissions per group.
- Review access quarterly; remove stale access.
- Enforce MFA (multi-factor authentication) for all accounts, especially admins.
- Disable generic/shared accounts (no "admin" password shared across users).
- Implement password policies: 12+ characters, special chars, rotate quarterly.

**Why it matters**: Compromised credentials are the #1 breach vector; MFA & least privilege limit damage.

**Quick win**: Deploy Azure AD/Okta for centralized identity; enable MFA via phone/authenticator app; audit user group memberships; remove access for departed employees.

---

#### Control 6: Access Control Management

**Goal**: Grant, enforce, and revoke access rights (least privilege, MFA, privileged access) across assets.

**IG1 Actions:**
- Use strong authentication for admin accounts (MFA mandatory).
- Implement Privileged Access Management (PAM): force admins to check out temporary credentials, all actions logged.
- Use SSH keys (not passwords) for Linux admin access.
- Log and monitor all privileged sessions (who accessed what, when).

**Why it matters**: Admin account compromise = full system compromise; logging provides forensics for incidents.

**Quick win**: Enable MFA for all domain admin accounts; deploy jump box/bastion host for privileged access; log all sudo commands (Linux).

---

### Controls 7–16: Detection, Defense & Resilience

Vulnerability management, logging, email/web and malware defense, recovery, network infrastructure and monitoring, awareness, vendors, and application security.

---

#### Control 7: Continuous Vulnerability Assessment and Remediation

**Goal**: Find and fix vulnerabilities systematically.

**IG2 Actions:**
- Scan all systems for known vulnerabilities: quarterly external scans, monthly internal scans.
- Prioritize by CVSS severity; remediate critical within 15 days, high within 30 days.
- Maintain a vulnerability remediation SLA; track metrics.
- Automate patching where possible (Windows Update, yum auto-update).

**Why it matters**: Known vulnerabilities are the easiest to exploit; consistent patching blocks 80% of incidents.

**Quick win**: Deploy vulnerability scanner (Qualys, Nessus, OpenVAS); run monthly internal scan; prioritize and remediate top findings.

---

#### Control 8: Audit Log Management

**Goal**: Log everything, retain logs, and alert on suspicious activity.

**IG2 Actions:**
- Enable logging on all systems (servers, databases, firewalls, applications).
- Centralize logs (syslog, ELK, Splunk, Azure Monitor) — don't leave logs only on the local system.
- Retain logs for 1+ year (compliance often requires 3-7 years).
- Protect logs from tampering (read-only, hash verification).
- Alert on critical events (failed logins, privilege escalation, file deletion).

**Why it matters**: Logs are your forensics/audit trail; centralization prevents attackers from wiping local logs.

**Quick win**: Configure Windows Event Log forwarding to a central server; enable app/database logging; set up alerts for "failed login" and "privilege escalation".

---

#### Control 9: Email and Web Browser Protections

**Goal**: Block malware, phishing, and C2 callbacks at the email/web layer.

**IG2 Actions:**
- Deploy email filtering: block malicious links/attachments, sandbox suspicious files.
- Require DMARC/SPF/DKIM to prevent domain spoofing.
- Block known malicious websites (URL filtering, DNS sinkhole).
- Deploy anti-malware on all endpoints.
- Implement secure email gateway (SEG) — scan inbound/outbound email.

**Why it matters**: Email is the #1 attack vector (phishing, malware, credential harvesting); web filtering prevents drive-by downloads.

**Quick win**: Enable DMARC on your domain; deploy email gateway (Microsoft Defender for Office 365, Proofpoint); enable DNS filtering (Cloudflare, Quad9); deploy endpoint antivirus.

---

#### Control 10: Malware Defenses

**Goal**: Detect and prevent malware.

**IG2 Actions:**
- Deploy antivirus + anti-malware on all endpoints (real-time scanning).
- Regularly update antivirus signatures (auto-update enabled).
- Quarantine or remove detected malware automatically.
- Monitor for execution of known malware (behavioral detection).
- Restrict execution of executables (application whitelisting — only approved apps can run).

**Why it matters**: Malware is a common infection vector; real-time scanning catches it before execution.

**Quick win**: Deploy Windows Defender (built-in, free, good) or commercial AV (CrowdStrike, Sophos); enable auto-update; enable behavioral protection.

---

#### Control 11: Data Recovery Capability

**Goal**: Backup and disaster recovery — ensure you can restore after ransomware/disaster.

**IG2 Actions:**
- Backup all critical data daily (incremental) or weekly (full).
- Test restore procedures monthly (prove backups work).
- Store backups off-site (geographic separation, isolated network).
- Define RTO (Recovery Time Objective) and RPO (Recovery Point Objective) for each system.
- Implement immutable backups (can't be deleted by attacker, even with admin creds).

**Why it matters**: Ransomware and disaster can wipe systems; backups enable recovery. Attackers often target backups — immutable backups prevent this.

**Quick win**: Enable Azure Backup or AWS Backup; test restore on a non-production system; configure backup alerts; separate backup network from prod.

---

#### Control 12: Network Infrastructure Management

**Goal**: Securely manage network devices and architecture (segmentation, secure configs, up-to-date firmware) to reduce lateral movement.

**IG2 Actions:**
- Segment network: DMZ (public), Internal (users/apps), Restricted (databases, admin systems).
- Implement network firewall rules: default-deny between zones; allow only necessary traffic.
- Implement micro-segmentation on layer 3/4 (firewall rules per app/service).
- Isolate guest/BYOD networks from internal network.
- Use VLANs for logical separation; implement 802.1X for network access control.

**Why it matters**: Breach of one zone doesn't automatically compromise all zones; containment reduces damage.

**Quick win**: Configure firewall ACLs to restrict traffic between network segments; isolate guest WiFi; enable Windows Firewall on client systems.

---

#### Control 13: Network Monitoring and Defense

**Goal**: Detect and respond to threats across the network — IDS/IPS, traffic monitoring, and perimeter defenses.

**IG2 Actions:**
- Deploy firewall (default-deny, allow by exception).
- Implement IDS/IPS (Intrusion Detection/Prevention System) to detect attacks.
- Deploy WAF (Web Application Firewall) for HTTP(S) apps.
- Monitor and log all perimeter traffic.
- Block known malicious IP ranges (threat intelligence feeds).

**Why it matters**: Perimeter defense is first line; blocks automated scans and known attack signatures.

**Quick win**: Deploy hardware firewall (Palo Alto, Fortinet, Cisco) or cloud firewall (AWS WAF, Azure WAF); enable IPS signatures; deploy WAF for web apps; enable DDoS protection.

---

#### Control 14: Security Awareness and Skill Building

**Goal**: Train staff to recognize and avoid social engineering / security mistakes.

**IG2 Actions:**
- Mandatory annual security training for all staff (GDPR/HIPAA compliance, phishing recognition, password hygiene).
- Role-specific training (developers on secure coding, admins on hardening, users on phishing).
- Phishing simulations: send fake phishing emails monthly; track who clicks; coach repeat offenders.
- Incident response training: tabletop exercises, incident response plan walkthroughs.

**Why it matters**: Humans are a security layer; training reduces click-through rates and improves incident response.

**Quick win**: Deploy security awareness platform (KnowBe4, Proofpoint Security Awareness); run monthly phishing simulation; track metrics.

---

#### Control 15: Service Provider Management

**Goal**: Assess and monitor third-party security posture (vendors, cloud providers, contractors).

**IG2 Actions:**
- Require vendors to be SOC 2 Type II, ISO 27001, or equivalent certified.
- Request attestation letters / security questionnaires annually.
- Include security clauses in contracts (data protection, breach notification, audit rights).
- Assess subprocessor risks (vendor's vendors).
- Monitor vendor security incidents (set up alerts for your vendors' breaches).

**Why it matters**: Vendors can be breach vectors (supply chain compromise); vetting reduces risk.

**Quick win**: Audit critical vendors for SOC 2/ISO compliance; add security requirements to vendor contracts; monitor vendor breach notifications.

---

#### Control 16: Application Software Security

**Goal**: Manage the security of in-house and acquired software across its lifecycle to prevent, detect, and fix weaknesses.

**Actions:**
- Establish a secure development process; train developers in secure coding.
- Maintain an inventory of third-party software components; patch known-vulnerable dependencies (SCA).
- Use static and dynamic analysis (SAST/DAST) and remediate findings before release.
- Separate production, staging, and development environments; protect application secrets.

**Why it matters**: Application flaws (injection, deserialization, vulnerable dependencies) are a leading breach vector; building security into the SDLC is cheaper than patching later.

**Quick win**: Add an SCA/dependency scanner (Dependabot, Snyk) and a SAST tool to CI; fail the build on critical findings.

---

### Controls 17–18: Response & Testing

Incident response and penetration testing.

---

#### Control 17: Incident Response Management

**Goal**: Plan and execute incident response; contain and remediate breaches quickly.

**Actions:**
- Document an incident response plan: roles, escalation, communication, forensics.
- Define incident severity levels (P1/P2/P3) and an escalation path.
- Establish an incident response team (IR Lead, Technical Lead, Communications).
- Conduct incident simulations (tabletop) at least annually.
- Perform root cause analysis for incidents; implement preventive controls.

**Why it matters**: Incidents happen; a practiced plan limits damage (containment, eradication, recovery). RCA improves defenses.

> [!note]
> "Threat Intelligence" was a control in CIS v7 but is **not** a standalone control in v8 — its ideas live inside Controls 13 (Network Monitoring & Defense) and 17.

**Quick win**: Create an incident response runbook (1-page template per incident type); assign team roles; run one tabletop exercise.

---

#### Control 18: Penetration Testing

**Goal**: Test defenses with authorized security testing; find vulnerabilities before adversaries do.

**IG3 Actions:**
- Conduct annual penetration testing (external + internal).
- Test all attack surfaces: web apps, APIs, cloud infrastructure, physical security.
- Test incident response (red team exercises simulating active attack).
- Track vulnerabilities; prioritize and remediate critical/high findings.
- Share pentest reports with stakeholders; use as compliance evidence.

**Why it matters**: Pentests find real vulnerabilities missed by vulnerability scanners; red teams validate incident response.

**Quick win**: Budget for annual external pentest; conduct an internal pentest with staff (free if you have in-house security expertise); track findings in vulnerability management tool.

---

## Implementation Roadmap

### Phase 1: Quick Wins (Month 1)

**IG1 basics** — high impact, low effort:
- [ ] Asset inventory (export from IT system, version-control).
- [ ] Enable MFA for admin accounts.
- [ ] Configure Windows Firewall on workstations.
- [ ] Enable full-disk encryption (BitLocker/FileVault).
- [ ] Configure basic DLP (email/USB block).
- [ ] Deploy antivirus, enable real-time scanning.
- [ ] Enable logging on servers/databases.

**Effort**: 2–4 weeks, mostly configuration.

### Phase 2: Baseline Hardening (Months 2–3)

**IG1 + IG2 foundational controls**:
- [ ] Deploy vulnerability scanner; run baseline scan.
- [ ] Implement RBAC (audit and remediate excess access).
- [ ] Configure network firewall; implement segmentation.
- [ ] Deploy centralized logging (Splunk/ELK/Azure Monitor).
- [ ] Implement PAM for privileged access.
- [ ] Define incident response plan.

**Effort**: 6–8 weeks, infrastructure/process work.

### Phase 3: Detection & Response (Months 4–6)

**IG2 maturity**:
- [ ] Deploy SIEM (correlate logs, detect anomalies).
- [ ] Implement security awareness training.
- [ ] Automate patch management.
- [ ] Conduct first tabletop incident simulation.
- [ ] Vendor security assessment.

**Effort**: 8–12 weeks, ongoing process.

### Phase 4: Advanced Monitoring (Months 7–12)

**IG3 capabilities**:
- [ ] Deploy advanced endpoint detection (EDR).
- [ ] Implement threat intelligence feeds.
- [ ] Conduct annual penetration testing.
- [ ] Implement application whitelisting.
- [ ] Enhanced incident response (red team exercises).

**Effort**: 12+ weeks, specialized skills/budget required.

---

## CIS Controls Quick Reference

| # | Control | Quick Win |
|---|---|---|
| 1 | Inventory & Control of Enterprise Assets | Export hardware list from MDM; version-control it |
| 2 | Inventory & Control of Software Assets | Run software inventory scan; audit installed apps |
| 3 | Data Protection | Enable BitLocker + email DLP |
| 4 | Secure Configuration of Assets & Software | Apply CIS Benchmarks to Windows/Linux |
| 5 | Account Management | Inventory accounts; disable dormant/shared accounts |
| 6 | Access Control Management | Implement RBAC; enable MFA |
| 7 | Continuous Vulnerability Management | Deploy Nessus/Qualys; scan regularly |
| 8 | Audit Log Management | Centralize logs; enable alerting |
| 9 | Email & Web Browser Protections | Deploy email gateway; enable DMARC |
| 10 | Malware Defenses | Deploy AV/EDR; enable real-time scanning |
| 11 | Data Recovery | Enable cloud backup; test restore; immutable backups |
| 12 | Network Infrastructure Management | Secure device configs; segment networks |
| 13 | Network Monitoring & Defense | Deploy IDS/IPS; monitor traffic |
| 14 | Security Awareness & Skills Training | Mandatory training + phishing sim |
| 15 | Service Provider Management | Audit vendor compliance; sign SLAs |
| 16 | Application Software Security | Add SCA + SAST to CI; patch dependencies |
| 17 | Incident Response Management | Document IR plan; run tabletop |
| 18 | Penetration Testing | Budget annual pentest |

---

## CIS Controls vs. Other Frameworks

| Framework | Focus | Depth | Speed to Value |
|---|---|---|---|
| **CIS Controls** | Tactical; prioritized best practices | High-level actions, IG-based progression | Fast (quick wins in 1 month) |
| **NIST CSF** | Strategic; functions/categories | Framework for governance | Medium (planning phase ~3 months) |
| **ISO 27001** | Process; management system | Detailed controls, prescriptive audit | Slow (12–18 month certification) |
| **NIST SP 800-53** | Federal requirement; detailed controls | Very detailed (catalog of 1000+ controls) | Slow (specialized for gov/defense) |

**CIS Controls' Advantage**: Fastest path to measurable security improvement; actionable; free (baselines available); used by SOCs and DevOps.

---

## CIS Controls for Penetration Testers

**How to use CIS Controls in pentesting:**

- **Scope**: CIS Controls define what "mature" security looks like; assess which controls are present/absent.
- **Finding mapping**: Map findings to CIS Controls (weakness in Control 5 Access Control → finding about excessive access).
- **Remediation**: CIS roadmap is a quick fix playbook — "implement Control X at IG2 level" is specific, actionable guidance.
- **Client communication**: Clients understand CIS Controls better than technical vulnerability lists — frame findings as "Control Y weakness" for clarity.

Example: Excessive file shares → Control 12 (Network Infrastructure Management) / Control 6 (Access Control Management) failure → remediate with RBAC + segmentation.

---


## See also

[[NIST-CSF]], [[NIST-SP-800-53]], [[ISO-27001-27002]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
