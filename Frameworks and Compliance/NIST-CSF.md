# NIST Cybersecurity Framework (CSF)

#Frameworks #NIST #CSF #RiskManagement #Governance

## What is this?

**NIST Cybersecurity Framework** — US framework for managing cybersecurity risk. Provides a common language for cybersecurity and a structured approach to governing, identifying, protecting, detecting, responding to, and recovering from cyber threats. Non-mandatory but increasingly required by government/enterprise customers (RFP requirement).

---

## Overview

**NIST CSF vs. NIST SP 800-53:**
- **CSF** = high-level framework (what to do); flexible implementation.
- **SP 800-53** = detailed security controls (how to do it); prescriptive.

CSF is often the starting point; orgs then map to 800-53 or other standards (ISO 27001, CIS Controls) for implementation details.

**Versions:** CSF 1.0 (2014), CSF 1.1 (2018), **CSF 2.0 (2024, latest)** — adds governance, supply chain, and emphasizes continuous improvement.

---

## The 6 Core Functions (CSF 2.0)

CSF 2.0 organizes cybersecurity around **6 core functions**. The new **GOVERN (GV)** function — added in 2.0 — is the overarching function that establishes and monitors the cybersecurity strategy informing the other five (detailed under [CSF 2.0 Updates](#csf-20-updates-2024) below). The five operational functions:

### 1. IDENTIFY (ID)
"What assets and risks do we have?"

Develop an understanding of your organization's cybersecurity context.

**Key Activities:**
- Asset inventory: hardware, software, data, people.
- Business continuity planning: critical processes, dependencies.
- Risk assessment: threats, vulnerabilities, likelihood, impact.
- Governance: roles, policies, compliance requirements.
- Supply chain risk: third-party dependencies, vendor security.
- Data management: what data you have, where it's stored, who accesses it.

**Questions to answer:**
- What systems/data do we have?
- Who owns each system?
- What's the business impact if a system fails?
- What threats are we likely to face?
- What's our current risk level?

---

### 2. PROTECT (PR)
"How do we prevent/mitigate threats?"

Implement safeguards to prevent or slow cyber attacks.

**Key Activities:**
- Access control: MFA, least privilege, authentication.
- Data security: encryption, classification, handling procedures.
- Infrastructure hardening: secure configuration, remove unnecessary services.
- Supply chain protection: vendor risk management, secure procurement.
- Training & awareness: staff education on threats/procedures.
- Information and processes: document security policies, procedures, controls.

**Questions to answer:**
- Who has access to what? Is it appropriate?
- How do we protect data (at rest, in transit)?
- Are systems configured securely (hardened)?
- Do staff know how to handle security incidents?
- Do we have secure development practices?

---

### 3. DETECT (DE)
"How do we know when something bad is happening?"

Implement monitoring and analysis to find unauthorized activities or breaches.

**Key Activities:**
- Anomalies and events: logging, monitoring, alerting.
- Security monitoring: SIEM, IDS/IPS, system logs.
- Investigation support: forensics, evidence preservation.
- Detection processes: procedures for identifying incidents.

**Questions to answer:**
- Are we logging all relevant activities?
- Do we have alerting for suspicious behavior?
- Can we investigate incidents (forensics)?
- How quickly can we detect a breach?

---

### 4. RESPOND (RS)
"What's our plan when something bad happens?"

Implement procedures for incident response.

**Key Activities:**
- Response planning: incident response plan, playbooks, escalation.
- Communications: who to notify (internal, external, regulators).
- Mitigation: containment, eradication, short-term fixes.
- Improvement: root cause analysis, lessons learned.

**Questions to answer:**
- Do we have an incident response plan?
- Who's on the incident response team?
- How do we communicate with stakeholders during an incident?
- Can we contain/fix incidents quickly?

---

### 5. RECOVER (RC)
"How do we restore normal operations after an incident?"

Implement procedures and capabilities to restore systems and processes.

**Key Activities:**
- Recovery planning: RTO/RPO targets, recovery procedures.
- Improvements: what did we learn? How do we prevent this next time?
- Communications: post-incident updates to stakeholders.
- Restoration: bring systems back online, verify integrity.

**Questions to answer:**
- Can we restore systems quickly (RTO)?
- How much data loss is acceptable (RPO)?
- Do we test recovery procedures regularly?
- Do we improve after incidents?

---

## The 22 Categories

Under the 6 functions, CSF 2.0 organizes into **22 categories** (groups of related activities) and 106 subcategories. Each category is a specific outcome you need to achieve.

**Examples (ID category):**
- **ID.AM-1**: Inventoried physical devices and software assets.
- **ID.RA-1**: Asset vulnerabilities are identified and recorded.
- **ID.RM-1**: Risk management processes and procedures.

**Examples (PR category):**
- **PR.AC-1**: Identities and access management systems are managed.
- **PR.DS-1**: Data security policies and procedures.
- **PR.IP-1**: Security policies and procedures are managed.

**Structure:** Each category has a description, outcomes, and reference implementations (mapped to other standards like NIST 800-53, CIS Controls, ISO 27001).

---

## Implementation Tiers (Maturity Levels)

CSF defines 4 tiers describing how mature your implementation is:

### Tier 1: Partial
- Processes are informal, reactive.
- Limited awareness of cybersecurity risks.
- Example: no formal incident response plan; respond to incidents ad-hoc.

### Tier 2: Risk-Informed
- Processes are formal but not always integrated.
- Some awareness of risks; some coordination across functions.
- Example: incident response plan exists; may not be tested regularly.

### Tier 3: Repeatable
- Processes are formal, integrated, regularly reviewed.
- Risk management is structured and documented.
- Example: incident response plan documented, trained, and tested annually.

### Tier 4: Adaptive
- Processes are formal, optimized, continuously improving.
- Organization learns from incidents and adjusts practices.
- Example: incident response processes continuously refined based on lessons learned.

**Most organizations target Tier 2–3; Tier 4 is aspirational.**

---

## Profiles

A **CSF Profile** describes your current and target state:

- **Current Profile**: where you are today (Tier 1–4 per function).
- **Target Profile**: where you want to be (Tier 2–4 per function).

**Example:**
- **Current State**: Identify (Tier 2), Protect (Tier 2), Detect (Tier 1), Respond (Tier 1), Recover (Tier 1).
- **Target State**: Identify (Tier 3), Protect (Tier 3), Detect (Tier 3), Respond (Tier 2), Recover (Tier 2).

**Gap Analysis**: Difference between current and target = your roadmap.

---

## CSF 2.0 Updates (2024)

CSF 2.0 introduces:

### New Function: GOVERN (GV)
- Emphasis on cybersecurity governance.
- Board oversight, compliance, risk management.
- Organizational structure and accountability.

**Key Categories:**
- **GV.OC-1**: Organizational cybersecurity culture.
- **GV.RM-1**: Risk management strategy and processes.
- **GV.RR-1**: Roles and responsibilities for cybersecurity.

### Supply Chain Risk Management (Enhanced)
- Deeper focus on third-party/vendor risks.
- Contractual obligations, audits, incident notification.

### Continuous Improvement
- Feedback loops from incidents and monitoring.
- Regular reviews and updates to processes.

### Measurable Outcomes
- More emphasis on metrics and KPIs.
- Ability to track progress toward target profile.

---

## CSF Implementation Approach

### Phase 1: Assess Current State (1–2 months)

1. **Define scope**: which functions/categories apply to your organization?
2. **Current profile**: assess maturity of each function (Tier 1–4).
3. **Document baseline**: current policies, procedures, controls.
4. **Gap analysis**: what's missing to reach target tier?

### Phase 2: Define Target State (1 month)

1. **Business drivers**: what tier should each function target?
   - Critical infrastructure, government contractor → Tier 3–4.
   - Medium-risk business → Tier 2–3.
   - Low-risk → Tier 1–2.
2. **Target profile**: define goals per function.
3. **Roadmap**: prioritize gaps by risk/impact.

### Phase 3: Implement (3–12 months)

1. **Quick wins**: easy improvements (policies, awareness, basic tools).
2. **Medium-term**: infrastructure changes (logging, hardening, MFA).
3. **Long-term**: culture change, continuous improvement processes.

### Phase 4: Measure & Improve (Continuous)

1. **Metrics**: define KPIs per function.
2. **Dashboard**: track progress toward target profile.
3. **Regular reviews**: assess current state quarterly; adjust roadmap.
4. **Incidents as learning**: each incident feedback improves processes.

---

## CSF vs. Other Frameworks

| Framework | Type | Scope | Flexibility | Use Case |
|---|---|---|---|---|
| **NIST CSF** | Framework | Broad (risk management) | High (guidance, not prescriptive) | Strategic planning, governance |
| **NIST SP 800-53** | Controls Standard | Detailed (federal systems) | Low (prescriptive, detailed) | Federal contractors, high-risk |
| **ISO 27001** | Management System | Information security | Medium (balanced) | Global orgs, certification |
| **CIS Controls** | Prioritized Controls | Practical (20 controls) | Medium (prioritized baseline) | SMBs, quick wins |
| **HITRUST** | Compliance Framework | Healthcare | Low (prescriptive, strict) | Healthcare, compliance-heavy |

**CSF is the starting framework** — most orgs begin with CSF to structure thinking, then map to 800-53/ISO/CIS for detailed implementation.

---

## Mapping CSF to Other Standards

CSF is intentionally flexible; the detailed controls are in other frameworks:

**CSF Category PR.AC-1 (Access Control)** maps to:
- **ISO 27001**: A.4.1, A.5.2, A.6.1.
- **NIST 800-53**: AC-2, AC-3, AC-4 (dozens of access control controls).
- **CIS Controls**: Control 5 (Account Management).

Organizations typically:
1. Use CSF to structure strategy (what to do).
2. Map to 800-53/ISO/CIS for implementation (how to do it).
3. Use CSF as communication tool with executives/board.

---

## CSF for Penetration Testers

**How CSF relates to pentesting:**

- **IDENTIFY**: pentest scope (which systems, what's critical).
- **PROTECT**: pentest validates controls are in place (access, encryption, segmentation).
- **DETECT**: pentest validates detection capabilities (does IDS catch attack? Logs captured?).
- **RESPOND**: pentest validates incident response (can team handle active attack?).
- **RECOVER**: pentest validates recovery procedures (can systems be restored?).

**Mature organizations use pentesting to measure progress toward target CSF profile** — a pentest becomes part of DETECT/RESPOND maturity assessment.

---

## Common CSF Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No current-state assessment | Roadmap not grounded in reality | Formally assess each function/category; document baseline |
| Target too ambitious | Plan fails; morale drops | Target Tier 2–3; Tier 4 takes years |
| IDENTIFY function weak | Don't know what to protect | Invest in asset inventory, risk assessment |
| No governance (GV) | No accountability, inconsistent execution | Assign roles, establish policies, board oversight |
| No metrics | Can't track progress | Define KPIs per function; monthly dashboard |
| One-time exercise | Improvements don't stick | Make CSF continuous (annual review, incident feedback) |

---

## After Implementation

**Continuous Cycle:**

1. **Monthly**: review metrics; trending toward target?
2. **Quarterly**: update current profile; any material changes?
3. **Annually**: full profile review; adjust target; plan next year's improvements.
4. **Per incident**: root cause → control gap → roadmap update.

CSF is a **living document** — not a checkbox exercise.

---


## See also

[[NIST-SP-800-53]], [[ISO-27001-27002]], [[CIS-Controls]], [[Zero-Trust-Architecture]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
