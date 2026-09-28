# OWASP SAMM (Software Assurance Maturity Model)

#OWASP #SAMM #MaturityModel #DevSecOps #AppSec

## What is this?

**OWASP SAMM** — Framework for assessing and improving software security maturity in organizations. Provides roadmap for building/enhancing security practices; organized by business functions and maturity levels. Published 2009; updated 2020 (SAMM 2.0). Used by development teams, security organizations, and enterprises to measure progress.

---

## Overview

**OWASP SAMM Basics:**
- **Purpose**: Measure software security maturity; guide improvement roadmap.
- **Scope**: Organization-wide security practices; development to operations.
- **Audience**: CISOs, security teams, development leadership, architects.

**vs. NIST CSF**:
- **NIST CSF** = broad cybersecurity (all systems); high-level functions.
- **OWASP SAMM** = software development security; detailed practices for dev teams.

**Maturity Levels**: each practice is rated **1 → 2 → 3** (level 0 = practice not performed). Roughly: 1 = ad-hoc/initial, 2 = defined/repeatable, 3 = optimized/measured.

---

## SAMM 2.0 Structure

SAMM 2.0 organizes **15 security practices** into **5 business functions**, each with 3 practices:

| Function | Practices |
|---|---|
| **Governance** | Strategy & Metrics · Policy & Compliance · Education & Guidance |
| **Design** | Threat Assessment · Security Requirements · Security Architecture |
| **Implementation** | Secure Build · Secure Deployment · Defect Management |
| **Verification** | Architecture Assessment · Requirements-driven Testing · Security Testing |
| **Operations** | Incident Management · Environment Management · Operational Management |

> [!note]
> The walkthrough below follows the **official SAMM 2.0** structure — 5 business functions × 3 practices = 15. (SAMM 1.x had a separate "Deployment" function; in 2.0 its activities moved into Implementation → *Secure Deployment* and into *Operations*.) Each SAMM practice also has two *streams* (A/B) and maturity levels 1–3; the compact 1/2/3 lines below summarize the maturity ladder per practice.

### Governance (GOV)

*Cross-cutting strategy, oversight, and enablement.*

#### Strategy & Metrics
- **1** — A security roadmap exists with a basic set of application-risk metrics.
- **2** — Roadmap aligned to a measured application-risk profile; metrics gathered across the portfolio.
- **3** — Strategy and budget are driven by metrics and reviewed continuously.

#### Policy & Compliance
- **1** — Security/compliance baseline (policies, standards) identified for applications.
- **2** — Policies mapped to applications; third parties held to the same requirements.
- **3** — Compliance measured per application and reported; deviations tracked to closure.

#### Education & Guidance
- **1** — Ad-hoc security training available to developers.
- **2** — Role-based training plus a centralized secure-development knowledge base.
- **3** — Training effectiveness measured; a security-champions program embeds expertise in teams.

---

### Design (DES)

*Getting requirements and architecture right before code.*

#### Threat Assessment
- **1** — Best-effort application risk classification and simple threat modeling.
- **2** — Standardized threat-modeling methodology (STRIDE/PASTA) applied to high-risk apps.
- **3** — Threat models are proactive, tool-assisted, and kept current as the design changes.

#### Security Requirements
- **1** — Security requirements captured for high-risk features.
- **2** — Requirements standardized and derived from business/compliance drivers; supplier requirements included.
- **3** — Requirements are structured, testable, and traced through to verification.

#### Security Architecture
- **1** — Teams are aware of secure-design principles and reference components.
- **2** — Shared, vetted security components/patterns promoted for reuse.
- **3** — Reference architecture and component security managed and measured across the portfolio.

---

### Implementation (IMP)

*Building and shipping the software securely.*

#### Secure Build
- **1** — Repeatable, documented build process.
- **2** — Build automated with security checks (SAST, dependency/SCA scanning) and an SBOM produced.
- **3** — Build integrity enforced (signed artifacts, provenance); gates block on findings. See [[Supply-Chain-Security]].

#### Secure Deployment
- **1** — Deployment process is documented and repeatable.
- **2** — Deployment automated; secrets injected securely (no secrets in code or images).
- **3** — Deployment integrity verified; configuration and secrets managed and audited continuously.

#### Defect Management
- **1** — Security defects are collected in one place.
- **2** — Defects tracked with severity/SLA, fed back to teams, and reported as metrics.
- **3** — Defect metrics drive process improvement; SLAs measured and enforced.

---

### Verification (VER)

*Checking that what was built matches the security intent.*

#### Architecture Assessment
- **1** — Security mechanisms reviewed against requirements for high-risk apps.
- **2** — Architecture reviewed against the threat model; findings tracked.
- **3** — Reviews are systematic and measured across the portfolio.

#### Requirements-driven Testing
- **1** — Ad-hoc testing that controls work (positive tests) and that misuse is blocked (negative tests).
- **2** — Security test cases derived from requirements and run consistently.
- **3** — Testing automated against requirements and abuse cases; coverage measured.

#### Security Testing
- **1** — Automated scanning (SAST/DAST) on high-risk apps.
- **2** — Scanning integrated into the pipeline; manual pen testing on release; findings triaged. See [[PTES]].
- **3** — Continuous, tuned automated + manual testing; results feed metrics and release gates.

---

### Operations (OPS)

*Keeping software secure in production. (This function replaced SAMM 1.x's "Deployment.")*

#### Incident Management
- **1** — A basic capability to detect and respond to incidents exists.
- **2** — Formal IR plan with roles, playbooks, and drills; incidents analyzed for lessons.
- **3** — Detection/response measured and continuously improved, with partial automation.

#### Environment Management
- **1** — Patching and hardening of the deployment environment happen best-effort.
- **2** — Consistent hardening baselines (CIS) and a patch cadence; configuration audited.
- **3** — Environment managed as code with continuous compliance and drift remediation.

#### Operational Management
- **1** — Basic data-protection and system-decommissioning practices.
- **2** — Data lifecycle (classification, retention, secure disposal) and legacy/EOL management formalized.
- **3** — Operational processes measured and continuously improved.

---

## SAMM Maturity Progression

Typical progression for organization (not all functions mature at same rate):

| Phase | Timeframe | Focus |
|---|---|---|
| Initial | 0–6 months | Establish practices, create policies, basic training |
| Managed (Lvl 1) | 6–12 months | Formal processes, metrics tracking, tools adoption |
| Measured (Lvl 2) | 12–24 months | Automation, continuous improvement, data-driven decisions |
| Optimized (Lvl 3) | 24+ months | Continuous optimization, advanced automation, industry leadership |

---

## SAMM vs. Other Models

| Model | Focus | Scope | Maturity Levels | Use Case |
|---|---|---|---|---|
| **OWASP SAMM** | Software security practices | Development org | 0–3 | Develop org security roadmap |
| **NIST CSF** | Cybersecurity function | Organization-wide | N/A (maturity implicit) | Enterprise cybersecurity strategy |
| **ISO 27001** | Information security management | Organization-wide | N/A (compliance-based) | Global certification |
| **CMMI** | Software process maturity | Overall process | 1–5 | Process improvement (broader than security) |

---

## SAMM Implementation Roadmap

### Year 1: Establish Foundation (Target: Maturity 1 across all functions)
- [ ] Security policies documented and communicated.
- [ ] Risk management process established.
- [ ] Design reviews, threat modeling introduced.
- [ ] Code review process with security checklist.
- [ ] Security testing integrated into QA.
- [ ] Incident response plan documented, team trained.
- [ ] Hardening standards defined.
- [ ] Release management formalized.

### Year 2: Implement Automation (Target: Maturity 2 across all functions)
- [ ] SAST/DAST tools integrated into CI/CD.
- [ ] Dependency scanning automated.
- [ ] Infrastructure as Code.
- [ ] Continuous monitoring and logging.
- [ ] Metrics dashboards created.
- [ ] Annual penetration testing.

### Year 3+: Continuous Optimization (Target: Maturity 3)
- [ ] Continuous deployment (frequent releases).
- [ ] Automated security gates (all tests pass before release).
- [ ] Continuous penetration testing (red team).
- [ ] Metrics-driven decision making.
- [ ] Lessons learned automation.

---

## SAMM Assessment Process

### Self-Assessment
1. For each practice, rate current maturity (0–3).
2. Document evidence (policies, tools, metrics).
3. Identify gaps (what's missing to reach next level).

### External Assessment
1. Third-party assessor reviews practices.
2. Interviews staff, reviews documentation.
3. Provides independent maturity rating.
4. Recommends improvements.

### Roadmap Development
1. Prioritize high-impact improvements.
2. Set targets (e.g., "Maturity 2 by Q4 2025").
3. Allocate resources, assign owners.
4. Track progress; adjust as needed.

---

## Quick Reference: SAMM Maturity Levels

| Level | Description | Example |
|---|---|---|
| **0 (Initial)** | No formal practice; ad-hoc | Security testing done occasionally, when budget allows |
| **1 (Managed)** | Formal process defined; inconsistently applied | Security testing scheduled annually; documented but not automated |
| **2 (Measured)** | Process applied consistently; metrics tracked | Security testing automated; results dashboard; metrics trending |
| **3 (Optimized)** | Process continuously improved; data-driven | Continuous security testing; automated gates; lessons learned drive improvements |

---


## See also

[[Secure-SDLC]], [[OWASP-Proactive-Controls]], [[OWASP-Secure-Coding-Practices]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-09-27*
*Model: claude-opus-4-8*
