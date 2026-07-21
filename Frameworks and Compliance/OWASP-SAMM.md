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
> The walkthrough below labels practices loosely (e.g. "Design Reviews", "Secure Coding") — use the table above for the **official** SAMM 2.0 names. Also note: **"Deployment" was a SAMM 1.x business function; in 2.0 it was replaced by "Operations"** (secure-deployment/defect items moved under Implementation), so treat the legacy "Business Function 6: Deployment" heading below as pre-2.0.

### Business Function 1: Governance (GOV)

**Goal**: Strategic security management; oversight, compliance, culture.

#### GOV.1 Policies and Compliance

**Maturity 1 (Managed)**:
- Information security policies documented.
- Policies communicated to all staff.
- Policy compliance monitored.

**Maturity 2 (Measured)**:
- Policies cover all security domains (data protection, incident response, etc.).
- Metrics track compliance (% staff trained, audits passed, etc.).

**Maturity 3 (Optimized)**:
- Policies evolved based on incident data, threat landscape changes.
- Continuous improvement; policies updated quarterly.

---

#### GOV.2 Risk Management

**Maturity 1 (Managed)**:
- Risk assessment process defined (identify threats, vulnerabilities, likelihood, impact).
- Risks documented; remediation plans created.

**Maturity 2 (Measured)**:
- Risk assessment performed regularly (annually minimum).
- Risks tracked over time; trends analyzed.
- Risk appetite defined (org's risk tolerance).

**Maturity 3 (Optimized)**:
- Risk assessment integrated into all business decisions.
- Risk response strategies optimized (accept, mitigate, transfer).
- Continuous monitoring; risks re-assessed quarterly.

---

#### GOV.3 Strategy and Metrics

**Maturity 1 (Managed)**:
- Security strategy defined (goals, priorities, timeline).
- Business-aligned (security supports business objectives).

**Maturity 2 (Measured)**:
- Metrics track progress (# vulnerabilities, code review %, pen test coverage).
- Dashboards; stakeholder reporting.

**Maturity 3 (Optimized)**:
- Metrics drive decisions (data-driven security investment).
- Benchmarking (compare against industry peers).
- Continuous optimization based on metrics.

---

### Business Function 2: Design (DES)

**Goal**: Secure application architecture; threat modeling, secure design.

#### DES.1 Design Reviews

**Maturity 1**:
- Security reviews conducted on major applications (not all).
- Informal; no standard process.

**Maturity 2**:
- Formal design review process; all apps reviewed.
- Checklist-based; standard criteria.

**Maturity 3**:
- Continuous design review (iterative; reviews during development).
- Metrics-driven (track issues found vs. exploited; validate effectiveness).

---

#### DES.2 Threat Modeling

**Maturity 1**:
- Threat modeling performed on request (not standard).
- Informal; documented in variable detail.

**Maturity 2**:
- Threat modeling standard practice (all critical apps).
- Structured approach (STRIDE, PASTA, or similar).
- Documented; traces to mitigations.

**Maturity 3**:
- Continuous threat modeling (updated as design changes).
- Integrated with development workflow.
- Automated tools assist process.

---

#### DES.3 Secure Coding

**Maturity 1**:
- Secure coding guidelines published.
- Limited adoption; voluntary.

**Maturity 2**:
- Secure coding standards enforced (code review checks against standards).
- Training mandatory for all developers.
- Compliance metrics tracked.

**Maturity 3**:
- Secure coding practices integrated into development workflow.
- Automated enforcement (linters, SAST tools).
- Continuous improvement based on incident analysis.

---

### Business Function 3: Implementation (IMP)

**Goal**: Secure coding practices; vulnerability prevention during development.

#### IMP.1 Code Review

**Maturity 1**:
- Peer review conducted; focuses on functionality.
- Security is secondary concern.

**Maturity 2**:
- Security-focused code reviews (formal process).
- Security checklist used; reviewers trained on common vulns.
- All code reviewed before merge.

**Maturity 3**:
- Continuous code review (automated + manual).
- SAST tools integrated (automated scanning; findings prioritized).
- Metrics: # issues found, severity, remediation time.

---

#### IMP.2 Security Testing

**Maturity 1**:
- Basic testing (unit tests); security not primary focus.
- Ad-hoc penetration testing (not scheduled).

**Maturity 2**:
- Security-focused test cases (test for injection, XSS, CSRF, etc.).
- Regular pen testing (annual minimum).
- Test coverage metrics.

**Maturity 3**:
- Continuous security testing (DAST in CI/CD).
- Automated security tests (run on every commit).
- Red team exercises (annual; simulate advanced attacks).
- Test coverage 80%+ of codebase.

---

#### IMP.3 Secure Build

**Maturity 1**:
- Build process documented; version control used.
- No automated security gates.

**Maturity 2**:
- Security checks in CI/CD (SAST, dependency scanning).
- Automated tests; security findings block merge.
- Build artifacts signed; integrity verified.

**Maturity 3**:
- Comprehensive security checks in pipeline.
- Automated scanning, testing, code review gates.
- Build metrics; failures analyzed; trends tracked.

---

### Business Function 4: Verification (VER)

**Goal**: Testing, validation of security controls; quality assurance.

#### VER.1 Security Testing

**Maturity 1**:
- Security testing performed; not integrated into standard QA.
- Manual testing; variable coverage.

**Maturity 2**:
- Security testing part of QA process (all releases).
- Test cases documented; repeatable.
- Severity levels defined; critical issues block release.

**Maturity 3**:
- Continuous security testing (automated, part of CI/CD).
- Metrics: coverage, false positive rate, time-to-remediate.

---

#### VER.2 Penetration Testing

**Maturity 1**:
- Ad-hoc penetration tests (not scheduled).
- Test scope varies; results not formally documented.

**Maturity 2**:
- Annual penetration testing (external firm or internal team).
- Formal scope, rules of engagement, reporting.
- Remediation tracked; re-test confirms fixes.

**Maturity 3**:
- Continuous penetration testing (ongoing red team exercises).
- Metrics: findings, time-to-remediate, trend analysis.
- Lessons learned applied to defensive controls.

---

#### VER.3 Resilience Testing

**Maturity 1**:
- Disaster recovery testing; limited scope.
- Not integrated into security program.

**Maturity 2**:
- Disaster recovery + incident response tested regularly.
- Formal test plans; documented results.
- RTO/RPO validated.

**Maturity 3**:
- Continuous resilience testing (chaos engineering).
- Metrics: recovery time, data loss, business impact.

---

### Business Function 5: Operations (OPS)

**Goal**: Secure operations; incident response, monitoring, patch management.

#### OPS.1 Incident Management

**Maturity 1**:
- Incident response plan exists; ad-hoc execution.
- No formal training; inconsistent response.

**Maturity 2**:
- Formal incident response plan (roles, procedures, escalation).
- Team trained; annual drills.
- Incidents documented; trends analyzed.

**Maturity 3**:
- Continuous incident response improvement.
- Metrics: detection time, response time, remediation time.
- Automated response (automated playbooks).
- Lessons learned integrated into defensive controls.

---

#### OPS.2 Environment Management

**Maturity 1**:
- Systems configured according to baselines; informal.
- Documentation variable; hard to audit.

**Maturity 2**:
- Hardening standards documented (CIS Benchmarks).
- Configuration scanning (automated audits).
- Remediation tracked; metrics monitored.

**Maturity 3**:
- Infrastructure as Code (declarative; tracked in version control).
- Continuous compliance monitoring.
- Automated remediation (drift corrected automatically).

---

#### OPS.3 Operational Enablement

**Maturity 1**:
- Documentation exists; training ad-hoc.
- Security guidance scattered; not centralized.

**Maturity 2**:
- Security runbooks created (step-by-step procedures).
- Training mandatory; compliance tracked.
- Documentation centralized; accessible.

**Maturity 3**:
- Automation reduces manual procedures (ChatOps, automated workflows).
- Continuous improvement (feedback loops from incidents).

---

### Business Function 6: Deployment (DEP)

**Goal**: Secure release management; supply chain security.

#### DEP.1 Release Management

**Maturity 1**:
- Releases documented; tracking basic.
- No formal approval process.

**Maturity 2**:
- Formal release process (approval, testing, sign-off).
- Release notes include security changes.
- Rollback procedures documented.

**Maturity 3**:
- Continuous deployment (automated; frequent small releases).
- Automated testing gates (security checks before release).
- Metrics: release frequency, time-to-production, incident rate.

---

#### DEP.2 Provisioning

**Maturity 1**:
- Deployment manual; configuration varies.
- No version control for infrastructure.

**Maturity 2**:
- Infrastructure as Code (declarative; tracked in git).
- Automated provisioning (Terraform, Ansible).
- Configuration compliance verified.

**Maturity 3**:
- Continuous provisioning (auto-scaling, self-healing).
- Infrastructure tested automatically (pre-production).
- Metrics: provisioning time, configuration drift, security incidents.

---

#### DEP.3 Decommissioning

**Maturity 1**:
- Systems decommissioned on ad-hoc basis.
- Data disposal inconsistent; sometimes insecure.

**Maturity 2**:
- Formal decommissioning process (data destruction verification).
- Disposal procedures documented.
- Metrics: systems decommissioned, data securely destroyed.

**Maturity 3**:
- Automated decommissioning (infrastructure cleanup).
- Data destruction automated and verified (with cryptographic proof).

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
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
