# AI/LLM Penetration Test Reporting Template

Standardized format for documenting findings from AI/LLM security assessments. Use this template to ensure consistent, high-quality reporting across engagements.

Related: [[AI-LLM-02-Technical-Testing-Checklist]] | [[AI-LLM-03-Payload-Tracker]] | [[AI-LLM-04-Evidence-Collection]]

---

## Report Structure

1. Executive Summary
2. Assessment Overview
3. Findings Summary
4. Detailed Findings
5. Recommendations
6. Appendices

---

## Executive Summary

**Purpose**: High-level overview for non-technical stakeholders (C-suite, business owners)

**Length**: 1-2 pages max

**Include**:
- Testing scope and objectives
- Key findings (Critical/High only)
- Overall risk rating
- Business impact summary
- Top 3-5 recommendations

**Tone**: Business-focused, avoid technical jargon

---

### Executive Summary Template

EXECUTIVE SUMMARY

[Client Name] engaged [Your Company] to conduct a security assessment of their 
AI/LLM system "[System Name]" from [Start Date] to [End Date]. The assessment 
identified [X] security vulnerabilities, including [Y] Critical and [Z] High 
severity findings.

KEY FINDINGS:
The most significant security risks identified include:

1. System Prompt Disclosure - Attackers can extract the AI's configuration and 
   instructions, revealing sensitive business logic and security controls.
   
2. Unrestricted Tool Access - The AI can execute arbitrary code and access 
   internal systems without proper authorization checks.
   
3. Business Logic Manipulation - Users can manipulate the AI into providing 
   unauthorized discounts and bypassing payment controls.

BUSINESS IMPACT:
These vulnerabilities could result in:
- Unauthorized access to customer data (PII/PHI)
- Financial loss through pricing manipulation (estimated $X per incident)
- Reputational damage from AI-generated harmful content
- Regulatory non-compliance (HIPAA, PCI-DSS, etc.)

RECOMMENDATIONS:
Immediate action items to reduce risk:
1. Implement input validation and prompt injection detection
2. Restrict tool/function access with authorization controls
3. Add human-in-the-loop approval for sensitive operations
4. Deploy output filtering for sensitive data
5. Conduct security training for AI development team

OVERALL RISK RATING: [CRITICAL / HIGH / MEDIUM]

A detailed breakdown of findings and remediation guidance follows in this report.

---

## Assessment Overview

### Engagement Details

| Field | Value |
|-------|-------|
| **Client** | [Company Name] |
| **System Tested** | [AI System Name/Version] |
| **Assessment Type** | Black Box / Gray Box / White Box |
| **Testing Period** | [Start Date] - [End Date] |
| **Total Effort** | [X hours] |
| **Tester(s)** | [Name(s)] |
| **Report Date** | [Date] |
| **Report Version** | [v1.0] |

### Scope

**In Scope**:
- [System component 1]
- [System component 2]
- [Endpoint/interface 3]
- [etc.]

**Out of Scope**:
- [Excluded component 1]
- [Excluded component 2]
- [etc.]

### Testing Methodology

The assessment followed a systematic approach:

1. **Reconnaissance** - Mapped attack surface and identified entry points
2. **Prompt Injection Testing** - Attempted to manipulate AI behavior
3. **System Prompt Extraction** - Tried to disclose internal configuration
4. **Guardrail Testing** - Evaluated content filtering and safety controls
5. **Tool/Function Abuse** - Tested authorization on agentic capabilities
6. **Business Logic Testing** - Assessed application-specific vulnerabilities
7. **Data Exfiltration** - Verified sensitive data handling

Reference: [[AI-LLM-02-Technical-Testing-Checklist]]

### Testing Constraints

**Limitations**:
- [e.g., Testing limited to non-production environment]
- [e.g., Rate limiting restricted testing volume]
- [e.g., Certain features were disabled during test window]

**Assumptions**:
- [e.g., Testing assumes current production configuration]
- [e.g., Findings reflect system state as of [date]]

---

## Findings Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | X | XX% |
| High | X | XX% |
| Medium | X | XX% |
| Low | X | XX% |
| Informational | X | XX% |
| **Total** | **X** | **100%** |

### Findings by Category

| Category | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| Prompt Injection | X | X | X | X | X | X |
| Data Disclosure | X | X | X | X | X | X |
| Access Control | X | X | X | X | X | X |
| Business Logic | X | X | X | X | X | X |
| Configuration | X | X | X | X | X | X |
| **Total** | **X** | **X** | **X** | **X** | **X** | **X** |

### OWASP LLM Top 10 Mapping

| OWASP Category | Findings | Severity |
|----------------|----------|----------|
| LLM01: Prompt Injection | F001, F003 | Critical, High |
| LLM02: Insecure Output Handling | F007 | High |
| LLM06: Sensitive Information Disclosure | F001, F008 | Critical |
| LLM07: Insecure Plugin Design | F004 | Critical |
| LLM08: Excessive Agency | F004, F005 | Critical, High |
| [etc.] | | |

---

## Detailed Finding Template

Use this template for each finding. See examples at the end of this document.

---

### [F-XXX] Finding Title

**Severity**: Critical / High / Medium / Low / Informational

**Category**: [Prompt Injection / Data Disclosure / Access Control / Business Logic / etc.]

**OWASP LLM**: [LLM01 / LLM02 / etc.] (if applicable)

**Status**: Open / In Progress / Remediated

---

#### Description

[Clear, concise description of the vulnerability. What is the issue?]

---

#### Impact

[Business and technical impact. What can an attacker do? What's at risk?]

**Technical Impact**:
- [Specific technical consequence 1]
- [Specific technical consequence 2]

**Business Impact**:
- [Business risk 1]
- [Business risk 2]

---

#### Affected Components

- [Component 1]
- [Component 2]

---

#### Evidence

**Screenshots**: (Reference [[AI-LLM-04-Evidence-Collection]])
- `filename1.png`
- `filename2.png`

**Payload Reference**: [[AI-LLM-03-Payload-Tracker#PT-XXX]]

---

#### Proof of Concept

**Step-by-step reproduction**:

1. Step one
2. Step two
3. Step three

**Expected Result**: [what should happen]

**Actual Result**: [what actually happens]

**Reproducibility**: [percentage]

---

#### Root Cause

[Technical explanation of why the vulnerability exists]

---

#### Risk Rating Justification

**CVSS v3.1 Score**: [X.X] ([Severity])

**Vector String**: `CVSS:3.1/AV:[X]/AC:[X]/PR:[X]/UI:[X]/S:[X]/C:[X]/I:[X]/A:[X]`

---

#### Recommendations

**Short-term** (Immediate mitigation):
1. [Quick fix]
2. [Workaround]

**Long-term** (Permanent remediation):
1. [Architectural change]
2. [Code fix]
3. [Process improvement]

---

#### References

- [Link 1]
- [Link 2]

---

## Strategic Recommendations

**1. Implement Defense-in-Depth for AI Systems**

Layer security controls:
- **Input Layer**: Validation, sanitization, injection detection
- **Model Layer**: Guardrails, safety classifiers
- **Output Layer**: Filtering, redaction, encoding
- **Infrastructure Layer**: Network segmentation, least privilege

**2. Adopt Secure AI Development Lifecycle**

- Threat modeling for AI-specific risks
- Security reviews at each development stage
- Continuous monitoring and incident response

**3. Implement Zero Trust for AI Tools/Functions**

- Every tool invocation requires authorization
- Principle of least privilege
- Human-in-the-loop for high-risk operations

---

## Appendices

### Appendix A: Testing Methodology Detail

Full reference: [[AI-LLM-02-Technical-Testing-Checklist]]

### Appendix B: Payload Library

Full reference: [[AI-LLM-03-Payload-Tracker]] and [[AI-LLM-06-Quick-Reference]]

### Appendix C: Evidence Archive

All screenshots and Burp exports: See [[AI-LLM-04-Evidence-Collection]]

### Appendix D: OWASP LLM Top 10

| ID | Category | Description |
|----|----------|-------------|
| LLM01 | Prompt Injection | Manipulating AI via crafted inputs |
| LLM02 | Insecure Output Handling | Unsafe processing of AI outputs |
| LLM03 | Training Data Poisoning | Manipulating training data |
| LLM04 | Model Denial of Service | Resource exhaustion attacks |
| LLM05 | Supply Chain Vulnerabilities | Compromised dependencies |
| LLM06 | Sensitive Information Disclosure | Leaking confidential data |
| LLM07 | Insecure Plugin Design | Unsafe tool/plugin implementation |
| LLM08 | Excessive Agency | AI with too much autonomy |
| LLM09 | Overreliance | Users trusting AI without verification |
| LLM10 | Model Theft | Unauthorized access to model |

---

## Tags
#reporting #findings #documentation #ai-testing #pentest-report

---

## Related Documents
- [[AI-LLM-00-Overview|Overview]]
- [[AI-LLM-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[AI-LLM-03-Payload-Tracker|Payload Tracker]]
- [[AI-LLM-04-Evidence-Collection|Evidence Collection]]
- [[AI-LLM-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
