# Frameworks and Compliance — Index

#MOC #Frameworks #Compliance #Reference

Map of content for the security frameworks, compliance/regulatory standards, testing methodologies, and vulnerability-classification references in this folder. 35 notes, grouped below. Each note is a standalone engagement reference; use this page to navigate and to see how they relate.

---

## Regulatory & Compliance (laws & mandates)

| Note | What it covers |
|---|---|
| [[PCI-DSS-v4]] | Payment card data security (12 requirements / 6 goals, v4.0) |
| [[HIPAA]] | US health information privacy & security (PHI) |
| [[HITRUST]] | Healthcare security framework harmonizing HIPAA/NIST/ISO/PCI |
| [[GDPR]] | EU personal data protection |
| [[GLBA]] | US financial-sector consumer privacy |
| [[FERPA]] | US student education records |
| [[SOC-2-Type-II]] | Service-organization trust-criteria audit |
| [[FedRAMP]] | US federal cloud authorization |

---

## Security Frameworks & Control Catalogs

| Note | What it covers |
|---|---|
| [[NIST-CSF]] | Cybersecurity risk framework (6 functions, CSF 2.0) |
| [[NIST-SP-800-53]] | Federal security & privacy control catalog |
| [[ISO-27001-27002]] | ISMS standard (27001) + control catalog (27002:2022) |
| [[CIS-Controls]] | Prioritized 18 controls for rapid risk reduction |

---

## Architecture, Cloud & Secure Development

| Note | What it covers |
|---|---|
| [[Zero-Trust-Architecture]] | Never trust, always verify (NIST SP 800-207) |
| [[Critical-Infrastructure-ICS-Security]] | OT/ICS security (NIST SP 800-82) |
| [[Cloud-Security]] | Cloud-native risks (AWS/Azure/GCP) |
| [[Container-Security]] | Docker / Kubernetes security |
| [[Supply-Chain-Security]] | SLSA, SBOM, build integrity, provenance |
| [[Secure-SDLC]] | Security across the development lifecycle (SSDF) |

---

## Testing Methodologies & Threat Intelligence

| Note | What it covers |
|---|---|
| [[PTES]] | Penetration Testing Execution Standard (7 phases) |
| [[NIST-SP-800-115]] | Technical security testing & assessment guide |
| [[MITRE-ATT-CK]] | Adversary tactics & techniques (14 tactics) |
| [[Threat-Intelligence-Frameworks]] | TLP 2.0, STIX/TAXII |

---

## OWASP Standards

| Note | What it covers |
|---|---|
| [[OWASP-Top-10]] | Web application risks (2025) |
| [[OWASP-API-Top-10]] | API security risks (2023) |
| [[OWASP-LLM-Top-10]] | LLM / AI application risks (2025) |
| [[OWASP-Mobile-Top-10]] | Mobile application risks (2024) |
| [[OWASP-ASVS]] | Application Security Verification Standard (v5.0) |
| [[OWASP-MASVS]] | Mobile App Security Verification Standard (v2.1) |
| [[OWASP-Proactive-Controls]] | Developer-facing defenses (v4, 2024) |
| [[OWASP-SAMM]] | Software Assurance Maturity Model |
| [[OWASP-Secure-Coding-Practices]] | Secure coding checklist |

---

## Vulnerability Scoring & Classification

| Note | What it covers |
|---|---|
| [[CVSSv3]] | CVSS v3.1 scoring metrics |
| [[CVSSv4]] | CVSS v4.0 scoring metrics |
| [[CWE-Top-25]] | Most dangerous software weaknesses (2025) |
| [[SANS-Top-25]] | Software security errors (CWE/SANS lineage) |

---

## How they relate

- **Compliance ↔ controls**: [[PCI-DSS-v4]], [[HIPAA]], [[SOC-2-Type-II]] define *what* to prove; [[NIST-SP-800-53]], [[ISO-27001-27002]], [[CIS-Controls]] provide the *controls* to satisfy them.
- **Federal stack**: [[FedRAMP]] baselines are built on [[NIST-SP-800-53]]; both align to [[NIST-CSF]].
- **Healthcare**: [[HITRUST]] harmonizes [[HIPAA]] with NIST/ISO/PCI.
- **Privacy laws**: [[GDPR]], [[GLBA]], [[FERPA]], [[HIPAA]].
- **App security ladder**: [[OWASP-Top-10]] (risks) → [[OWASP-ASVS]] (verify) → [[OWASP-Proactive-Controls]] / [[OWASP-Secure-Coding-Practices]] (build) → [[OWASP-SAMM]] / [[Secure-SDLC]] (mature the program).
- **Mobile pair**: [[OWASP-Mobile-Top-10]] (risks) ↔ [[OWASP-MASVS]] (verify).
- **Offensive workflow**: [[PTES]] / [[NIST-SP-800-115]] (methodology) → [[MITRE-ATT-CK]] (techniques) → [[Threat-Intelligence-Frameworks]] (share findings), scored with [[CVSSv4]] and classified with [[CWE-Top-25]].

---

*Created: 2026-07-21*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
