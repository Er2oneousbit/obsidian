# OWASP ASVS (Application Security Verification Standard)

#OWASP #ASVS #Verification #SecureCoding #AppSec

## What is this?

**OWASP ASVS** — Comprehensive security verification standard for web applications. Provides a detailed, testable checklist of security requirements organized by chapter (encoding, validation, authentication, authorization, cryptography, etc.). Used as an assessment baseline for secure development, code review, and penetration testing. Current release is **v5.0.0 (May 2025)** — ~350 requirements across **17 chapters**, retaining the three verification levels.

---

## Overview

**OWASP ASVS Basics:**
- **Purpose**: Define security requirements; measure compliance; guide secure development.
- **Scope**: Web applications and APIs (traditional, cloud, microservices, SPAs).
- **Audience**: Developers, security architects, code reviewers, pentesters, QA.

**vs. Other Standards**:
- **OWASP Top 10** = risks (what to avoid); high-level awareness. See [[OWASP-Top-10]].
- **OWASP ASVS** = requirements/controls (what to build and verify); detailed checklist.
- **NIST SP 800-53** = comprehensive controls for federal systems. See [[NIST-SP-800-53]].
- **ASVS** = application-specific; developer-implementable and directly testable.

> [!note]
> **v4.0.x → v5.0 changed a lot.** v4.0 had 14 chapters; v5.0 reorganized into **17**, splitting encoding/output into its own chapter, adding **Web Frontend Security**, **Self-contained Tokens**, **OAuth and OIDC**, and **WebRTC**, and rebalancing the levels (L1 lightened, L3 substantially expanded). Requirement numbering was reworked, so old `V2.1.1`-style IDs from 4.x do not map 1:1 to 5.0.

---

## Verification Levels

The three levels are **cumulative** — L2 includes all of L1, L3 includes all of L2.

| Level | Target | Typical assurance activity |
|---|---|---|
| **L1** | Baseline security hygiene; lower-risk apps | Automated scanning + developer review; largely black-box testable |
| **L2** | Business-critical apps handling sensitive data (most apps should target this) | Manual code review + testing; the recommended standard for most software |
| **L3** | High-assurance / high-value systems (finance, healthcare, government) | Threat modeling, in-depth review, penetration testing, formal assessment |

---

## The 17 Chapters (v5.0)

| # | Chapter | Covers |
|---|---|---|
| V1 | Encoding and Sanitization | Context-aware output encoding and sanitization (the primary XSS/injection-output defenses) |
| V2 | Validation and Business Logic | Input validation, strong typing, and business-logic integrity (idempotency, sequencing, anti-automation) |
| V3 | Web Frontend Security | Browser-side controls: CSP, security headers, CORS, cookie attributes, clickjacking defenses |
| V4 | API and Web Service | REST/GraphQL security, rate limiting, schema validation, API-specific authz |
| V5 | File Handling | Upload validation (type/size), safe storage outside web root, no execution of uploads |
| V6 | Authentication | Password policy, breached-password checks, MFA, anti-brute-force, secure recovery |
| V7 | Session Management | Strong session tokens, rotation on login, timeout, secure cookie flags, logout invalidation |
| V8 | Authorization | Least privilege, deny-by-default, authorization enforced server-side on every request |
| V9 | Self-contained Tokens | Secure use/validation of stateless tokens (e.g. JWT): signature, algorithm, claims, expiry |
| V10 | OAuth and OIDC | Correct OAuth 2.x / OpenID Connect flows, token handling, authorization-server hardening |
| V11 | Cryptography | Approved algorithms, key management, sufficient entropy; includes post-quantum planning (L3) |
| V12 | Secure Communication | TLS 1.2+ everywhere, certificate validation, strong ciphers |
| V13 | Configuration | Hardened deployment, secrets management, no defaults/debug, minimal footprint |
| V14 | Data Protection | Data classification, protection at rest, caching/leakage controls, privacy |
| V15 | Secure Coding and Architecture | Secure design, dependency/supply-chain hygiene, safe deserialization, no dangerous code execution |
| V16 | Security Logging and Error Handling | Log security events (no secrets/PII), protect logs, fail-secure error handling |
| V17 | WebRTC | Security of real-time peer-to-peer media/data channels |

> [!note]
> Access control ("Authorization", V8) and stateless tokens (V9) are now separate chapters, and OAuth/OIDC (V10) is broken out from general authentication (V6) — reflecting how much modern authn/authz is delegated to token- and OAuth-based flows.

---

## Using ASVS for Pentesting

**Pre-test scope**:
- Confirm which ASVS **level** the app claims (L1/L2/L3) — that sets the requirement set to test against.
- Use the chapter list as a coverage roadmap so no domain is missed.

**During the test**:
- Test each applicable requirement; record pass/fail with evidence.
- Rate failures by severity (Critical/High/Medium/Low).

**Report**:
- Map each finding to its ASVS chapter/requirement so remediation is precise and re-testable.

**Example finding**:
- **Chapter**: V6 Authentication (target L2).
- **Issue**: Application accepts 6-character passwords and does not check against breached-password lists.
- **Fix**: Enforce a stronger password policy and integrate a breached-password check per V6.

---

## Resources

- **OWASP ASVS project**: [owasp.org/www-project-application-security-verification-standard](https://owasp.org/www-project-application-security-verification-standard/)
- **GitHub (source, latest release, CSV/JSON exports)**: [github.com/OWASP/ASVS](https://github.com/OWASP/ASVS)
- **Mobile equivalent**: [[OWASP-MASVS]]


## See also

[[OWASP-Top-10]], [[OWASP-Proactive-Controls]], [[OWASP-MASVS]], [[CWE-Top-25]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
