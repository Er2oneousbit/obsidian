# OWASP Top 10

#OWASP #OWASPTop10 #WebAppAttacks #AppSec #VulnClassification

## What is this?

**OWASP Top 10** — List of the 10 most critical web application security risks, ranked by prevalence and impact. Published by OWASP (Open Web Application Security Project); updated every 3–4 years. Used by developers, testers, and security teams to prioritize application security efforts.

---

## Overview

**OWASP Top 10 Basics:**
- **Purpose**: Raise awareness of most common/critical web app vulnerabilities.
- **Scope**: Web applications (traditional server-side web apps, SPAs, APIs).
- **Audience**: Developers, QA, security teams, anyone building web apps.
- **Data Source**: Contributed application-testing data plus a community survey; derived from ~589 CWEs in the 2025 cycle (up from ~400 in 2021).

**Versions**: 2010, 2013, 2017, 2021, **2025 (current)** — announced at OWASP Global AppSec (Nov 2025), finalized early 2026.

> [!note]
> The Top 10 is largely prevalence-based (what's most common in real testing data), not purely severity-based — some high-severity issues rank lower because they're less frequent. It is an awareness document, not a complete standard; use [[OWASP-ASVS]] for exhaustive verification.

---

## OWASP Top 10 2025 Rankings

| Rank | Category | Change from 2021 |
|---|---|---|
| A01:2025 | Broken Access Control | #1 (unchanged); **SSRF folded in here** |
| A02:2025 | Security Misconfiguration | ▲ up from #5 |
| A03:2025 | Software Supply Chain Failures | **NEW** (expands 2021's "Vulnerable & Outdated Components") |
| A04:2025 | Cryptographic Failures | ▼ down from #2 |
| A05:2025 | Injection | ▼ down from #3 |
| A06:2025 | Insecure Design | ▼ down from #4 |
| A07:2025 | Authentication Failures | ≈ (renamed from "Identification and Authentication Failures") |
| A08:2025 | Software or Data Integrity Failures | ≈ unchanged |
| A09:2025 | Security Logging and Alerting Failures | ≈ (renamed from "…Monitoring Failures") |
| A10:2025 | Mishandling of Exceptional Conditions | **NEW** (error handling / fail-open) |

---

### A01:2025 — Broken Access Control

**Definition**: Users act outside their intended permissions — view/modify others' data, escalate privilege, or reach admin functions. Now also covers **SSRF** (server coerced into making requests on the attacker's behalf).

```python
# VULNERABLE: IDOR — no ownership check
@app.route('/account/<user_id>')
def account(user_id):
    return db.get_account(user_id)   # any id returns any account

# Attacker changes /account/1001 -> /account/1002
```

**Mitigation**: Deny-by-default; enforce authorization server-side on every request; use indirect object references; verify ownership; for SSRF, allowlist destinations and block internal/link-local ranges.

---

### A02:2025 — Security Misconfiguration

**Definition**: Insecure defaults, incomplete hardening, verbose errors, unnecessary features/ports enabled, unpatched config. Jumped to #2 as cloud/IaC scale multiplies misconfig.

```
# Common findings
- Default admin credentials unchanged
- Directory listing enabled
- Stack traces / debug mode in production
- Over-permissive S3 bucket / security group (0.0.0.0/0)
- Unused services and sample apps left installed
```

**Mitigation**: Hardened baselines (CIS benchmarks), repeatable IaC config, minimal footprint, disable debug in prod, review cloud storage/network exposure.

---

### A03:2025 — Software Supply Chain Failures (NEW)

**Definition**: Compromise anywhere in the software supply chain — vulnerable/malicious dependencies, compromised build systems, poisoned distribution. Broadens 2021's "Vulnerable and Outdated Components."

```
- Pulling an unpinned dependency that ships a backdoor (typosquat / hijacked package)
- Build/CI compromise injecting code into artifacts (SolarWinds-style)
- Vulnerable transitive dependency (Log4Shell)
```

**Mitigation**: SBOMs, dependency pinning + lockfiles, signed artifacts/provenance (SLSA, Sigstore), SCA scanning (Dependabot/Snyk), harden CI/CD. See [[Supply-Chain-Security]].

---

### A04:2025 — Cryptographic Failures

**Definition**: Weak/missing protection of data in transit or at rest — leads to exposure of PII, credentials, card data.

```
- Cleartext transport (HTTP, plain LDAP)
- Weak/deprecated algorithms (MD5, SHA1, DES, ECB mode)
- Hardcoded keys; passwords stored with fast/unsalted hashes
```

**Mitigation**: TLS 1.2+ everywhere; strong algorithms (AES-GCM, SHA-256+); password hashing with Argon2/bcrypt; proper key management (HSM/KMS); classify and minimize sensitive data.

---

### A05:2025 — Injection

**Definition**: Untrusted input interpreted as code/commands — SQL, NoSQL, OS command, LDAP, and **XSS** (still classed under Injection since 2021).

```python
# VULNERABLE: SQL injection
query = f"SELECT * FROM users WHERE name = '{name}'"   # ' OR '1'='1
```

**Mitigation**: Parameterized queries/prepared statements; context-aware output encoding for XSS; allowlist input validation; safe APIs instead of shells; least-privilege DB accounts.

---

### A06:2025 — Insecure Design

**Definition**: Flaws in the design itself — missing threat modeling, unsafe business logic, absent security controls by design (distinct from implementation bugs).

```
- No rate limit / anti-automation on password reset -> credential stuffing
- Business logic lets negative quantities create credit
- Trust boundary assumed but never enforced
```

**Mitigation**: Threat modeling early; secure design patterns and reference architectures; abuse-case testing; security requirements in the design phase. See [[Secure-SDLC]].

---

### A07:2025 — Authentication Failures

**Definition**: Weaknesses letting attackers assume identities — credential stuffing, weak/absent MFA, session fixation, exposed session IDs, weak recovery flows.

```
- No brute-force / credential-stuffing protection
- Weak or missing MFA
- Session token not rotated after login; long-lived tokens
```

**Mitigation**: MFA; block weak/breached passwords; rate limiting and lockouts; rotate session IDs on login; short-lived tokens; secure password recovery.

---

### A08:2025 — Software or Data Integrity Failures

**Definition**: Code/data trusted without integrity verification — unsigned updates, insecure deserialization, CI/CD that consumes untrusted artifacts.

```python
# VULNERABLE: insecure deserialization
obj = pickle.loads(request.data)   # attacker payload -> RCE
```

**Mitigation**: Verify signatures/digests on updates and dependencies; avoid native deserialization of untrusted data (use data-only formats + integrity checks); protect the CI/CD pipeline. Overlaps [[Supply-Chain-Security]].

---

### A09:2025 — Security Logging and Alerting Failures

**Definition**: Insufficient logging, detection, or alerting — breaches go unnoticed; incident response is blind. (Renamed from "…Monitoring Failures" to stress actionable alerting.)

```
- Logins, access-control failures, high-value actions not logged
- Logs lack context or are not centralized/alertable
- No alerting on suspicious patterns
```

**Mitigation**: Log security-relevant events with context; centralize to SIEM; alert on anomalies; protect logs from tampering; test detection with red-team exercises.

---

### A10:2025 — Mishandling of Exceptional Conditions (NEW)

**Definition**: Improper handling of errors and edge cases — fail-open logic, swallowed exceptions, inconsistent error paths that bypass security or leak information.

```python
# VULNERABLE: fail-open
try:
    authorized = check_permission(user, resource)
except Exception:
    authorized = True   # error -> access granted
```

**Mitigation**: Fail closed/secure by default; handle all error paths explicitly; don't leak internals in error messages; consistent, tested exception handling.

---

## 2021 → 2025 At a Glance

- **New**: A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions.
- **Consolidated**: SSRF (2021 A10) → into A01 Broken Access Control; Vulnerable & Outdated Components (2021 A06) → into A03 Supply Chain Failures.
- **Moved up**: Security Misconfiguration (#5 → #2).
- **Moved down**: Cryptographic Failures (#2 → #4), Injection (#3 → #5), Insecure Design (#4 → #6).
- **Renamed**: Identification and Authentication Failures → Authentication Failures; Logging and Monitoring Failures → Logging and Alerting Failures.

---

## Quick Reference

| Code | Category | First check |
|---|---|---|
| A01 | Broken Access Control | IDOR, forced browsing, SSRF, privilege escalation |
| A02 | Security Misconfiguration | Defaults, debug mode, cloud exposure |
| A03 | Software Supply Chain Failures | SBOM, dependency CVEs, build/CI integrity |
| A04 | Cryptographic Failures | TLS, algorithm strength, secret storage |
| A05 | Injection | SQLi, XSS, command injection |
| A06 | Insecure Design | Threat model, business-logic abuse |
| A07 | Authentication Failures | MFA, brute force, session handling |
| A08 | Software/Data Integrity | Deserialization, update signing |
| A09 | Logging & Alerting | Coverage, centralization, alerting |
| A10 | Mishandling Exceptional Conditions | Fail-open, error leakage |


## See also

[[OWASP-ASVS]], [[OWASP-Proactive-Controls]], [[OWASP-API-Top-10]], [[CWE-Top-25]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
