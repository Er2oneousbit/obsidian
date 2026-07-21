# OWASP Proactive Controls

#OWASP #ProactiveControls #SecureCoding #Defense #AppSec

## What is this?

**OWASP Top 10 Proactive Controls** — The most important techniques to *build* secure applications, written for developers. Focuses on defense (what to do) rather than risks (what to avoid). First published 2016; the current edition is **v4 (2024)**, a substantial reorganization of the 2018 (v3) list. Complements the [[OWASP-Top-10]] (which frames attacks to prevent).

---

## Overview

**OWASP Proactive Controls Basics:**
- **Purpose**: Positive, developer-facing guidance on building secure apps (not just avoiding the Top 10).
- **Scope**: Design, development, and configuration practices for web/API apps.
- **Audience**: Developers, architects, security champions, DevOps.

**vs. OWASP Top 10**:
- **Top 10** = risks/attacks to prevent (what goes wrong).
- **Proactive Controls** = practices to implement (how to build it right).

> [!note]
> **v3 (2018) → v4 (2024) renumbered and reframed the controls.** The v4 list below leads with Access Control (C1) and adds explicit controls for **secure-by-default configuration (C5)**, **browser security features (C8)**, and **stopping SSRF (C10)**. Older references to "C1 Define Security Requirements" etc. are v3-era.

---

## The 10 Proactive Controls (v4, 2024)

| # | Control |
|---|---|
| C1 | Implement Access Control |
| C2 | Use Cryptography to Protect Data |
| C3 | Validate all Input & Handle Exceptions |
| C4 | Address Security from the Start |
| C5 | Secure By Default Configurations |
| C6 | Keep your Components Secure |
| C7 | Secure Digital Identities |
| C8 | Leverage Browser Security Features |
| C9 | Implement Security Logging and Monitoring |
| C10 | Stop Server Side Request Forgery |

---

### C1 — Implement Access Control

Least privilege, deny-by-default, and authorization enforced server-side on every request.

```python
ROLES = {'viewer': ['read'], 'editor': ['read', 'write'], 'admin': ['read', 'write', 'delete']}

def require_permission(perm):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if perm not in ROLES.get(current_user.role, []):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator
```

Addresses the #1 risk, [[OWASP-Top-10]] A01 Broken Access Control (including IDOR and SSRF-as-access-control).

---

### C2 — Use Cryptography to Protect Data

Protect data at rest and in transit with strong, standard algorithms and real key management.

```python
app.config['SESSION_COOKIE_SECURE'] = True     # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True    # no JS access
# At rest: AES-GCM via a vetted library; keys in a KMS/HSM, rotated — never hardcoded
```

Passwords hashed with Argon2/bcrypt (never fast/unsalted hashes). Addresses A04 Cryptographic Failures.

---

### C3 — Validate all Input & Handle Exceptions

Allowlist input validation, context-aware output encoding, parameterized queries, and fail-secure exception handling.

```python
# Parameterized query — injection-proof
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# Context-aware output encoding — prevents XSS
from html import escape
safe = escape(user_comment)
```

Fail **closed** on error; never leak stack traces/internals. Addresses A05 Injection and A10 Mishandling of Exceptional Conditions.

---

### C4 — Address Security from the Start

Security requirements and threat modeling in the design phase, not bolted on later.

```
Requirement: authentication must support MFA
Threat:      account takeover -> data exposure
Mitigation:  TOTP MFA + recovery codes; enforce server-side
```

Feeds directly into a [[Secure-SDLC]]. Addresses A06 Insecure Design.

---

### C5 — Secure By Default Configurations

Ship hardened defaults: debug off in production, minimal features/services, no default credentials, least-privilege file/service permissions, secrets from a vault (not code).

Addresses A02 Security Misconfiguration.

---

### C6 — Keep your Components Secure

Track and update dependencies; use maintained frameworks/libraries instead of home-grown security code.

```bash
# SCA in CI: fail the build on known-vulnerable dependencies
dependency-check --project MyApp --scan .
```

Maintain an SBOM and pin versions. Addresses A03 Software Supply Chain Failures; see [[Supply-Chain-Security]].

---

### C7 — Secure Digital Identities

Strong authentication and session management: MFA, breached-password checks, anti-brute-force, session rotation on login, secure recovery.

Addresses A07 Authentication Failures. Aligns with [[OWASP-ASVS]] chapters V6–V10.

---

### C8 — Leverage Browser Security Features

Use the browser's built-in defenses via response headers.

```python
@app.after_request
def security_headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    return resp
```

CSP (XSS), HSTS (force HTTPS), `X-Content-Type-Options` (MIME sniffing), frame controls (clickjacking), and `SameSite` cookies.

---

### C9 — Implement Security Logging and Monitoring

Log security-relevant events with context, centralize to a SIEM, alert on anomalies, and protect logs from tampering — without logging secrets/PII.

```python
logger.warning(f"Failed login: user={username} ip={request.remote_addr}")
logger.critical(f"Privilege change: user={uid} {old_role}->{new_role}")
```

Addresses A09 Security Logging and Alerting Failures.

---

### C10 — Stop Server Side Request Forgery

New in v4. When the server fetches a user-supplied URL, allowlist destinations, block internal/link-local ranges (169.254.0.0/16, 127.0.0.0/8, RFC 1918), disable unused schemes (`file://`, `gopher://`), and enforce cloud metadata protections (IMDSv2).

In the 2025 Top 10, SSRF is folded into A01 Broken Access Control.

---

## Quick Reference Checklist

- [ ] C1 — Access control: deny-by-default, server-side, every request.
- [ ] C2 — Crypto: strong algorithms, managed keys, hashed passwords.
- [ ] C3 — Input validation, output encoding, parameterized queries, fail-secure.
- [ ] C4 — Security requirements + threat modeling up front.
- [ ] C5 — Hardened, secure-by-default configuration.
- [ ] C6 — Dependencies tracked, scanned, updated (SBOM).
- [ ] C7 — MFA, strong sessions, secure identity.
- [ ] C8 — CSP, HSTS, and other security headers.
- [ ] C9 — Centralized security logging + alerting.
- [ ] C10 — SSRF protections on server-side fetches.


## See also

[[OWASP-Top-10]], [[OWASP-ASVS]], [[OWASP-Secure-Coding-Practices]], [[Secure-SDLC]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
