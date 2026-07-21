# OWASP MASVS (Mobile Application Security Verification Standard)

#OWASP #MASVS #Mobile #Verification #AppSec

## What is this?

**OWASP MASVS** — Security verification standard specific to mobile applications (iOS, Android, hybrid). Defines security requirements tailored to mobile: platform APIs, on-device storage, device-specific risks, and resilience. Part of the OWASP **Mobile Application Security (MAS)** project. Current release is **v2.1.0 (Jan 2024)** — **8 control categories**; the v2 refactor **removed the old L1/L2/R levels** from MASVS (testing depth is now expressed as profiles in the MASTG) and added **MASVS-PRIVACY**.

---

## Overview

**OWASP MASVS Basics:**
- **Purpose**: Define mobile app security requirements; guide secure mobile development and testing.
- **Scope**: Native iOS/Android apps and cross-platform/hybrid apps.
- **Audience**: Mobile developers, mobile security testers, app security architects.

**vs. ASVS**:
- **ASVS** = web/backend/API focus; general application security. See [[OWASP-ASVS]].
- **MASVS** = mobile-specific; on-device storage, platform APIs, reverse-engineering resilience.

> [!note]
> **v1.x → v2.x is a significant change.** MASVS v2 replaced per-requirement L1/L2/R levels with high-level **security controls** grouped in 8 categories, and moved the graded testing depth into the **MASTG** (Mobile Application Security Testing Guide — renamed from the old **MSTG**) as three **profiles**. So references to `MSTG-x` IDs or "MASVS-L1/L2" requirements are v1.x-era and no longer current.

---

## The 8 MASVS Categories (v2.x)

| Code | Category | Covers |
|---|---|---|
| **MASVS-STORAGE** | Data Storage | Sensitive data kept out of insecure storage/logs/backups; use platform-secure storage (iOS Keychain, Android Keystore) |
| **MASVS-CRYPTO** | Cryptography | Strong algorithms, proper key management, secure randomness; no hardcoded keys |
| **MASVS-AUTH** | Authentication & Authorization | Secure auth, biometric integration, session handling, server-side authorization |
| **MASVS-NETWORK** | Network Communication | TLS everywhere, certificate validation/pinning, no cleartext traffic |
| **MASVS-PLATFORM** | Platform Interaction | Safe use of IPC/intents, permissions (least privilege), WebViews, deep links |
| **MASVS-CODE** | Code Quality | No debug/insecure build settings, dependency hygiene, safe handling of platform inputs |
| **MASVS-RESILIENCE** | Anti-Reverse-Engineering & Tampering | Obfuscation, anti-tampering, root/jailbreak & debugger detection, integrity checks |
| **MASVS-PRIVACY** | Privacy | Data minimization, transparency, and control over user/PII data (new in v2.1) |

---

## Testing Profiles (in the MASTG)

Verification depth is now chosen via **MAS profiles** rather than per-requirement levels:

| Profile | Applies to |
|---|---|
| **MAS-L1** | Apps handling sensitive data that need a basic level of security |
| **MAS-L2** | Apps handling highly sensitive data needing defense-in-depth |
| **MAS-R** | Apps needing resilience against reverse engineering/tampering — **independent** of the security level (maps to MASVS-RESILIENCE) |

> [!note]
> MAS-R is orthogonal: an app can be MAS-L2 **and** MAS-R (e.g. a banking app that both protects data and resists tampering). MASVS-RESILIENCE controls are only relevant when MAS-R is in scope.

---

## Using MASVS for Mobile Pentesting

**Pre-test**:
- Confirm which **profile(s)** apply (MAS-L1, MAS-L2, and/or MAS-R).
- Use the 8 categories as the coverage roadmap; pull concrete test procedures from the **MASTG**.

**During the test**:
- Test on both iOS and Android where relevant (platform behavior differs).
- For MAS-R, test on a rooted/jailbroken device and attempt anti-tampering/pinning bypass (Frida, objection).

**Report**:
- Map findings to the MASVS category (e.g. MASVS-STORAGE) and cite the MASTG test.

**Example finding**:
- **Category**: MASVS-STORAGE (profile MAS-L1).
- **Issue**: Password stored in cleartext in Android `SharedPreferences`.
- **Fix**: Use `EncryptedSharedPreferences` / Android Keystore.

---

## MASVS vs. OWASP Mobile Top 10

| MASVS | OWASP Mobile Top 10 |
|---|---|
| Verification standard (what to build/verify) | Risk list (what commonly goes wrong) |
| 8 control categories, testable via MASTG | 10 high-level risks |
| For secure development + structured assessment | For awareness + framing pentest findings |

**Usage**: MASVS/MASTG for development and structured verification; [[OWASP-Mobile-Top-10]] for awareness and framing findings.

---

## Resources

- **OWASP MAS project / MASVS**: [mas.owasp.org/MASVS](https://mas.owasp.org/MASVS/)
- **MASTG (testing guide)**: [mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/) — detailed per-control test procedures.
- **GitHub**: [github.com/OWASP/masvs](https://github.com/OWASP/masvs)
- **Tools**: MobSF (static/dynamic analysis), Frida & objection (instrumentation, pinning/root-detection bypass).


## See also

[[OWASP-Mobile-Top-10]], [[OWASP-ASVS]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
