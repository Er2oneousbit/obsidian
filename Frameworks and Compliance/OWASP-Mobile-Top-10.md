# OWASP Mobile Top 10

#OWASP #Mobile #iOS #Android #MobileSecurity

## What is this?

**OWASP Mobile Top 10** — Top 10 most critical mobile application security risks. Specific to iOS and Android apps (mobile web is covered by the [[OWASP-Top-10]] for web). The current edition is **2024** — the first major refresh since 2016 — reranking risks and adding supply-chain, privacy, and configuration categories. Covers platform-specific vulnerabilities and mobile-unique threats (on-device data storage, IPC, tampering/reverse engineering).

---

## Overview

**OWASP Mobile Top 10 Basics:**
- **Purpose**: Highlight security risks specific to mobile apps (iOS, Android).
- **Scope**: Native and hybrid mobile apps.
- **Audience**: Mobile developers, security testers, mobile security teams.

**Why different from the web Top 10**:
- Different threat model — the device itself may be compromised, rooted, or jailbroken.
- Client binary is in the attacker's hands (reverse engineering, tampering).
- Platform-specific surfaces: permissions, IPC/intents, WebViews, secure storage, deep links.

> [!note]
> Awareness list. For structured verification and test procedures, pair with [[OWASP-MASVS]] and the MASTG. The 2024 list replaced 2016 entries like "Client Code Quality" and standalone "Reverse Engineering / Code Tampering" with **Supply Chain (M2)**, **Privacy (M6)**, **Binary Protections (M7)**, and **Security Misconfiguration (M8)**.

---

## OWASP Mobile Top 10 (2024)

| Code | Risk |
|---|---|
| M1 | Improper Credential Usage |
| M2 | Inadequate Supply Chain Security |
| M3 | Insecure Authentication/Authorization |
| M4 | Insufficient Input/Output Validation |
| M5 | Insecure Communication |
| M6 | Inadequate Privacy Controls |
| M7 | Insufficient Binary Protections |
| M8 | Security Misconfiguration |
| M9 | Insecure Data Storage |
| M10 | Insufficient Cryptography |

---

### M1 — Improper Credential Usage

**Definition**: Hardcoded credentials/API keys in the app, or insecure storage/transmission of credentials.

```
# Reverse-engineered APK reveals:
API_KEY = "AKIA...HARDCODED"
```

**Prevention**: No hardcoded secrets in the binary; fetch short-lived tokens from the backend; store secrets in Keychain/Keystore; rotate leaked keys.

---

### M2 — Inadequate Supply Chain Security

**Definition**: Compromise via third-party SDKs, libraries, or build/distribution pipeline — malicious/vulnerable dependencies shipped inside the app.

**Prevention**: Vet and pin SDKs; SBOM; SCA scanning; verify signatures; secure the CI/CD and signing keys. See [[Supply-Chain-Security]].

---

### M3 — Insecure Authentication/Authorization

**Definition**: Weak or bypassable authentication, or authorization decisions made client-side that the server doesn't re-check.

```
# Client "isAdmin" flag trusted by the backend -> privilege escalation
```

**Prevention**: Authenticate and authorize server-side; never trust client-side role/state; secure biometric integration; MFA for sensitive actions.

---

### M4 — Insufficient Input/Output Validation

**Definition**: Untrusted input (from IPC, deep links, files, server responses, or user) processed without validation — injection, path traversal, memory issues.

**Prevention**: Validate/allowlist all inputs including inter-process and deep-link data; encode output; treat server responses as untrusted.

---

### M5 — Insecure Communication

**Definition**: Traffic sent in cleartext or over weak TLS, or without certificate validation — enabling interception/MITM.

```
# HTTP endpoint, or TLS with no cert pinning -> proxy intercepts tokens
```

**Prevention**: TLS 1.2+ for all traffic; validate certificates; consider certificate pinning; no cleartext (`usesCleartextTraffic=false`).

---

### M6 — Inadequate Privacy Controls (NEW in 2024)

**Definition**: Mishandling of PII/personal data — excessive collection, leakage via logs/backups/IPC, or lack of user consent/control.

**Prevention**: Data minimization; exclude sensitive data from logs and cloud backups; honor consent; comply with [[GDPR]]/platform privacy rules.

---

### M7 — Insufficient Binary Protections (NEW in 2024)

**Definition**: The app binary is easy to reverse-engineer or tamper with — extract secrets/logic, patch controls, repackage.

**Prevention**: Obfuscation; anti-tampering and integrity checks; root/jailbreak and debugger detection (MASVS-RESILIENCE / MAS-R profile). Note: defense-in-depth, not a substitute for server-side controls.

---

### M8 — Security Misconfiguration (NEW in 2024)

**Definition**: Insecure default or platform configuration — exported components, debuggable builds, over-broad permissions, misconfigured WebViews.

```xml
<!-- Android: component unintentionally exported -->
<activity android:name=".Admin" android:exported="true"/>
```

**Prevention**: Least-privilege permissions; `exported=false` unless required; disable debugging in release; harden WebView settings; secure defaults.

---

### M9 — Insecure Data Storage

**Definition**: Sensitive data stored unprotected on-device — plaintext in SharedPreferences/UserDefaults, SQLite, files, or caches.

```
# Android SharedPreferences storing plaintext session token
```

**Prevention**: Use platform-secure storage (Keychain, Keystore, EncryptedSharedPreferences); encrypt at rest; exclude from backups; don't cache sensitive data.

---

### M10 — Insufficient Cryptography

**Definition**: Weak/deprecated algorithms, misuse (ECB mode, static IVs), or poor key management/derivation.

**Prevention**: Strong standard algorithms (AES-GCM, SHA-256+); platform crypto APIs; proper KDFs; keys in Keychain/Keystore; no home-grown crypto.

---

## Using the Mobile Top 10 for Pentesting

**Setup**: Intercepting proxy (Burp) with the app's traffic; a rooted/jailbroken test device; MobSF for static/dynamic triage; Frida/objection for runtime instrumentation and pinning/root-detection bypass.

**Map findings**: Frame each finding by its M-code for reporting, and cite the corresponding [[OWASP-MASVS]] category / MASTG test for the verification detail.

---

## Quick Reference

| Code | Risk | First check |
|---|---|---|
| M1 | Improper Credential Usage | Hardcoded keys in APK/IPA; secret storage |
| M2 | Inadequate Supply Chain Security | Third-party SDKs, build pipeline |
| M3 | Insecure Auth/Authz | Client-trusted authz; weak auth |
| M4 | Insufficient Input/Output Validation | IPC/deep-link/input handling |
| M5 | Insecure Communication | TLS, cert validation/pinning |
| M6 | Inadequate Privacy Controls | PII collection, logs, consent |
| M7 | Insufficient Binary Protections | Reverse engineering, tampering |
| M8 | Security Misconfiguration | Exported components, debug, WebView |
| M9 | Insecure Data Storage | Plaintext on-device storage |
| M10 | Insufficient Cryptography | Weak algorithms, key management |


## See also

[[OWASP-MASVS]], [[OWASP-Top-10]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
