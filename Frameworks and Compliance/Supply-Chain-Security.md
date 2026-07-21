# Supply Chain Security

#SupplyChain #SLSA #SBOM #DevSecOps #Provenance

## What is this?

**Software Supply Chain Security** — Practices and frameworks protecting software from compromise during development, build, distribution. SLSA (Supply-chain Levels for Software Artifacts) is emerging standard. Covers build integrity, provenance, dependencies, and third-party risk. Critical post-SolarWinds (2020), Log4j (2021), 3CX (2023) supply chain attacks.

---

## Overview

**Supply Chain Security Basics:**
- **Purpose**: Verify software hasn't been tampered with; trace origin; manage third-party risk.
- **Scope**: Dependencies (libraries), build artifacts, distribution channels, vendors.
- **Audience**: DevOps, security teams, developers, procurement, CISOs.

**Why Supply Chain?**
- **Attack vector**: Attacking software vendor affects all customers (mass impact).
- **Trust assumption**: Users trust software vendors; attackers exploit that.
- **Hidden compromise**: Malicious code in dependencies hard to detect.

**Notable Incidents**:
- **SolarWinds (2020)**: Build system compromised; malicious code injected into updates; 18,000+ customers affected.
- **Log4j (2021)**: JNDI injection in open-source library; used by millions; exploited immediately.
- **3CX (2023)**: Installer compromised; distributed malware to customers.

---

## SLSA Framework

### SLSA Levels

SLSA (Supply-chain Levels for Software Artifacts) **v1.0 (2023)** defines a **Build track** with four levels, **L0–L3** (the earlier 0.1 draft used L1–L4; the old "Level 4" was dropped):

#### Level 0: No Requirements
- No protections; baseline (status quo).
- Used as starting point for improvement.

---

#### Level 1: Build Process Requirements

**Goal**: Prove artifact came from claimed source (provenance).

**Requirements**:
- Build platform must record provenance (who built it, when, from what source code).
- Provenance must be available (not secret).
- Version control must be version-controlled (not just scripts).

**Example**:
```
Build log shows:
- Artifact: app-1.0.jar
- Built by: CI/CD system (GitHub Actions)
- From: github.com/mycompany/myapp@abc123 (specific commit)
- Timestamp: 2024-01-15 10:30:00 UTC
- Build command: ./build.sh (version-controlled)
```

---

#### Level 2: Build Process + Source Requirements

**Goal**: Build process is hardened; source verified.

**New Requirements**:
- Build platform hardened (access controlled, logging).
- Build environment isolated (no shared secrets; temporary credentials).
- Build script version-controlled & reviewed.
- Source dependencies pinned (known versions, not latest).

**Example**:
```
Build system:
- GitHub Actions (hardened platform)
- Secrets injected via GitHub Secrets (not in code)
- Build runs in ephemeral container (fresh each build)
- Artifacts signed with key (prove authenticity)
```

---

#### Level 3: Higher Assurance Build Process

**Goal**: Build system highly resistant to compromise.

**New Requirements**:
- Build platform must follow hardened practices (SLSA v1.0 spec).
- Provenance signed & cryptographically verifiable.
- Access control (only authorized personnel can trigger builds).
- Audit logging (all actions logged; immutable).

**Example**:
```
Build platform security:
- Two-person rule (requires approval from 2 people to release)
- Encrypted signing keys (in HSM; not on servers)
- Immutable audit logs (can't delete/modify)
- Automated testing gates (all tests pass before release)
```

---

#### Level 4 — Removed in SLSA v1.0

> [!warning]
> SLSA **v1.0 has no Level 4** — the Build track tops out at **L3**. The "Level 4" ideas below (hermetic and reproducible builds) came from the older SLSA 0.1 draft; they're no longer a required SLSA level, though they remain good practice.

**Legacy goal (SLSA 0.1)**: Build system is maximally secure; threat actors can't compromise.

**New Requirements**:
- Build platform meets all SLSA L3 requirements PLUS:
- Redundancy (multiple independent build systems).
- Hermetic builds (build output deterministic; same input = same output).
- Reproducible builds (anyone can verify build independently).

**Example**:
```
Hermetic build:
- Build output deterministic
- Same code + same build system = identical binary
- Anyone can rebuild from source code
- Proves binary wasn't tampered with (if rebuild matches)
```

---

## Software Bill of Materials (SBOM)

**Purpose**: Document all components in software; track for vulnerabilities.

**Format**: CycloneDX or SPDX (standard formats).

**Example**:
```json
{
  "components": [
    {
      "name": "log4j",
      "version": "2.14.1",
      "type": "library",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    },
    {
      "name": "commons-lang",
      "version": "3.11",
      "type": "library",
      "purl": "pkg:maven/org.apache.commons/commons-lang3@3.11"
    }
  ]
}
```

**Why SBOM?**
- Vulnerability tracking: When Log4j has CVE, quickly find affected versions.
- License compliance: Know all licenses; avoid GPL in proprietary code.
- Supply chain risk: Track third-party components; assess vendor security.

---

## Build Artifact Signing & Verification

### Signing

**Goal**: Prove artifact integrity; prevent tampering in transit.

**Process**:
```
1. Build system creates artifact (app-1.0.jar)
2. Compute hash: SHA256(app-1.0.jar) = abc123...
3. Sign hash: RSA_SIGN(hash, private_key) = signature
4. Distribute: artifact + signature
```

### Verification

**Process**:
```
1. User downloads artifact + signature
2. Compute hash: SHA256(app-1.0.jar) = abc123...
3. Verify signature: RSA_VERIFY(signature, hash, public_key) = OK or FAIL
4. If OK: artifact is authentic, unmodified
5. If FAIL: artifact was tampered with; reject
```

**Tools**:
- Cosign (container image signing; Sigstore project).
- GPG (code signing; traditional).
- Java jarsigner (JAR file signing).

---

## Dependency Management

### Dependency Scanning

**Goal**: Find vulnerable libraries before shipping.

**Tools**:
- `npm audit` (Node.js).
- `pip install safety` (Python).
- Snyk, Dependabot (GitHub), Renovate.

**Process**:
```bash
# Scan dependencies
npm audit

# Output:
# 5 vulnerabilities found
# - High: Express.js 4.16.3 (RCE)
# - Medium: lodash 4.17.19 (Prototype Pollution)

# Fix: Update dependencies
npm update
```

### Dependency Pinning

**Bad**:
```json
{
  "dependencies": {
    "express": "^4.16.0"  // Any version 4.16.0+; can auto-update to vulnerable 4.17.0
  }
}
```

**Good**:
```json
{
  "dependencies": {
    "express": "4.18.2"  // Exact version; reproducible; no auto-updates
  }
}
```

### Lock Files

**Purpose**: Guarantee reproducible builds; same dependencies every time.

**Files**:
- `package-lock.json` (Node.js).
- `Pipfile.lock` (Python).
- `go.sum` (Go).

**Process**:
```bash
# First install: lockfile created (exact versions locked)
npm install

# Later install: lockfile used (exact same versions)
npm ci  # "clean install" (uses lockfile; never updates)
```

---

## Third-Party Risk Management

### Vendor Assessment

**Questions**:
- Does vendor have secure SDLC (code review, testing, etc.)?
- Does vendor sign releases (provenance)?
- Does vendor provide SBOM (dependencies)?
- How quickly does vendor patch vulnerabilities?
- Is vendor's build system secure (SLSA L2+)?

**Assessment Process**:
```
1. Send vendor security questionnaire
2. Review SBOM (dependencies, licenses)
3. Scan for known vulnerabilities
4. Check CVE history (how many? how quickly patched?)
5. Evaluate access control (who can release?)
6. Verify code signing (releases signed?)
```

### Subprocessor Management

**Definition**: Vendor uses other vendors (subprocessors) for code.

**Example**:
```
Your app
  └─ uses Flask (Python web framework)
      └─ uses Werkzeug (request handling)
          └─ uses MarkupSafe (template safety)
```

**Risk**: If MarkupSafe has vulnerability, your app affected.

**Mitigation**:
- SBOM includes transitive dependencies (all levels).
- Dependency scanning includes transitive deps.
- License compliance checked at all levels.

---

## Build Artifact Integrity

### Checksums/Hashing

**Purpose**: Detect tampering in transit.

**Formats**:
```
SHA256: abc123def456...
MD5: xyz789... (don't use; broken)
```

**Example**:
```
Download app-1.0.jar
Compute: SHA256(app-1.0.jar)
Compare to published: abc123def456...
Match? → Authentic
Mismatch? → Tampered with; reject
```

### Code Signing

**Purpose**: Cryptographic proof of authenticity.

**Process**:
```
1. Developer signs release: gpg --sign app-1.0.jar
2. Creates: app-1.0.jar.asc (signature)
3. User verifies: gpg --verify app-1.0.jar.asc
4. GPG checks signature using developer's public key
5. If valid: authentic
```

### Notarization (macOS)

**Purpose**: Apple verifies app is not malware before distribution.

**Process**:
```
1. Developer uploads app to Apple
2. Apple scans for malware
3. Apple signs app (notarization)
4. User downloads notarized app
5. OS validates signature; allows execution
```

---

## Supply Chain Security Checklist

### Build System
- [ ] Build platform hardened (access controlled, logged).
- [ ] Build environment isolated (ephemeral, no shared secrets).
- [ ] Provenance recorded (who, what, when).
- [ ] Artifacts signed (cryptographically).
- [ ] Signing keys protected (HSM or vault).

### Dependencies
- [ ] SBOM generated (all dependencies listed).
- [ ] Dependency scanning (vulnerability detection).
- [ ] Lock files used (reproducible builds).
- [ ] Transitive dependencies tracked.
- [ ] License compliance checked.

### Distribution
- [ ] Checksums published (allow verification).
- [ ] Signatures verified (code signing).
- [ ] Checksums/signatures over HTTPS (no tampering in transit).
- [ ] Multiple distribution channels (not just one).
- [ ] CDN security reviewed (no cache poisoning).

### Third-Party
- [ ] Vendor security assessed.
- [ ] Vendor provides SBOM.
- [ ] Vendor signs releases.
- [ ] Vendor's build system secure (SLSA L2+).
- [ ] Incident notification SLA (vendors notify of breaches).

### Monitoring
- [ ] Vulnerability alerts subscribed (GitHub, npm, etc.).
- [ ] CVEs tracked (patched quickly).
- [ ] Build logs monitored (detect tampering).
- [ ] Audit logs retained (forensics capability).

---

## SLSA vs. CISA Principles

| SLSA | CISA Secure Software Development |
|---|---|
| Focus: Build integrity, provenance | Focus: Development practices, security |
| 4 levels (0–3) | Best practices (no levels) |
| Build platform requirements | SDLC practices (code review, testing, etc.) |

**Complementary**: SLSA (build security) + CISA Principles (development security) = comprehensive supply chain security.

---

## Resources

- **SLSA Framework**: slsa.dev (official site).
- **Sigstore**: cosign (code signing, easy adoption).
- **SBOM**: SPDX, CycloneDX (standards).
- **CISA Secure Software Development**: cisa.gov (best practices).
- **NIST SP 800-53 SR (Supply Chain Risk Management)**: controls for vendor management.

---


## See also

[[Secure-SDLC]], [[Container-Security]], [[Cloud-Security]], [[OWASP-Top-10]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
