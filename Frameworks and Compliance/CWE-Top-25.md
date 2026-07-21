# CWE Top 25

#CWE #Weaknesses #VulnClassification #SecureCoding #MITRE

## What is this?

**CWE Top 25 Most Dangerous Software Weaknesses** — Annual list of the 25 most dangerous software weaknesses, ranked by combining prevalence (how many CVEs map to the weakness) with average severity (CVSS). Published by MITRE with CISA/HSSEDI. Unlike the OWASP Top 10 (web-app risk categories), CWE entries are root-cause weakness types that can affect any software. Used by developers, testers, and security teams to prioritize remediation.

---

## Overview

**CWE Top 25 Basics:**
- **Purpose**: Identify most dangerous software weaknesses; guide development/testing priorities.
- **Scope**: All software types (web apps, desktop, embedded, firmware).
- **Data Source**: CVE/NVD records from the trailing ~2 years, scored by prevalence × severity.
- **Cadence**: Published annually (typically late in the year). The **2025 list** below is the current edition, compiled from the weaknesses behind 39,080 CVEs.
- **Audience**: Developers, security researchers, QA, security teams.

**vs. OWASP Top 10**:
- **OWASP Top 10** = web app risk categories (application-level).
- **CWE Top 25** = lower-level technical weaknesses (can affect any software).

> [!note]
> MITRE also publishes companion views alongside the main "Most Dangerous" ranking — e.g. "Weaknesses On the Cusp" (just outside the 25) and KEV-based analyses of weaknesses in actively exploited CVEs. There is no separate "Most Prevalent" Top 25; prevalence is one input to the single ranking.

---

## 2025 CWE Top 25 (Ranked)

| Rank | CWE | Weakness |
|---|---|---|
| 1 | CWE-79 | Cross-Site Scripting (XSS) |
| 2 | CWE-89 | SQL Injection |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) |
| 4 | CWE-862 | Missing Authorization |
| 5 | CWE-787 | Out-of-Bounds Write |
| 6 | CWE-22 | Path Traversal |
| 7 | CWE-416 | Use-After-Free |
| 8 | CWE-125 | Out-of-Bounds Read |
| 9 | CWE-78 | OS Command Injection |
| 10 | CWE-94 | Code Injection (Improper Control of Generation of Code) |
| 11 | CWE-120 | Classic Buffer Overflow (Copy without Checking Size) |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type |
| 13 | CWE-476 | NULL Pointer Dereference |
| 14 | CWE-121 | Stack-Based Buffer Overflow |
| 15 | CWE-502 | Deserialization of Untrusted Data |
| 16 | CWE-122 | Heap-Based Buffer Overflow |
| 17 | CWE-863 | Incorrect Authorization |
| 18 | CWE-20 | Improper Input Validation |
| 19 | CWE-284 | Improper Access Control |
| 20 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| 21 | CWE-306 | Missing Authentication for Critical Function |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) |
| 23 | CWE-77 | Command Injection |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling |

> [!note]
> Ranking shifts year to year. In 2025, access-control weaknesses climbed sharply (CWE-862 Missing Authorization to #4) and several buffer-overflow variants (CWE-120/121/122) re-entered the list; XSS (CWE-79) held #1 for a second year while Out-of-Bounds Write (CWE-787) dropped from #2 to #5.

---

## Web / Injection Weaknesses (in detail)

### CWE-79: Cross-Site Scripting (XSS) — Rank 1

**Definition**: Attacker injects client-side script; the victim's browser executes it in the app's origin.

```html
<!-- VULNERABLE: no output encoding -->
<p><?php echo $_GET['user_comment']; ?></p>

<!-- Attacker sends: <img src=x onerror="alert(document.cookie)"> -->
<!-- onerror fires; attacker script runs in victim's session -->
```

**Mitigation**:
- Context-specific output encoding (HTML, JS, URL, CSS).
- Input validation (allowlist).
- Content Security Policy (CSP).
- `HttpOnly` cookies (block JS access to session cookies).

---

### CWE-89: SQL Injection — Rank 2

**Definition**: Attacker-controlled input is concatenated into a SQL query and changes its logic.

```python
# VULNERABLE: string-built query
username = request.form['username']
query = f"SELECT * FROM users WHERE username='{username}'"
# Attacker sends: ' OR '1'='1  -> returns all users
```

**Mitigation**:
- Parameterized queries / prepared statements.
- Input validation (allowlist).
- Least-privilege DB accounts.
- WAF as defense-in-depth (not a fix).

---

### CWE-352: Cross-Site Request Forgery (CSRF) — Rank 3

**Definition**: Attacker tricks an authenticated user's browser into sending a state-changing request the user didn't intend.

```html
<img src="http://bank.com/transfer?to=attacker&amount=1000">
<!-- Victim is logged in; browser attaches auth cookies; transfer executes -->
```

**Mitigation**:
- Anti-CSRF tokens (random, per-session/request, validated server-side).
- `SameSite` cookies.
- Origin/Referer validation on state-changing requests.

---

### CWE-78: OS Command Injection — Rank 9

**Definition**: User input flows into an OS/shell command, letting the attacker run arbitrary commands.

```python
# VULNERABLE
os.system("ping -c 1 " + request.args['host'])
# Attacker sends: 127.0.0.1; cat /etc/passwd
```

**Mitigation**:
- Avoid the shell; use argument-array APIs (`subprocess.run([...], shell=False)`).
- Allowlist inputs; never pass raw input to a shell.
- Least privilege for the executing process.

---

### CWE-94: Code Injection — Rank 10

**Definition**: Application generates/executes code from data; attacker injects code that runs in the interpreter.

```python
# VULNERABLE
result = eval(request.form['expression'])
# Attacker sends: __import__('os').system('id')
```

**Mitigation**:
- Avoid `eval`/`exec`/dynamic code execution.
- Allowlist known-good values; sandbox untrusted evaluation.

---

### CWE-434: Unrestricted File Upload — Rank 12

**Definition**: App accepts uploads without validating type; attacker uploads a web shell or malware.

```php
// VULNERABLE: no type validation, stored in web root under original name
move_uploaded_file($_FILES['file']['tmp_name'], '/var/www/uploads/'.$_FILES['file']['name']);
// Attacker uploads shell.php -> requests /uploads/shell.php -> RCE
```

**Mitigation**:
- Validate type by magic bytes (not just extension/MIME).
- Store outside web root; disable script execution in the upload dir.
- Rename on save; scan with AV (ClamAV).

---

### CWE-918: Server-Side Request Forgery (SSRF) — Rank 22

**Definition**: Server fetches an attacker-controlled URL, letting the attacker reach internal services (cloud metadata, admin panels, internal APIs).

```
POST /fetch  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Server retrieves cloud credentials on the attacker's behalf
```

**Mitigation**:
- Allowlist destination hosts/schemes; deny internal/link-local ranges (169.254.0.0/16, 127.0.0.0/8, RFC 1918).
- Disable unused URL schemes (`file://`, `gopher://`).
- Require IMDSv2 / disable metadata credential exposure.

---

## Authorization & Access-Control Weaknesses

The 2025 list is heavy on broken access control — CWE-862, CWE-863, CWE-284, CWE-639, and CWE-306 together cover most authorization failures a tester probes for.

| CWE | Weakness | What to test | Fix |
|---|---|---|---|
| CWE-862 | Missing Authorization | Request another user's/object's resource with a valid session — no check present | Enforce authorization server-side on every request; deny-by-default |
| CWE-863 | Incorrect Authorization | Auth check exists but is flawed (wrong role compared, client-trusted) | Centralize checks; test each role/object |
| CWE-284 | Improper Access Control | Broad category — control missing or wrong at a boundary | Least privilege; complete mediation |
| CWE-639 | Authorization Bypass via User-Controlled Key (IDOR) | Increment/replace an ID in the request and access another tenant's data | Indirect references; per-object ownership checks |
| CWE-306 | Missing Authentication for Critical Function | Hit an admin/critical endpoint unauthenticated | Require and verify auth on all sensitive functions |

---

## Memory-Safety Weaknesses (C/C++)

Ranks 5, 7, 8, 11, 13, 14, 16 are memory-corruption classes — largely absent in memory-safe languages (Rust, Java, Go, Python).

| CWE | Weakness | Typical cause |
|---|---|---|
| CWE-787 | Out-of-Bounds Write | Writing past a buffer (overflow, off-by-one) → memory corruption, RCE |
| CWE-125 | Out-of-Bounds Read | Reading past a buffer → info leak / crash |
| CWE-416 | Use-After-Free | Dereferencing freed memory → crash / RCE |
| CWE-476 | NULL Pointer Dereference | Dereferencing NULL → crash / DoS |
| CWE-120 | Classic Buffer Overflow | Copy without size check (`strcpy`) |
| CWE-121 | Stack-Based Buffer Overflow | Overflow of a stack buffer → overwrite return address |
| CWE-122 | Heap-Based Buffer Overflow | Overflow of a heap allocation → corrupt heap metadata |

**Mitigation** (all): bounds checking, safe string APIs (`strncpy`/`strlcpy`), compiler hardening (`-fstack-protector`, ASLR, DEP/NX), AddressSanitizer in testing, and memory-safe languages where feasible.

---

## Other Notable Entries

| CWE | Weakness | Note |
|---|---|---|
| CWE-22 | Path Traversal | `../` in a file parameter reaches files outside the intended dir — canonicalize and confine to an allowlisted base path |
| CWE-502 | Deserialization of Untrusted Data | Deserializing attacker data → object injection / RCE — avoid native deserialization of untrusted input; use data-only formats + integrity checks |
| CWE-20 | Improper Input Validation | Root cause behind many injections — validate type/length/format/range with allowlists |
| CWE-200 | Exposure of Sensitive Information | Verbose errors, debug endpoints, directory listings leaking data |
| CWE-77 | Command Injection | Broader parent of CWE-78 (any command interpreter, not just the OS shell) |
| CWE-770 | Allocation of Resources Without Limits | Unbounded connections/memory/regex backtracking → DoS — enforce quotas, rate limits, timeouts |

---

## CWE Top 25 Quick Reference (2025 top 10)

| Rank | CWE | Weakness | Class |
|---|---|---|---|
| 1 | 79 | Cross-Site Scripting | Injection |
| 2 | 89 | SQL Injection | Injection |
| 3 | 352 | CSRF | Web/session |
| 4 | 862 | Missing Authorization | Access control |
| 5 | 787 | Out-of-Bounds Write | Memory safety |
| 6 | 22 | Path Traversal | Injection/path |
| 7 | 416 | Use-After-Free | Memory safety |
| 8 | 125 | Out-of-Bounds Read | Memory safety |
| 9 | 78 | OS Command Injection | Injection |
| 10 | 94 | Code Injection | Injection |

---

## Using CWE in Development

**Secure Coding Review**:
- Test code against the CWE Top 25; for each, verify the weakness isn't present.
- Example: "SQL injection (CWE-89)? → confirm parameterized queries everywhere."

**Vulnerability Remediation**:
- Map each finding to a CWE; use it as the basis for the fix.
- Example: "XSS finding → CWE-79 → context-aware output encoding + CSP."

**Risk Prioritization**:
- Findings matching the Top 25 are high-priority (common and dangerous); focus first on the top 10.

---

## CWE Lookup Resources

- **cwe.mitre.org** — browse all CWEs (900+) and the current/archived Top 25 lists.
- **cwe.mitre.org/top25/** — latest Top 25 landing page (currently 2025).
- **SANS Top 25** — historically the joint "CWE/SANS Top 25"; the ranking is now maintained by MITRE/CISA as the CWE Top 25. SANS republishes MITRE's list rather than producing a separate one.


## See also

[[SANS-Top-25]], [[OWASP-Top-10]], [[CVSSv4]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
