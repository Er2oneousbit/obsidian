# 🛡️ OWASP Top 10 Lists

#OWASP #OWASPTop10 #APITop10 #LLM #AISecurity #WebAppAttacks #AppSec #VulnClassification

Scannable index of the current OWASP Top 10 lists. Full category detail, CWE mappings, and testing guidance live in the framework notes — [[OWASP-Top-10]], [[OWASP-API-Top-10]], [[OWASP-LLM-Top-10]].

---

## 🌐 Web Applications (OWASP Top 10 – 2025)

1. **Broken Access Control** – Missing/weak authz → IDOR, forced browsing, privilege escalation. **SSRF folded in here for 2025.**
2. **Security Misconfiguration** – Default creds, bad CORS, verbose errors, debug mode left on. ▲ up from #5.
3. **Software Supply Chain Failures** – Malicious or vulnerable dependencies, compromised build/CI, poisoned distribution. Broadens 2021's "Vulnerable & Outdated Components."
4. **Cryptographic Failures** – Weak crypto → plaintext data leaks. ▼ down from #2.
5. **Injection** – SQLi, NoSQLi, command injection, XSS. ▼ down from #3.
6. **Insecure Design** – Logic flaws, no rate limits, poor workflows. ▼ down from #4.
7. **Authentication Failures** – Broken login/MFA/session mgmt. Renamed from "Identification & Authentication Failures."
8. **Software or Data Integrity Failures** – Unsafe updates, deserialization, unsigned artifacts.
9. **Security Logging & Alerting Failures** – Gaps in detection and response. Renamed from "…Monitoring Failures."
10. **Mishandling of Exceptional Conditions** – **NEW for 2025** — fail-open error handling, leaked stack traces, unhandled edge cases.

### 2021 → 2025 mapping

Client scoping docs and compliance frameworks still cite 2021 — use this to translate findings.

| 2021 | 2025 |
|---|---|
| A01 Broken Access Control | A01 — unchanged |
| A02 Cryptographic Failures | A04 |
| A03 Injection | A05 |
| A04 Insecure Design | A06 |
| A05 Security Misconfiguration | A02 |
| A06 Vulnerable & Outdated Components | A03 Software Supply Chain Failures (broadened) |
| A07 Identification & Auth Failures | A07 Authentication Failures (renamed) |
| A08 Software & Data Integrity Failures | A08 — unchanged |
| A09 Logging & Monitoring Failures | A09 Logging & Alerting Failures (renamed) |
| A10 Server-Side Request Forgery | **merged into A01** |
| — | A10 Mishandling of Exceptional Conditions (**new**) |

---

## 🔌 APIs (OWASP API Security Top 10 – 2023)

Still the current edition — no 2025 revision.

1. **Broken Object Level Authorization (BOLA)** – Horizontal data access (classic IDOR).
2. **Broken Authentication** – Weak or missing login, MFA, or tokens.
3. **Broken Object Property Level Authorization (BOPLA)** – Unauthorized property manipulation; merges 2019's Excessive Data Exposure + Mass Assignment.
4. **Unrestricted Resource Consumption** – DoS via large/complex requests; also cost-based abuse.
5. **Broken Function Level Authorization (BFLA)** – Privilege escalation via function calls.
6. **Unrestricted Access to Sensitive Business Flows** – Abusing workflows (checkout, money transfer, ticket purchase).
7. **Server-Side Request Forgery (SSRF)** – API as proxy into internal/cloud. *(Still standalone here — unlike Web 2025.)*
8. **Security Misconfiguration** – Exposed debug endpoints, weak CORS.
9. **Improper Inventory Management** – Shadow/deprecated APIs, version sprawl.
10. **Unsafe Consumption of APIs** – Trusting third-party APIs without validation.

---

## 🤖 LLMs / AI Systems (OWASP Top 10 for LLM Applications – 2025)

Published by the OWASP GenAI Security Project. Replaces the original 2023 list.

1. **Prompt Injection** – Malicious instructions override intended logic; direct and indirect.
2. **Sensitive Information Disclosure** – Model leaks secrets, PII, or training data. ▲ big rise from #6.
3. **Supply Chain** – Untrusted models, weights, datasets, adapters.
4. **Data and Model Poisoning** – Backdoors or bias introduced during pre-training, fine-tuning, or embedding. Broadened from "Training Data Poisoning."
5. **Improper Output Handling** – Model output executed downstream (RCE, XSS, SQLi). Renamed from "Insecure Output Handling."
6. **Excessive Agency** – Model granted dangerous real-world powers (shell, transactions, email).
7. **System Prompt Leakage** – **NEW** — system instructions extracted, exposing logic and embedded secrets.
8. **Vector and Embedding Weaknesses** – **NEW** — RAG-specific: embedding inversion, cross-tenant leakage, poisoned retrieval.
9. **Misinformation** – Hallucinated or fabricated output relied on as fact. Replaces "Overreliance."
10. **Unbounded Consumption** – Resource/cost exhaustion. Broadened from "Model Denial of Service."

### Retired from the 2023 list

Old category names still appear across `Sr Tester Role/Topics/` and `Methdocs/AI LLM/` — map them here.

| 2023 | 2025 |
|---|---|
| Insecure Plugin Design | merged into **Excessive Agency** |
| Overreliance | became **Misinformation** |
| Model Theft | folded into **Sensitive Information Disclosure** |
| Training Data Poisoning | broadened → **Data and Model Poisoning** |
| Model Denial of Service | broadened → **Unbounded Consumption** |
| Insecure Output Handling | renamed → **Improper Output Handling** |

---

## 💡 Interview Flex

- **Web Top 10** → traditional appsec (breadth). 2025 shift: supply chain and misconfiguration climbed; SSRF absorbed into access control.
- **API Top 10** → access control + data-centric (depth). Three of ten are authorization failures — BOLA, BOPLA, BFLA.
- **AI/LLM Top 10** → emerging risk (novel attack surface). 2025 shift: RAG and agentic systems now have their own categories.

---

## See also

[[OWASP-Top-10]], [[OWASP-API-Top-10]], [[OWASP-LLM-Top-10]], [[OWASP-Mobile-Top-10]], [[This VS That]], [[Topic Checklists]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-13*
*Updated: 2026-08-17*
*Model: claude-opus-5*
