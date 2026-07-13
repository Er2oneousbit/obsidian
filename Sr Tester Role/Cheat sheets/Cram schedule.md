# 🧭 Senior Pen Tester Study Roadmap

## 🎯 Tier 1 — Absolute Must-Knows (Core 10)

These are the vulns that come up **every time** in interviews and in real-world tests:

* **SQLi** → injection fundamentals, blind/time-based, UNION.
* **XSS** → reflected, stored, DOM, filter bypass.
* **CSRF** → tokens, SameSite, Origin checks.
* **IDOR/BOLA** → object access control in web + APIs.
* **BFLA** → function-level access control.
* **Mass Assignment** → property-level injection in APIs.
* **File Upload** → webshells, polyglots, bypass tricks.
* **SSRF** → internal scans, metadata exfiltration, URL parser bypasses.
* **Authentication/Session** → brute force, password spraying, JWT tampering, MFA bypass.
* **Logic Flaws & Race Conditions** → cart manipulation, double spend, workflow abuse.

👉 Action: Have solid **What / How to Exploit / How to Fix** notes (your Dradis library). Pair each with at least 1 **hands-on lab** (PortSwigger Academy is gold).

---

## 🛡️ Tier 2 — Strong “Senior” Bonus Topics

These show depth and modern awareness — not always tested, but great for “what else do you look for?” questions:

* **XXE & Deserialization** → legacy but still interview favorites.
* **Command Injection** → OS-level impact.
* **Open Redirects** → chainable into OAuth/SSRF/phishing.
* **JWT/OAuth/OIDC** → common in APIs and mobile backends.
* **WebSocket Vulns** → auth, origin, message tampering.
* **Excessive Data Exposure** → APIs dumping too much info.
* **Security Misconfigurations** → debug endpoints, verbose errors, default creds.

👉 Action: Be able to describe these and give a **short exploit scenario** (doesn’t need a full demo).

---

## 🤖 Tier 3 — Awareness Topics (Mention, Don’t Memorize)

These are hot/future-facing. Knowing the vocabulary + risks is enough.

* **AI/LLM Security** (OWASP Top 10 LLM): prompt injection, data leakage, overreliance.
* **NoSQL Injection** → MongoDB `$ne`, `$gt`.
* **GraphQL** → introspection abuse, batching DoS, excessive data exposure.
* **Thick Clients** → local storage, insecure updates, DLL planting.
* **Local OS Findings** → unquoted service paths, world-writable configs, creds in files.
* **MITRE ATT&CK Mapping** → use to show risk context (“this vuln → T1190 exploit public-facing app”).

👉 Action: Have a **one-paragraph mental summary** for each. No deep dive needed.

---

## ⏳ How to Tackle It Without Burning Out

1. **Week 1–2: Core 10**

   * Build/finish Dradis notes (most are already done).
   * Do PortSwigger labs for SQLi, XSS, CSRF, IDOR/BOLA, SSRF.
   * Practice explaining “what it is / how to exploit / how to fix” out loud.

2. **Week 3: Senior Bonus Topics**

   * Add JWT, Deserialization, WebSockets, Misconfig to notes.
   * Do 2–3 labs or CTFs for JWT + WebSockets.
   * Prep 1–2 “real-world stories” (like “I found a misconfig in prod that…”).

3. **Week 4: Awareness Layer**

   * Skim OWASP API Top 10 + LLM Top 10.
   * Write **1-line definitions + 1 example each** (cheat sheet style).
   * Tie them to MITRE tactics (show you think big-picture).

---

## 🎤 Interview Strategy

* **Don’t try to recite everything.** Anchor answers with your Dradis notes.
* If asked something you haven’t memorized:

  * Frame it as **“Here’s how I’d approach testing that”** instead of panicking.
  * Senior = methodology + reasoning, not Jeopardy answers.
* Sprinkle in **impact-driven phrasing**:

  * “That vuln could expose PHI, which ties directly into compliance risk.”
  * “Here’s how I’d chain an open redirect into OAuth hijack.”

---

👉 By following this plan, you’ll walk into the interview with **10 rock-solid core vulns**, **5–7 bonus topics**, and **broad awareness** of the rest. That’s exactly what a **Senior** is expected to show: *depth where it counts, breadth where it matters.*

---


