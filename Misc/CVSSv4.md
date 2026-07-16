# CVSS v4.0 Reference Guide

CVSSv4.0 introduces refinements to scoring including a new **User Interaction** metric with three levels (None, Passive, Active), reorganized environmental metrics, and updated scoring algorithms. Use this guide for vulnerability assessments published or updated after November 2023.

---

## Base Metrics

### Attack Vector (AV)
Describes how the vulnerability is exploited:

- **Network (N)**: Exploitable remotely over a network, including the internet or same NAT/private network.
- **Adjacent (A)**: Requires access to the same physical or logical network segment (e.g., Bluetooth, Wi-Fi, ARP, L2 broadcast domains, Zigbee, local mesh networks, etc).
- **Local (L)**: Requires local access, such as downloading a file or using a local shell.  
  > *Note: If access is via SSH but the exploit occurs in the local shell, this is still considered Local.*
- **Physical (P)**: Requires physical interaction with the device (e.g., hands on keyboard or hardware).

---

### Attack Complexity (AC)
Describes conditions beyond the attacker's control that must exist for exploitation:

- **Low (L)**: No special conditions required; the attacker can exploit the vulnerability at will.
- **High (H)**: Requires specific conditions or configurations that are not always present.

> *Note: AC does not account for the skill level of the attacker—only the presence of conditions outside their control (e.g., timing windows, race conditions, or specific system states).*

---

### Privileges Required (PR)
Describes the level of privileges an attacker must have before exploiting the vulnerability:

- **None (N)**: No authentication or privileges required.
- **Low (L)**: Requires basic user privileges or authentication.
- **High (H)**: Requires administrative or elevated privileges.

> *Note: This metric assumes the attacker has already obtained the required level of access before attempting the exploit.*

---

### User Interaction (UI)
Describes whether exploitation requires user interaction. **NEW in v4.0: Three levels instead of two.**

- **None (N)**: Exploitation is fully under the attacker's control; no user action required.
- **Passive (P)**: Requires the user to perform some action, but not necessarily awareness of the exploit (e.g., visiting a malicious page, opening an email).
- **Active (A)**: Requires the user to actively engage or be aware (e.g., clicking a malicious link, running an executable, typing credentials).

> *Note: UI refers to the victim's interaction, not the attacker's actions.*

> *Note: In v3.1, "Required" is now split into Passive and Active. Passive is closer to the old Required for web-based attacks; Active requires more deliberate user action.*

---

### Scope (S)
Describes whether the vulnerability affects only the vulnerable component or extends beyond it:

- **Unchanged (U)**: Impact is limited to the vulnerable component and its authority.
- **Changed (C)**: Exploitation affects components beyond the vulnerable one (e.g., SSRF, XSS affecting browser, web vuln leading to OS access).

> *Note: Changed scope often implies a privilege boundary is crossed, such as from a web app to the underlying OS or from one tenant to another in a multi-tenant environment.*

---

### Confidentiality Impact (C)
Measures the impact on the confidentiality of information:

- **None (N)**: No data is disclosed.
- **Low (L)**: Partial disclosure of non-critical data.
- **High (H)**: Full disclosure of non-critical data or any disclosure of critical data.

> *Note: Only consider unauthorized access to data.*  

> *Note: Critical data includes anything that could lead to further compromise or legal/regulatory impact.*

---

### Integrity Impact (I)
Measures the impact on the trustworthiness and accuracy of data:

- **None (N)**: No modification of data.
- **Low (L)**: Partial modification of non-critical data (e.g., config changes).
- **High (H)**: Modification of critical data or widespread data tampering (e.g., password list).

> *Note: These impacts should be assessed based on the worst-case outcome that is reasonably expected from successful exploitation.*  

> *Note: Examples of high impact include tampering with logs, altering audit trails, or modifying authentication mechanisms.*

---

### Availability Impact (A)
Measures the impact on the availability of the system or data:

- **None (N)**: No impact.
- **Low (L)**: Partial denial of service or reduced performance; non-critical resources affected.
- **High (H)**: Full denial of service or impact to critical resources (e.g., CPU, RAM, disk space).

> *Note: These impacts should be assessed based on the worst-case outcome that is reasonably expected from successful exploitation.*

---

## Threat Metrics

Threat metrics in v4.0 reflect the current state of threats and attack patterns, replacing temporal metrics from v3.

### Exploit Maturity (E)
Reflects the current availability and reliability of exploit code or active exploitation:

- **Not Defined (X)**: No value assigned (default, lowest impact on score).
- **Unproven (U)**: No known exploit code or active exploitation.
- **Proof-of-Concept (P)**: Demonstration code exists but may not be reliable or widely available.
- **Functional (F)**: Exploit code exists and works in most situations; active exploitation is limited.
- **High (H)**: Exploit code is widely available, reliable, and actively exploited.

> *Note: This reflects the current state of the threat landscape, not the theoretical exploitability.*

---

## Environmental Metrics

Environmental metrics allow customization of the base score to reflect your organization's specific environment.

### Modified Base Metrics
Override the base metrics if your environment differs from the default assumptions:

- **Modified Attack Vector (MAV)**: Customize AV if your environment has network segmentation or other controls.
- **Modified Attack Complexity (MAC)**: Adjust if special conditions are always/never present in your environment.
- **Modified Privileges Required (MPR)**: Override if privilege levels differ (e.g., service accounts have higher privileges).
- **Modified User Interaction (MUI)**: Customize if users in your environment are more/less likely to interact.
- **Modified Scope (MS)**: Adjust if component isolation is stronger/weaker.
- **Modified Confidentiality/Integrity/Availability (MC/MI/MA)**: Override if impacts differ from base assumptions.

> *Example: A vulnerability is remotely exploitable (AV:N) in general, but in your environment it is only exploitable locally due to network segmentation. Set MAV:L to reflect your actual exposure.*

---

### Confidentiality Requirement (CR), Integrity Requirement (IR), Availability Requirement (AR)
Reflects the importance of each security objective in the operational environment:

- **Low (L)**: Objective has limited importance in your environment.
- **Medium (M)**: Objective has moderate importance (default assumption).
- **High (H)**: Objective is critical to your environment (e.g., healthcare systems, financial services).

> *Note: These values should reflect the actual importance of each security objective (C/I/A) in your specific operational context.*

> *Note: Increasing a requirement multiplier increases the final score, reflecting higher organizational risk if that objective is compromised.*

---

## Scoring & Severity Ratings

### Base Score to Severity Mapping

| Base Score | Severity | Risk Level |
|---|---|---|
| 0.0 | None | No vulnerability |
| 0.1–3.9 | Low | Minor risk; lower priority for remediation |
| 4.0–6.9 | Medium | Moderate risk; should be remediated in normal cycles |
| 7.0–8.9 | High | Serious risk; prioritize for remediation |
| 9.0–10.0 | Critical | Severe risk; immediate remediation required |

---

## Example Scoring

**Scenario: Unauthenticated SSRF in a web API**

- **AV: Network (N)** — remotely exploitable
- **AC: Low (L)** — no special conditions required
- **PR: None (N)** — no authentication needed
- **UI: None (N)** — no user interaction required
- **S: Changed (C)** — can read internal files and reach internal services
- **C: High (H)** — can read /etc/passwd, cloud credentials, internal docs
- **I: High (H)** — can modify internal systems via SSRF chaining
- **A: High (H)** — can DOS internal services

**Vector: `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`**

**Base Score: 10.0 (Critical)**

---

## Key Differences from CVSS v3.1

| Feature | v3.1 | v4.0 | Impact |
|---|---|---|---|
| User Interaction | 2 levels (N, R) | 3 levels (N, P, A) | More granular; passive interactions now distinguishable |
| Scope | Unchanged/Changed | Same | No change |
| Temporal Metrics | Exploit Maturity, Release Date, Report Confidence | Threat Exploitation (TE) | Simplified and renamed |
| Environmental Metrics | CR, IR, AR + Modified Base | Same + Modified Base | More flexible but similar |
| Scoring Algorithm | Base × Temporal × Environmental | Revised calculation | Scores may differ; not directly comparable |

> *Note: CVSSv4.0 scores are not directly comparable to v3.1 scores. Use the published version when comparing vulnerabilities.*

---

*Created: 2026-07-15*
