# CVSS v4.0

#CVSS #Scoring #VulnerabilityManagement #Severity

## What is this?

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

### Attack Requirements (AT) — NEW in v4.0
Prerequisite deployment/execution conditions the attack depends on (split out of AC):

- **None (N)**: No specific conditions required.
- **Present (P)**: Exploitation depends on specific conditions (e.g., a race window, a particular configuration, or a machine-in-the-middle position).

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

> [!warning]
> **v4.0 removed the Scope metric.** Instead of Unchanged/Changed, v4.0 splits impact into two sets: the **Vulnerable System** (VC/VI/VA) and any **Subsequent System(s)** (SC/SI/SA) affected downstream — a more precise way to express what "scope change" tried to capture.

### Impact — Vulnerable System (VC, VI, VA)
Impact on the component that contains the vulnerability. Rate Confidentiality (**VC**), Integrity (**VI**), and Availability (**VA**) each:

- **High (H)**: Total loss (full disclosure, full modification, or full denial).
- **Low (L)**: Partial/limited loss.
- **None (N)**: No impact.

### Impact — Subsequent System (SC, SI, SA)
Impact on **other** systems beyond the vulnerable component — the replacement for "Scope: Changed." Same High/Low/None scale for Confidentiality (**SC**), Integrity (**SI**), Availability (**SA**). Example: an SSRF whose real damage lands on internal services scores that damage under the Subsequent-System metrics.

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
- **AT: None (N)** — no additional attack requirements
- **PR: None (N)** — no authentication needed
- **UI: None (N)** — no user interaction required
- **VC/VI/VA: High** — full impact on the vulnerable web system
- **SC/SI/SA: High** — reaches and impacts internal (subsequent) systems

**Vector: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`**

**Base Score: 10.0 (Critical)**

---

## Key Differences from CVSS v3.1

| Feature | v3.1 | v4.0 | Impact |
|---|---|---|---|
| User Interaction | 2 levels (N, R) | 3 levels (N, P, A) | More granular; passive interactions now distinguishable |
| Attack Requirements | — | **New: AT (None/Present)** | Prerequisite conditions split out of AC |
| Scope | Unchanged/Changed | **Removed** | Replaced by Vulnerable-System (VC/VI/VA) vs Subsequent-System (SC/SI/SA) impacts |
| Impact metrics | C/I/A (one set) | VC/VI/VA + SC/SI/SA (two sets) | Separates impact on the vulnerable system from downstream systems |
| Temporal → Threat | Exploit Maturity, Report Confidence, Remediation Level | Exploit Maturity only | Simplified |
| Supplemental metrics | — | **New** (Safety, Automatable, Recovery, etc.) | Extra context; no effect on the score |
| Nomenclature | Base/Temporal/Env | CVSS-B / BT / BE / BTE | Names reflect which metric groups were scored |
| Scoring Algorithm | Base × Temporal × Environmental | Revised calculation | Scores not directly comparable to v3.1 |

> *Note: CVSSv4.0 scores are not directly comparable to v3.1 scores. Use the published version when comparing vulnerabilities.*

---


## See also

[[CVSSv3]], [[CWE-Top-25]], [[SANS-Top-25]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
