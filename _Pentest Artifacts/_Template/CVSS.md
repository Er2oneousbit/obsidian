
# CVSS Reference Guide

## Attack Vector (AV)
Describes how the vulnerability is exploited:

- **Physical (P)**: Requires physical interaction with the device (e.g., hands on keyboard or hardware).
- **Local (L)**: Requires local access, such as downloading a file or using a local shell.  
  > *Note: If access is via SSH but the exploit occurs in the local shell, this is still considered Local.*
- **Adjacent (A)**: Requires access to the same physical or logical network segment (e.g., Bluetooth, Wi-Fi, ARP, L2 broadcast domains, Zigbee, local mesh networks, etc).
- **Network (N)**: Exploitable remotely over a network, including the internet or same NAT/private network.

---

## Attack Complexity (AC)
Describes conditions beyond the attacker's control that must exist for exploitation:

- **Low (L)**: No special conditions required; the attacker can exploit the vulnerability at will.
- **High (H)**: Requires specific conditions or configurations that are not always present.

> *Note: AC does not account for the skill level of the attacker—only the presence of conditions outside their control (e.g., timing windows, race conditions, or specific system states).*

---

## Privileges Required (PR)
Describes the level of privileges an attacker must have before exploiting the vulnerability:

- **None (N)**: No authentication or privileges required.
- **Low (L)**: Requires basic user privileges or authentication.
- **High (H)**: Requires administrative or elevated privileges.

> *Note: This metric assumes the attacker has already obtained the required level of access before attempting the exploit.*

---

## User Interaction (UI)
Describes whether exploitation requires user interaction:

- **None (N)**: Exploitation is fully under the attacker’s control.
- **Required (R)**: Requires user interaction (e.g., clicking a link, opening a file).

> *Note: UI refers to the victim's interaction, not the attacker's actions.*

---

## Scope (S)
Describes whether the vulnerability affects only the vulnerable component or extends beyond it:

- **Unchanged (U)**: Impact is limited to the vulnerable component and its authority.
- **Changed (C)**: Exploitation affects components beyond the vulnerable one (e.g., SSRF, XSS affecting browser, web vuln leading to OS access).

> *Note: Changed scope often implies a privilege boundary is crossed, such as from a web app to the underlying OS or from one tenant to another in a multi-tenant environment.*

---

## Confidentiality Impact (C)
Measures the impact on the confidentiality of information:

- **None (N)**: No data is disclosed.
- **Low (L)**: Partial disclosure of non-critical data.
- **High (H)**: Full disclosure of non-critical data or any disclosure of critical data.

> *Note: Only consider unauthorized access to data.*  

> *Note: Critical data includes anything that could lead to further compromise or legal/regulatory impact.*

---

## Integrity Impact (I)
Measures the impact on the trustworthiness and accuracy of data:

- **None (N)**: No modification of data.
- **Low (L)**: Partial modification of non-critical data (e.g., config changes).
- **High (H)**: Modification of critical data or widespread data tampering (e.g., password list).

> *Note: These impacts should be assessed based on the worst-case outcome that is reasonably expected from successful exploitation.*  

> *Note: Examples of high impact include tampering with logs, altering audit trails, or modifying authentication mechanisms.*

---

## Availability Impact (A)
Measures the impact on the availability of the system or data:

- **None (N)**: No impact.
- **Low (L)**: Partial denial of service or reduced performance; non-critical resources affected.
- **High (H)**: Full denial of service or impact to critical resources (e.g., CPU, RAM, disk space).

> *Note: These impacts should be assessed based on the worst-case outcome that is reasonably expected from successful exploitation.*

---

## Temporal Metrics

### Exploit Code Maturity (E)
Reflects the current availability and reliability of exploit code:

- **Not Defined (X)**: No value assigned.
- **High (H)**: Exploit code is widely available and reliable.
- **Functional (F)**: Exploit code exists and works in most situations.
- **Proof-of-Concept (P)**: Demonstration code exists but may not be reliable.
- **Unproven (U)**: No known exploit code.

> *Note: This reflects the current availability and reliability of exploit code, not the theoretical exploitability.*

---

## Environmental Metrics

### Confidentiality Requirement (CR), Integrity Requirement (IR), Availability Requirement (AR)
Reflects the importance of each security objective in the operational environment:

- **Low (L)**: Objective has limited importance.
- **Medium (M)**: Objective has moderate importance.
- **High (H)**: Objective is critical to the environment.
- **Not Defined (X)**: No value assigned.

> *Note: These values should reflect the importance of each security objective (C/I/A) in the specific operational environment, such as a healthcare or financial system.*

> *Note: The modified base metrics (AV, AC, PR, UI, S, C, I, A) in the Environmental section allow you to override the original base values to reflect the specific conditions of your environment.*
> *For example, if a vulnerability is remotely exploitable in general (AV:N), but in your environment it is only exploitable locally due to network segmentation, you can set the modified AV to Local (AV:L).* 
> *This customization helps produce a more accurate risk score tailored to your organization's actual exposure and impact.*

