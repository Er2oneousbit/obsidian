# Threat Intelligence Frameworks

#ThreatIntel #TLP #STIX #TAXII #MITRE

## What is this?

**Threat Intelligence (TI) Frameworks** — Standards for sharing, analyzing, and acting on threat information. Covers TLP (Traffic Light Protocol) for classification/sharing, STIX/TAXII for standardized exchange, ATT&CK for threat actor tactics/techniques. Enables defenders to collaborate, share intel, and improve detection.

---

## Overview

**Threat Intelligence Basics:**
- **Purpose**: Collect, analyze, share threat information to improve defenses.
- **Scope**: Threat actors, attack methods, vulnerabilities, malware, indicators of compromise.
- **Audience**: Security teams, analysts, incident responders, threat hunters.

**Why Threat Intelligence?**
- **Faster response**: Know threat actor TTPs (tactics, techniques, procedures); respond faster.
- **Proactive defense**: Understand threats before they attack you.
- **Collaboration**: Share intel with peers, law enforcement; collective defense.
- **Context**: Know *who* is attacking, *why*, what *techniques* they use.

---

## TLP (Traffic Light Protocol)

### Purpose

**TLP** classifies threat information by how it can be shared.

**Use Case**: Vendor discovers vulnerability; shares with community → some partners need immediate action (vendors); others just need to know.

TLP allows sharing same info at different trust levels.

### The 5 Labels (TLP 2.0)

> [!note]
> **TLP 2.0** (FIRST, 2022) is current. It renamed **TLP:WHITE → TLP:CLEAR** and added **TLP:AMBER+STRICT**. Material using `TLP:WHITE` or only four colors predates 2.0. Order, most to least restrictive: **RED → AMBER+STRICT → AMBER → GREEN → CLEAR**.

#### TLP:RED

**Sharing**: Do not share; authorized recipients only.

**Recipients**: Named individuals/organizations only.

**Example**: 
```
Zero-day vulnerability in Microsoft Office
Shared with: Microsoft, major enterprises working with vendor
NOT shared with: General public, indirect contacts
```

**Use Case**: Sensitive/unpatched vulnerabilities; early warning to most-at-risk orgs.

---

#### TLP:AMBER+STRICT

**Sharing**: Limited disclosure — recipients may share **only within their own organization**.

**Recipients**: The receiving organization's staff only (not its clients/customers).

**Use Case**: Sensitive intel where even client/vendor sharing could cause harm.

---

#### TLP:AMBER

**Sharing**: Limited disclosure — recipients may share within their organization **and with clients/customers who need to know** to protect themselves.

**Recipients**: The receiving org plus its clients, on a need-to-know basis.

**Example**:
```
New malware variant targeting financial sector
Shared with: FS-ISAC members (banks, insurers) and their at-risk clients
NOT shared with: General public, unrelated organizations
```

**Use Case**: Tactical intelligence; affects a specific sector or community.

---

#### TLP:GREEN

**Sharing**: Share with community and peers.

**Recipients**: Anyone in the community (industry, sector, organization).

**Example**:
```
Phishing campaign targeting government agencies
Shared with: CISA, government agencies, contractors
Can also share: General public (no operational impact)
```

**Use Case**: Specific threat; broader awareness helpful but not urgent.

---

#### TLP:CLEAR

**Sharing**: Unrestricted; disclosure is not limited (formerly **TLP:WHITE**).

**Recipients**: Anyone (including general public, media, internet).

**Example**:
```
Historical analysis: "Top 10 vulnerabilities exploited in 2023"
Shared with: General public, media, anyone
```

**Use Case**: General information, statistics, historical analysis.

---

### TLP Usage

**Example Threat Intel Report**:
```
TLP:AMBER

Subject: Emotet Malware Campaign Targeting Energy Sector

Indicators of Compromise (IoCs):
- IP: 192.0.2.1 (C2 server)
- Domain: evil.com
- File hash: abc123def456...

TTPs:
- Initial access: Spearphishing emails
- Execution: PowerShell scripts
- Persistence: Scheduled tasks
- Exfiltration: Over HTTPS to C2

Recommendations:
- Block IoCs at firewall/DNS
- Alert on file hashes in IDS
- Monitor for PowerShell abnormalities
- Train staff on phishing recognition
```

**Sharing**:
- TLP:AMBER: Share with energy sector peers (FS-ISAC, E-ISAC members).
- NOT TLP:CLEAR: Don't publish details (helps attackers; others not yet defended).

---

## STIX (Structured Threat Information eXpression)

### Purpose

**STIX** is a language for expressing threat information in standardized format.

**Why Standardized?**
- **Interoperability**: Share intel between different tools/platforms.
- **Automation**: Parse intel automatically; feed to tools (firewalls, SIEM, endpoint security).
- **Consistency**: Everyone speaks same language.

### STIX Objects

STIX represents threats as objects:

#### Indicator
**Definition**: Observable or pattern that indicates malicious activity.

**Example**:
```json
{
  "type": "indicator",
  "id": "indicator--abc123",
  "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
  "labels": ["malicious-activity"],
  "description": "Known malware hash"
}
```

#### Malware
**Definition**: Malicious software.

**Example**:
```json
{
  "type": "malware",
  "id": "malware--xyz789",
  "name": "Emotet",
  "labels": ["trojan", "backdoor"],
  "description": "Banking trojan; steals credentials; spreads via email"
}
```

#### Attack Pattern
**Definition**: How attackers attack; techniques.

**Example**:
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--abc123",
  "name": "T1566.001 - Spearphishing Attachment",
  "description": "Send email with malicious attachment; trick user to open"
}
```

#### Campaign
**Definition**: Related attacks by same threat actor.

**Example**:
```json
{
  "type": "campaign",
  "id": "campaign--xyz789",
  "name": "Operation Stealth",
  "description": "Multi-year campaign targeting energy sector",
  "created_by_ref": "identity--attacker-group-x"
}
```

#### Identity
**Definition**: Who did it (group, organization, individual).

**Example**:
```json
{
  "type": "identity",
  "id": "identity--xyz789",
  "name": "Lazarus Group",
  "identity_class": "threat-actor",
  "description": "North Korean state-sponsored group"
}
```

#### Relationship
**Definition**: How objects relate (e.g., "Lazarus Group uses Emotet malware").

**Example**:
```json
{
  "type": "relationship",
  "id": "relationship--abc123",
  "relationship_type": "uses",
  "source_ref": "identity--lazarus-group",
  "target_ref": "malware--emotet"
}
```

### STIX Bundle

**Definition**: Collection of STIX objects.

**Example**:
```json
{
  "type": "bundle",
  "id": "bundle--xyz789",
  "objects": [
    { "type": "identity", "id": "identity--lazarus", "name": "Lazarus Group" },
    { "type": "malware", "id": "malware--emotet", "name": "Emotet" },
    { "type": "relationship", "relationship_type": "uses", "source_ref": "identity--lazarus", "target_ref": "malware--emotet" }
  ]
}
```

---

## TAXII (Trusted Automated eXchange of Indicator Information)

### Purpose

**TAXII** is a protocol for sharing STIX objects.

**How it works**:
```
Threat Intel Provider (e.g., CISA)
  ├─ Hosts TAXII Server (receives/serves threat intel)
  │
Subscribers (e.g., your SOC)
  ├─ Subscribe to TAXII feeds (e.g., "Malware hashes")
  ├─ Receive STIX objects in standardized format
  ├─ Ingest into SIEM/firewall/tools automatically
```

### TAXII Channels

**Channels**: Topic-based feeds.

**Examples**:
- `malware-hashes`: Known malware file hashes.
- `c2-infrastructure`: Command & Control server IPs/domains.
- `phishing-urls`: Known phishing websites.
- `exploit-code`: Published exploit code/PoCs.

### TAXII Workflow

```
1. Provider publishes STIX objects to TAXII server
   - STIX bundle containing malware samples, C2 IPs, etc.

2. Subscriber polls TAXII server (or subscribes)
   - Receives updates in STIX format

3. Subscriber ingests STIX into tools
   - Firewall: Block C2 IPs
   - SIEM: Alert on malware hashes
   - Endpoint: Quarantine malware files
   - IDS: Detect based on patterns

4. Automated response
   - No manual translation needed
   - Same format everywhere
```

### Real-World Examples

**CISA AIS (Automated Indicator Sharing)**:
```
CISA shares threat indicators via TAXII
- Organizations subscribe to TAXII feeds
- Receive STIX-formatted indicators (malware hashes, C2 IPs)
- Automatically ingest into security tools
```

**ATT&CK STIX**:
```
MITRE publishes ATT&CK framework as STIX
- Threat actors → Attack patterns/techniques
- Tools can query: "What techniques does Lazarus Group use?"
- Integrate with SIEM (alert on ATT&CK techniques)
```

---

## Threat Intelligence Analysis

### Intelligence Cycle

**Process for analyzing threats**:

1. **Direction**: Define intelligence requirements.
   - "What attacks are targeting our industry?"
   - "Who is likely to attack us?"

2. **Collection**: Gather raw data.
   - Dark web, public sources, ISACs, vendors, law enforcement.
   - Malware samples, exploit code, attacker communications.

3. **Processing**: Organize raw data.
   - Parse malware samples, decode communications.
   - Extract indicators (IPs, domains, hashes).

4. **Analysis**: Make sense of data.
   - Link indicators to known threat actors.
   - Identify attack patterns, tactics, techniques.
   - Assess threat to your organization.

5. **Dissemination**: Share intelligence.
   - STIX/TAXII for automated sharing.
   - Reports for human analysis.
   - TLP classification (who can share with whom).

6. **Feedback**: Refine for next cycle.
   - "Did indicators help detect attacks?"
   - "Were predictions accurate?"
   - Improve sources, analysis, dissemination.

### Threat Levels

**How to assess threat to your org**:

| Level | Definition | Example |
|---|---|---|
| **Critical** | Imminent attack; specific intel; affect your org | Malware targeting your industry found; C2 hosting infrastructure in your cloud |
| **High** | Likely threat; targets your sector/region | Campaign targeting banks; you are a bank |
| **Medium** | Possible threat; general to your industry | New exploit for common software you use |
| **Low** | Theoretical threat; unlikely to affect you | Exploit for OS you don't use |
| **Informational** | General awareness; no immediate threat | Industry trends, historical analysis |

---

## Threat Actor Profiling (MITRE ATT&CK)

**Use ATT&CK to profile threat actors**:

**Lazarus Group Profile**:
```
Name: Lazarus Group
Attribution: North Korea (suspected)
Targets: Financial sector, government, cryptocurrency

TTPs (Techniques & Tactics):
- Initial access: Spearphishing (T1566), Supply chain compromise (T1195)
- Execution: PowerShell (T1086), Command line (T1059)
- Persistence: Scheduled tasks (T1053), Registry (T1547)
- Lateral movement: Pass-the-hash (T1550), SSH (T1021)
- Exfiltration: Over C2 (T1041)

Malware:
- Emotet (banking trojan)
- MATA (remote access trojan)

Infrastructure:
- C2 servers: 192.0.2.1, 192.0.2.2, ...
- Domains: evil.com, evil-c2.net, ...
```

**Use for Defense**:
- Monitor for Lazarus TTPs (if you're targeted, they use these techniques).
- Alert on their malware hashes, C2 IPs.
- Hunt for indicators (are we compromised?).

---

## Threat Intelligence Sources

### Internal
- Security logs (SIEM data; detect internal threats).
- Incident response reports (learn from your own breaches).

### Community
- ISACs (Information Sharing & Analysis Centers; sector-specific).
  - FS-ISAC (financial sector).
  - E-ISAC (energy sector).
  - H-ISAC (healthcare).
- CISA (US government; alerts, advisories).
- MITRE ATT&CK (public; threat actor profiles).

### Commercial
- Threat intel vendors (CrowdStrike, Mandiant, etc.).
- Subscription feeds (malware samples, exploit code, C2 infrastructure).

### Dark Web
- Malware forums, attacker communications.
- Leaked data, credentials.
- (Requires special access/tools.)

---

## Threat Intelligence Checklist

- [ ] Intel requirements defined (what do we need to know?).
- [ ] Sources identified (internal, ISAC, vendors, CISA).
- [ ] Collection automated (TAXII feeds, SIEM ingestion).
- [ ] Analysis process documented (how to assess threat level).
- [ ] STIX/TAXII implemented (standardized exchange).
- [ ] TTPs tracked (map to ATT&CK framework).
- [ ] Dissemination plan (who gets what intel, TLP classification).
- [ ] Feedback loop (assess accuracy, improve for next cycle).
- [ ] Metrics tracked (# of detections, accuracy, time-to-action).

---

## Common Threat Intelligence Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| **No actionable intel** | Intel gathered but not used | Focus on indicators/TTPs relevant to your org; integrate with tools |
| **No TLP classification** | Over-sharing; helps attackers | Classify every intel; follow TLP rules |
| **No STIX/TAXII** | Manual translation; slow adoption | Standardize on STIX/TAXII; automate ingestion |
| **Attribution without confidence** | False flags; misdirects defense | Assign confidence levels; don't over-attribute |
| **No context** | Raw indicators without meaning | Link indicators to threat actors, TTPs, intent |

---

## Resources

- **TLP**: First.org/tlp (official site; colors, guidelines).
- **STIX/TAXII**: OASIS standards; stix.mitre.org (MITRE's implementation).
- **MITRE ATT&CK**: attack.mitre.org (threat actor profiles).
- **CISA AIS**: cisa.gov/ais (Automated Indicator Sharing).
- **ISACs**: Your industry ISAC (sector-specific intel).

---


## See also

[[MITRE-ATT-CK]], [[PTES]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-opus-4-8*
