# Critical Infrastructure & ICS Security

#ICS #OT #SCADA #CriticalInfrastructure #NIST80082

## What is this?

**Industrial Control Systems (ICS) & Critical Infrastructure Security** — Security practices for operational technology (OT) environments: power grids, water systems, manufacturing, healthcare, transportation. NIST SP 800-82 is authoritative US standard. Unique threat model vs. IT: availability > confidentiality (downtime = physical danger, not just data loss).

---

## Overview

**ICS/Critical Infrastructure Basics:**
- **Purpose**: Protect systems controlling physical processes (power generation, water treatment, manufacturing).
- **Scope**: SCADA, PLC, DCS, HMI, RTU (industrial control systems).
- **Audience**: OT security engineers, critical infrastructure operators, defensive security teams.

**Why Different from IT Security**:
- **Availability first**: Downtime causes real-world harm (power outages, water contamination, factory shutdowns).
- **Legacy systems**: ICS systems often 20+ years old; patching difficult/impossible.
- **Safety-critical**: Failure can cause injury/death; can't just "reboot".
- **Determinism required**: Timing matters (must complete task within strict timeframe).
- **IT/OT convergence**: Traditional air-gapped ICS now connected to IT networks; new risks.

---

## ICS Architecture

### Traditional (Air-Gapped)

```
[Corporate IT Network] --- [Air Gap] --- [OT Network]
                                         ├─ SCADA master
                                         ├─ PLC/RTU
                                         └─ Field devices
                                         
- Operator console at air gap (manual data transfer)
- OT isolated from internet
- Risk: Insider threat, USB-based malware
```

### Modern (IT/OT Converged)

```
[Internet] → [Corporate Network] → [DMZ] → [OT Network]
                                           ├─ SCADA
                                           ├─ PLC
                                           └─ Field devices

- Remote monitoring/management (internet-accessible)
- Real-time data to corporate systems
- Risk: Internet-connected; vulnerable to remote attacks
```

---

## NIST SP 800-82 Framework

> [!note]
> **NIST SP 800-82 Rev 3 (2023)** was retitled *Guide to Operational Technology (OT) Security*. The other canonical OT references are **ISA/IEC 62443** (the primary ICS/OT security standard series, with security levels SL 1–4) and the **Purdue Model** (the Level 0–5 reference architecture used to segment OT networks) — know these alongside 800-82.

### 1. Governance & Risk Management

**Goal**: ICS security policy, risk assessment, compliance.

**Requirements**:
- ICS security policy (separate from IT policy; reflects OT priorities).
- Risk assessment (identify threats, vulnerabilities, impact; prioritize by availability risk).
- Roles & responsibilities (clear ownership; OT vs. IT).
- Budget & resources (security requires investment; justify by downtime cost).

**Unique to ICS**:
- Availability-focused risk rating (downtime = primary risk, not data breach).
- Safety impact assessment (can failure cause injury/death?).
- Business continuity (downtime = revenue loss; often greater than IT systems).

---

### 2. Asset Management

**Goal**: Know what systems exist; maintain inventory.

**Requirements**:
- Complete inventory (SCADA systems, PLCs, field devices, network components).
- Asset criticality (which systems are most important?).
- Software bill of materials (SBOM) for ICS devices.
- Legacy system tracking (many 20+ years old; no patches available).

**Challenges**:
- Proprietary systems (OT vendors don't publish specs).
- Legacy systems (can't upgrade; support ended).
- Supply chain (devices manufactured decades ago; no security features).

---

### 3. Access Control

**Goal**: Limit who can access/modify ICS.

**Requirements**:
- Segregation (separate ICS network from IT).
- Physical access controls (lock server rooms; limit who can touch hardware).
- Administrative access restricted (only trained personnel; MFA for remote access).
- Least privilege (users get only necessary access).

**Unique to ICS**:
- Field technician access (may be non-IT personnel; need simpler auth).
- Maintenance windows (access may be granted temporarily for specific tasks).
- Emergency access (bypass controls if safety-critical failure).

---

### 4. System Development

**Goal**: Secure procurement; secure configuration.

**Requirements**:
- Security in procurement (require security features; evaluate vendor security).
- Baseline configuration (document secure baseline; prevent unauthorized changes).
- Change management (test changes in staging before prod; minimal downtime).
- Supply chain risk (components from trusted vendors; verify authenticity).

**Unique to ICS**:
- Functional testing required (verify system still operates safely after security changes).
- Minimal downtime (changes must be quick; operations can't stop).
- Deterministic behavior (timing must be preserved; security can't slow down processes).

---

### 5. Protection & Monitoring

**Goal**: Detect anomalies; prevent unauthorized access.

**Requirements**:
- Network monitoring (NIDS/NIPS on OT network).
- Data loss prevention (block data exfiltration).
- Anomaly detection (unusual traffic/commands; ICS behavior should be predictable).
- Endpoint protection (antivirus on servers; but not on PLCs/RTUs).

**Unique to ICS**:
- Can't install AV on PLCs (would impact performance; may crash).
- Signature-based detection ineffective (OT malware rare; new signatures needed).
- Baseline learning (learn "normal" traffic; flag deviations).
- Protocol analysis (Modbus, OPC, DNP3 are proprietary; tools must understand them).

---

### 6. Recovery & Disaster Response

**Goal**: Restore service after compromise/failure.

**Requirements**:
- Backup & restore procedures (tested regularly).
- Incident response plan (OT-specific; includes both cyber and physical).
- Business continuity (how to operate if systems down?).
- Communication plan (who to notify if breach?).

**Unique to ICS**:
- Manual operations capability (if systems down, can operators run manually?).
- Safety procedures (steps to safely shut down if attacked).
- Third-party coordination (power grid breach affects everyone; need government notification).

---

## Common ICS Vulnerabilities

### 1. Unpatched Legacy Systems

**Risk**: No security patches available for 20+ year old systems.

**Example**:
```
SCADA system running Windows 2000
No patches since 2010
Multiple RCE vulnerabilities (EternalBlue, etc.)
Attacker gains access; compromises entire system
```

**Mitigation**:
- Air-gap (isolate completely from internet).
- Compensating controls (firewall, IDS, access controls).
- Regular risk assessment (accept risk or upgrade).
- Vendor coordination (some vendors provide security advisories for legacy systems).

---

### 2. Default Credentials

**Risk**: Devices shipped with default username/password.

**Example**:
```
PLC with default: admin/admin
Attacker on network: telnet to PLC, logs in, modifies control logic
Factory produces wrong output, or crashes
```

**Mitigation**:
- Change all default credentials during installation.
- Document new credentials securely (password manager).
- Regular audits (scan for default creds still in use).

---

### 3. Lack of Authentication

**Risk**: Some OT devices have no authentication (Modbus, older Ethernet).

**Example**:
```
Modbus TCP (common protocol for PLCs)
No built-in authentication
Attacker sends Modbus commands: set pump speed to 150%
Pump overheats, fails, or explodes
```

**Mitigation**:
- Network segmentation (restrict who can reach OT network).
- Firewalls (whitelist allowed Modbus commands).
- Protocol analysis (detect anomalous commands).
- Upgrade to authenticated protocols (Modbus TCP with TLS).

---

### 4. Insecure Remote Access

**Risk**: Remote support/monitoring access to OT network.

**Example**:
```
VPN to OT network for remote engineer support
VPN credentials compromised (phishing)
Attacker logs in, gains access to SCADA
```

**Mitigation**:
- MFA on VPN (not just password).
- Bastion host (jump box; limit what VPN can directly access).
- Session recording (log all remote access).
- Least privilege (remote user gets only necessary access).
- Time-based access (access expires after task).

---

### 5. Malware (Stuxnet-style)

**Risk**: Sophisticated malware targeting specific control logic.

**Example**: Stuxnet (2010)
```
Attacked uranium enrichment facility
Modified PLC control logic
Centrifuges spun too fast, destroyed themselves
But reported normal status to monitoring system
Operators didn't realize damage for months
```

**Mitigation**:
- Network segmentation (prevent malware spread).
- Anomaly detection (detect unusual PLC behavior).
- Firmware verification (detect modified control logic).
- Air-gap critical systems.
- Behavior monitoring (compare actual equipment behavior to expected).

---

## ICS Testing Approach

### Reconnaissance

```bash
# Port scanning (identify OT devices)
nmap -sV <network>
# Look for: Modbus (502), DNP3 (20000), OPC (135, 445)

# Protocol fingerprinting
Wireshark (capture Modbus, OPC traffic; analyze)

# Shodan/Censys
shodan search "Modbus"
# Finds internet-exposed ICS devices (shouldn't exist!)
```

### Vulnerability Assessment

```bash
# ICS-specific scanners
ICSDefense, Nessus (ICS plugin)
# Test for: default creds, unpatched systems, protocol anomalies

# Manual testing
- Try default credentials on devices
- Test if Modbus commands are accepted (no auth)
- Check for VPN/remote access; test security
```

### Exploitation (In Controlled Environment)

```bash
# Modbus command injection (if segmentation lacking)
Modbus exploit tools (Metasploit Modbus module)

# PLC reprogramming (if unauthorized write access allowed)
Attacker uploads modified control logic
Physical impact (pump spins wrong speed, valve opens incorrectly)

# Only in lab/isolated test bed; NEVER in production!
```

### Reporting

- **Critical findings**: Default creds, unpatched systems, exposed remote access.
- **High findings**: Lack of authentication, insufficient segmentation.
- **Medium findings**: Weak authentication, missing monitoring.
- **Focus on availability**: How can attack cause downtime or physical harm?

---

## ICS Security Checklist

### Governance
- [ ] ICS security policy (distinct from IT policy).
- [ ] Risk assessment (availability-focused).
- [ ] Compliance requirements identified (NERC CIP, NRC, etc.).
- [ ] Budget allocated for OT security.

### Asset Management
- [ ] Complete inventory (all SCADA, PLC, field devices).
- [ ] Asset criticality defined.
- [ ] Legacy system tracking (identify 20+ year old systems).
- [ ] Software bill of materials for devices.

### Access Control
- [ ] OT network segmented from IT.
- [ ] Physical access controls (locked rooms).
- [ ] Admin access restricted (MFA, least privilege).
- [ ] Default credentials changed.

### Protection
- [ ] Network monitoring (IDS, anomaly detection).
- [ ] Data loss prevention (no exfiltration).
- [ ] Endpoint protection (where feasible).
- [ ] Vulnerability scanning (regular, non-disruptive).

### Monitoring
- [ ] Baseline behavior established (normal traffic/commands).
- [ ] Anomaly detection active (alerts on deviations).
- [ ] Logging enabled (centralized, retained).
- [ ] Regular log review.

### Recovery
- [ ] Backup & restore procedures (tested annually).
- [ ] Incident response plan (OT-specific).
- [ ] Business continuity plan (manual operation capability).
- [ ] Communication procedures (internal, external, government).

---

## NIST SP 800-82 vs. IT Security Standards

| Aspect | NIST SP 800-82 (ICS) | NIST SP 800-53 (IT) |
|---|---|---|
| Priority | Availability first | Confidentiality/Integrity first |
| Legacy systems | Addresses; compensating controls | Assumes modern systems |
| Patching | May not be feasible; accept risk | Mandatory, frequent |
| Downtime | Unacceptable; must be minimal | Acceptable for maintenance |
| Segmentation | Air-gap critical systems | Network segmentation sufficient |
| Authentication | Challenging (legacy); may use physical | MFA standard |

---

## Critical Infrastructure Sectors

| Sector | Examples | Priority |
|---|---|---|
| **Power & Energy** | Power grids, generation, transmission | Very High |
| **Water & Wastewater** | Treatment facilities, distribution | Very High |
| **Chemicals & Hazmat** | Chemical plants, refineries | Very High |
| **Transportation** | Traffic signals, rail, aviation | Very High |
| **Healthcare** | Hospitals, MRI, dialysis | Very High |
| **Communications** | Telecom networks, broadcasting | High |
| **Defense** | Military systems, weapons | Very High |
| **Financial Services** | ATMs, trading systems | High |
| **Government Facilities** | Dams, courthouses, data centers | High |

---

## ICS Attack Scenarios

### Scenario 1: Ransomware on OT Network

```
1. Attacker gains access to OT network (VPN compromise, phishing).
2. Deploys ransomware (encrypts all files).
3. SCADA system shuts down (can't access control files).
4. Manufacturing stops; revenue loss $1M/day.
5. Ransom demand: $500K.
```

**Prevention**:
- Air-gap critical systems.
- Segmentation (ransomware can't reach SCADA from IT).
- Backup (separate, isolated; ransom worthless).

---

### Scenario 2: Malware Modifying Control Logic

```
1. Attacker gains access to PLC via Modbus.
2. Uploads modified control logic.
3. PLC controls pump; modified logic sets speed 150%.
4. Pump overheats, explodes.
5. Facility damaged; worker injured.
```

**Prevention**:
- Modbus authentication (requires credentials to modify).
- Anomaly detection (detect unusual speed commands).
- Air-gap (prevent Modbus access from untrusted network).
- Behavioral monitoring (detect if actual pump speed differs from commands).

---

## Resources

- **NIST SP 800-82**: Critical Infrastructure Protection (official guidance).
- **NERC CIP**: North American Electric Reliability Corp standards (power grid).
- **ICS-CERT**: Cybersecurity & Infrastructure Security Agency (alerts, advisories).
- **S4 Conference**: ICS security conference (research, tools, case studies).
- **Shodan, Censys**: Search engines for internet-exposed ICS (identify risk).

---


## See also

[[NIST-CSF]], [[NIST-SP-800-53]], [[Zero-Trust-Architecture]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
