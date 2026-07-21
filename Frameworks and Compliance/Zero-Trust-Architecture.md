# Zero Trust Architecture

#ZeroTrust #Architecture #NIST800207 #IAM #NetworkSecurity

## What is this?

**Zero Trust Architecture** — Security model that assumes no implicit trust; every access request must be verified. "Never trust, always verify." Applies to users, devices, applications, and network traffic. Emerging standard (post-2010s) as traditional perimeter-based security fails in cloud, remote work, BYOD environments. NIST SP 800-207 published 2020; de-facto standard for modern security.

---

## Overview

**Zero Trust Basics:**
- **Principle**: Assume every access attempt is a threat; verify always.
- **vs. Traditional**: Perimeter-based ("trust inside firewall, verify outside") vs. Zero Trust ("verify everything, everywhere").
- **Scope**: Network access, user authentication, device security, application access, data classification.
- **Audience**: Security architects, network engineers, security teams, CISOs.

**Why Zero Trust Now?**
- **Cloud**: No perimeter (resources everywhere; can't firewall inside).
- **Remote Work**: Users outside office; VPN insufficient.
- **BYOD**: Personal devices accessing corporate data; uncontrolled.
- **Breach Reality**: Attackers assume internal compromise; lateral movement is plan.

---

## Core Zero Trust Principles

### 1. Assume Breach

**Principle**: Assume attacker already has access (either now or will in future). Design for detection, containment, response.

**Implementation**:
- Monitor all traffic (detect intrusions).
- Segment networks (contain breach; prevent lateral movement).
- Incident response plan (respond quickly when detected).
- Regular penetration testing (validate detection capabilities).

---

### 2. Verify Explicitly

**Principle**: Every access request must be verified using all available data points.

**Data Points**:
- User identity (authentication).
- Device health (patched, encrypted, antivirus).
- Network location (trusted vs. untrusted network).
- Application (which app is requesting access).
- Time/context (is this request anomalous?).

**Implementation**:
- Multi-factor authentication (MFA; don't rely on password alone).
- Device posture check (is device compliant?).
- Geo-IP checking (is location expected?).
- Continuous verification (not just at login; throughout session).

---

### 3. Principle of Least Privilege

**Principle**: Users/apps get only minimum access needed for job.

**Implementation**:
- Just-in-Time (JIT) access (access granted temporarily; expires after time/task).
- Just-Enough-Access (JEA) (access limited to specific resources).
- Role-based access control (RBAC).
- Regular access reviews (audit and remove stale access).

---

### 4. Secure Every Layer

**Principle**: Security at every layer; defense-in-depth.

**Layers**:
- Identity (strong authentication).
- Device (hardened, patched, encrypted).
- Network (segmentation, encryption).
- Application (input validation, authorization checks).
- Data (encryption, classification, DLP).

---

### 5. Monitor & Log Everything

**Principle**: Continuous monitoring; detect anomalies, breaches.

**Implementation**:
- Centralized logging (SIEM).
- Real-time alerting (anomaly detection).
- Threat intelligence (known bad indicators).
- Regular review (hunt for threats).

---

## Zero Trust Architecture Components

### 1. Identity and Access Management (IAM)

**Core Component**: Verify user identity; grant access based on identity + device + context.

**Implementation**:
```
User login flow:
1. User provides credentials (username + password).
2. MFA verification (phone, authenticator, biometric).
3. Device check (is device compliant? patched? antivirus active?).
4. Context check (where is user? what time? is access anomalous?).
5. Conditional access policy applied (require MFA if outside VPN, block if high-risk device).
6. Access token issued (if all checks pass).
```

**Technologies**:
- Azure AD, Okta, Ping Identity (identity management).
- Duo, Microsoft Authenticator (MFA).
- Conditional Access policies (context-based access).

---

### 2. Device Trust/Endpoint Security

**Core Component**: Verify device is compliant before allowing access.

**Device Health Checks**:
- OS version (up-to-date?).
- Patches (all security patches applied?).
- Encryption (disk encrypted?).
- Antivirus (running and signatures current?).
- Firewall (enabled?).
- Screen lock (PIN, biometric?).

**Implementation**:
- Mobile Device Management (MDM) or Endpoint Detection & Response (EDR).
- Continuously verify device posture (not just at enrollment).
- Block non-compliant devices (or grant limited access).

**Technologies**:
- Microsoft Intune, Jamf (MDM).
- CrowdStrike, Microsoft Defender for Endpoint (EDR).

---

### 3. Network Access (Zero Trust Network Access)

**Core Component**: Microsegmentation; treat network as untrusted.

**Traditional**: Firewall at perimeter; internal traffic trusted.
```
Internet → Firewall → [Internal Network] (assumed safe)
                       - All internal traffic allowed
```

**Zero Trust**: Every connection verified; segmented networks.
```
Internet → Firewall → [Segment 1] (database)
                      [Segment 2] (web)
                      [Segment 3] (users)
                      
Between segments: explicit firewall rules; no implicit trust
```

**Implementation**:
- Microsegmentation (divide network into zones; firewall between each).
- Network access control (NAC; enforce device compliance before network access).
- Software-defined perimeter (SDP; control network access via software, not physical firewall).
- VPN alternative: Zero Trust Network Access (BeyondCorp model).

**Technologies**:
- Cisco ACI (application-centric infrastructure).
- Palo Alto Prisma (cloud-native network security).
- Cloudflare/Zscaler (Zero Trust Network Access).

---

### 4. Data Protection

**Core Component**: Encrypt, classify, monitor all data.

**Implementation**:
- Data classification (sensitive, confidential, public).
- Encryption at rest (database, storage).
- Encryption in transit (TLS).
- Data Loss Prevention (DLP) (monitor and block exfiltration).
- Secrets management (API keys, credentials in vault; never in code).

**Technologies**:
- Azure Information Protection, Microsoft Purview (classification).
- HashiCorp Vault, AWS Secrets Manager (secrets management).
- Symantec, Forcepoint (DLP).

---

### 5. Application & Workload Security

**Core Component**: Verify apps/services before allowing communication.

**Implementation**:
- API authentication (OAuth, mTLS).
- Service-to-service authorization (verify service identity before allowing API call).
- Workload identity (containers, functions authenticate using identity not credentials).
- Audit logging (log all application access).

**Technologies**:
- Service mesh (Istio, Linkerd) (manage service-to-service communication).
- Workload identity (Kubernetes, Azure Container Instances).

---

### 6. Monitoring & Threat Detection

**Core Component**: Continuous monitoring; detect anomalies.

**Implementation**:
- Centralized logging (collect logs from all sources).
- Security Information & Event Management (SIEM) (analyze logs, detect patterns).
- Threat intelligence (known bad IPs, domains, malware hashes).
- User & Entity Behavior Analytics (UEBA) (detect anomalous user/device behavior).

**Technologies**:
- Splunk, Microsoft Sentinel, Elastic (SIEM).
- Varonis, Exabeam (UEBA).
- Anomali, OTX (threat intelligence).

---

## Zero Trust Implementation Maturity

### Level 1: Initial
- Basic MFA on critical apps.
- Network firewall (traditional).
- No device compliance checks.
- Minimal logging.

---

### Level 2: Developing
- MFA on all apps.
- NAC (device compliance at network entry).
- Some microsegmentation (dev/test/prod).
- Centralized logging (SIEM).

---

### Level 3: Managed
- Conditional access (MFA + device health + location).
- Microsegmentation across network.
- Service-to-service authentication (mTLS, OAuth).
- UEBA (anomaly detection).

---

### Level 4: Optimized
- Full Zero Trust Network Access (no VPN; access based on identity/device/context).
- Full microsegmentation (granular policies).
- Continuous verification (not just at login).
- AI/ML-driven threat detection.

---

## Zero Trust Deployment Strategy

### Phase 1: Foundation (Months 1–3)
- [ ] Implement MFA (all users).
- [ ] Deploy MDM/EDM (device compliance).
- [ ] Centralize logging (SIEM).
- [ ] Risk assessment (current state).

### Phase 2: Network (Months 4–9)
- [ ] Network Access Control (NAC).
- [ ] Microsegmentation (initial; dev/prod separation).
- [ ] VPN → Zero Trust Network Access (pilot).
- [ ] Monitoring & alerting.

### Phase 3: Identity & Access (Months 10–15)
- [ ] Conditional access policies.
- [ ] Privileged Access Management (PAM).
- [ ] Service-to-service authentication.
- [ ] UEBA deployment.

### Phase 4: Optimization (Months 16+)
- [ ] Full microsegmentation.
- [ ] Continuous verification.
- [ ] AI/ML threat detection.
- [ ] Incident response integration.

---

## Zero Trust for Penetration Testers

**How Zero Trust affects pentesting:**

1. **Harder to pivot**: Microsegmentation blocks lateral movement.
2. **Continuous verification**: Attacker must re-authenticate frequently (not just at login).
3. **Detection focus**: Assume breach mentality means detection/response capabilities are strong.
4. **Red team exercises**: Organizations test detection/response regularly.

**Pentest approach**:
- Test each layer independently (identity, device, network, application, data).
- Test if attacker on compliant device can access restricted data.
- Test if attacker on non-compliant device is blocked/limited.
- Test lateral movement (can attacker move between segments?).
- Test detection (does SIEM alert on suspicious activity?).

**Finding examples**:
- "Device compliance bypass: Non-patched device gains network access (NAC misconfigured)."
- "Lateral movement: Attacker moves between network segments (microsegmentation not enforced)."
- "Stale access: User who departed still has access to sensitive apps (no access review)."

---

## Zero Trust vs. Traditional Security

| Aspect | Traditional | Zero Trust |
|---|---|---|
| Assumption | Trust inside perimeter | Never trust; always verify |
| Perimeter | Firewall-based | No perimeter; software-based |
| Authentication | Once at login | Continuous; every request verified |
| Network | Flat; internal traffic trusted | Segmented; all traffic verified |
| Access | Role-based static | Context-based dynamic (time, location, device health) |
| Monitoring | Alerts on perimeter traffic | Continuous monitoring everywhere |
| Response | Reactive (respond after breach) | Proactive (assume breach; detect early) |

---

## NIST SP 800-207 Zero Trust Architecture

Official NIST Zero Trust guideline (2020). Its **seven tenets** are (paraphrased):

1. **All data sources and computing services are resources.**
2. **All communication is secured** regardless of network location — being "on the internal network" grants no implicit trust.
3. **Access is granted per-session** (least privilege, re-evaluated each time).
4. **Access is determined by dynamic policy** — identity, device state, behavioral and environmental attributes.
5. **The enterprise monitors and measures the integrity and security posture** of all owned and associated assets.
6. **All resource authentication and authorization are dynamic and strictly enforced** before access is allowed.
7. **The enterprise collects as much information as possible** about asset/network/communication state and uses it to improve security.

> [!note]
> The "Verify explicitly / Assume breach / Least privilege" list higher in this note is the common **Microsoft/industry** framing of Zero Trust — complementary to, but not the same as, the 800-207 tenets above.

---

## Common Zero Trust Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| **MFA fatigue** | Users bypass or disable MFA | Intelligent MFA (context-based; only when necessary) |
| **Over-segmentation** | Business impact; systems can't communicate | Balance security with functionality; segment by risk/sensitivity |
| **Logging explosion** | Too much data; can't analyze | Centralize, filter, focus on security-relevant events |
| **Legacy systems exempt** | Weak link; still exploitable | Strategies for legacy (air-gap, WAF, reverse proxy) |
| **Assume breach without detection** | Useless (assumption without verification) | Invest in monitoring/detection capabilities |

---

## Resources

- **NIST SP 800-207**: Zero Trust Architecture (official guideline).
- **BeyondCorp**: Google's Zero Trust model (published papers).
- **Gartner**: Zero Trust maturity model, implementation roadmap.
- **Zero Trust Community**: Resources, case studies, tools.

---


## See also

[[NIST-SP-800-53]], [[NIST-CSF]], [[Cloud-Security]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
