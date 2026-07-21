# PTES (Penetration Testing Execution Standard)

#PenTest #Methodology #PTES #RedTeam #Engagement

## What is this?

**PTES (Penetration Testing Execution Standard)** — Open-source framework standardizing penetration testing methodology. Defines a 7-phase workflow for conducting penetration tests: from pre-engagement to reporting. Used by pentesters, security teams, and clients to align on scope, expectations, and deliverables.

---

## Overview

**PTES Basics:**
- **Purpose**: Standardize pentest methodology; provide repeatable framework.
- **Audience**: Pentesters (consultants, red teamers), internal security teams, clients.
- **Scope**: Full penetration tests (external recon → exploitation → reporting); applicable to web, network, physical, social engineering.
- **Maturity**: Published ~2012 and not significantly updated since — dated in specifics but still a widely-referenced engagement framework.

**Relation to Other Standards:**
- **NIST SP 800-115** = U.S. government technical testing standard (more detailed, very technical).
- **OWASP Testing Guide** = web application testing checklist.
- **PTES** = overall engagement framework (scope → testing → reporting).

---

## The 7 Phases of PTES

> [!note]
> PTES's official seven phases are: **Pre-engagement Interactions → Intelligence Gathering → Threat Modeling → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting.** This note follows that flow but merges active scanning/enumeration into the Intelligence Gathering → Vulnerability Analysis transition (labeled Phase 3 below). **Threat modeling** — profiling the target's assets, business processes, and likely attacker goals — is the true PTES Phase 3 and runs alongside recon/scanning.

### Phase 1: Pre-Engagement & Scoping

**Goal**: Define scope, objectives, rules of engagement (ROE), timeline.

**Activities:**
1. **Establish engagement scope**:
   - Which systems/networks in scope?
   - Which systems explicitly out of scope (production DB, payment processing, emergency systems)?
   - Geographical limitations (test US only, or include international)?
   - Time windows (business hours only, or 24/7)?

2. **Define objectives**:
   - What vulnerabilities are you looking for? (general security posture, specific risk, compliance validation?)
   - What's the business goal? (identify weaknesses, validate controls, incident response testing?)
   - Who are stakeholders? (CISO, CEO, compliance team?)

3. **Negotiate rules of engagement (ROE)**:
   - **Authorized testing**: Get written authorization from asset owner/legal (protect from law enforcement).
   - **Level of access granted**: Do you start with no access (black box) or with credentials (white box)?
   - **Escalation procedures**: If you find critical issue, who do you notify and how quickly?
   - **Incident response testing**: Can you actually trigger an incident, or just simulate?
   - **Social engineering**: Is phishing/pretexting allowed? (Often not; high risk of employee complaints.)
   - **Denial of service**: Explicitly disallow (can crash production systems).
   - **Physical testing**: Allowed to pick locks, tailgate, try USB drops? (Usually not.)
   - **3rd-party data**: If you exfiltrate customer data during test, you're liable; agree on data handling.

4. **Define timeline & availability**:
   - Test duration (1 week, 1 month, ongoing?).
   - Availability of target systems (production windows, maintenance windows to avoid).
   - When will findings be reported (daily, weekly, final report)?

5. **Sign-off & documentation**:
   - Engagement letter / contract (defines liability, confidentiality, scope).
   - ROE document (signatures from all parties).
   - Contact list (escalation contacts, emergency contacts).

**Deliverables:**
- Signed engagement letter.
- ROE document.
- Detailed scope definition (in-scope/out-of-scope systems, addresses, IPs, applications).

---

### Phase 2: Reconnaissance & Information Gathering

**Goal**: Gather all publicly available information about the target.

**Activities:**

#### Passive Reconnaissance (No direct contact with target)

```bash
# OSINT — publicly available information
# Target company domain, IP ranges, employees, infrastructure

# DNS enumeration
nslookup <target.com>
dig <target.com> ANY
whois <target.com>
whois <IP_RANGE>

# IP ranges & ASN
asnlookup -i <target.com>
whois -h whois.cymru.com " -v <IP>"

# Subdomain enumeration (passive, no scanning)
subfinder -d <target.com> -o subs.txt
amass enum -d <target.com> -passive

# Certificate enumeration (TLS certs often leak subdomains)
curl -s "https://crt.sh/?q=target.com&output=json" | jq '.[].name_value' | sort -u

# Email addresses, employee names
theHarvester -d <target.com> -b all

# GitHub leaks (employees may commit API keys, credentials)
github-dork.py
gitleaks scan -l

# Job postings (tech stack, hiring for new systems)
LinkedIn, Indeed job listings

# News articles, press releases (tech changes, acquisitions)
Google news, company blog

# Cached versions of websites
site:web.archive.org <target.com>

# DNS TXT records (SPF, DKIM, DMARC — auth configuration)
dig <target.com> TXT
```

#### Output of Phase 2
- List of all subdomains, IP addresses, ranges (CIDR).
- Employee names, email formats, phone numbers.
- Technology stack (web frameworks, CMS, plugins, versions — from headers, HTML meta tags, JavaScript libraries).
- DNS configuration (mail servers, nameservers).
- Certificates (TLS certs; often contain subdomains/SANs).
- External links, API endpoints discovered.
- Compliance information (privacy policies, security.txt, bug bounty programs).

**Note**: All information gathered passively (no port scans, no actual connections to services yet).

---

### Phase 3: Scanning & Enumeration

**Goal**: Actively probe the target to discover services, versions, and vulnerabilities.

**Activities:**

#### Network Scanning

```bash
# Port scanning — which ports are open, what services?
nmap -sV -sC -O <target_IP_or_subnet>
nmap -sV -Pn <target> (skip ping; assume host is up)
nmap --script vuln <target> (basic vulnerability checks)

# Service version detection
nmap -sV <target>

# OS detection
nmap -O <target>

# Aggressive scan (faster, noisier)
nmap -A -T4 <target>

# UDP scan (often missed, but DNS, SNMP, DHCP run on UDP)
nmap -sU <target>
```

#### Web Application Scanning

```bash
# Identify web services, directories, files
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://<target>/FUZZ
dirbuster (GUI version of ffuf)
gobuster dir -u http://<target> -w wordlist.txt

# Web server fingerprinting
curl -I http://<target>  # headers reveal server version, tech stack
nikto -h <target> (web server scanner)

# SSL/TLS certificate info
openssl s_client -connect <target>:443
testssl.sh <target>:443 (comprehensive TLS testing)

# Web app scanning (OWASP Top 10)
Burp Suite (manual + automated scanning)
OWASP ZAP (free alternative)
```

#### Vulnerability Scanning

```bash
# Network vulnerabilities
nessus (comprehensive; expensive but industry standard)
Qualys (cloud-based)
OpenVAS (free, open-source)
Rapid7 Nexpose

# Web app vulnerabilities
Burp Suite Professional (SAST/DAST)
OWASP ZAP
SQLmap (SQL injection detection)

# Configuration assessment
nmap NSE scripts (vuln category)
lynis (Linux hardening audit)
```

#### Active Enumeration (Interacting with services)

```bash
# SMB enumeration (file shares, users)
enum4linux -a <target>
smbclient -L \\<target> (list shares)

# LDAP enumeration (Active Directory)
ldapsearch -x -h <target> -b "dc=target,dc=com"

# HTTP enumeration (web server, apps, APIs)
curl, Burp, ZAP (explore app, find endpoints)

# Database enumeration
nmap -sV -p 3306,5432,1433 <target> (MySQL, PostgreSQL, MSSQL ports)

# Service enumeration
nmap -sV (shows service versions)
nmap --script default <target>
```

**Output of Phase 3:**
- Open ports, services, versions.
- Vulnerable services (Heartbleed on OpenSSL, EternalBlue on SMB, etc.).
- Web directories, files, endpoints.
- Technology stack details (WordPress 5.2, Apache 2.4.1, MySQL 5.6, etc.).
- Configuration weaknesses (default credentials, weak TLS, missing headers).
- User accounts, employee names from LDAP/email.

**Noise Level**: Phase 3 is **noisy** (lots of scanning traffic); target/IDS will likely detect it. Time this phase accordingly (don't scan at 2 AM in their office; they'll notice).

---

### Phase 4: Vulnerability Analysis

**Goal**: Review findings from scanning; identify exploitable vulnerabilities.

**Activities:**

1. **Prioritize findings**:
   - Filter out false positives (many scanners flag non-issues).
   - CVSS score each vulnerability (criticality).
   - Categorize by impact (RCE > privilege escalation > information disclosure > DoS).

2. **Assess exploitability**:
   - Which vulnerabilities can actually be exploited (not just theoretical)?
   - Which require authentication? (Insider threat, or valid credentials obtained?)
   - Which require user interaction? (Social engineering, phishing?)
   - Which are chained? (Combine low-severity vulns into higher-impact attack.)

3. **Develop exploitation strategy**:
   - **Path to initial access**: Which vulnerability do you exploit first?
     - Unpatched RCE on web server? SQL injection? Weak credentials?
   - **Post-exploitation**: Once you gain access, what's your next step?
     - Lateral movement (pivot to other systems)?
     - Privilege escalation (user → admin)?
     - Data exfiltration (steal customer data, intellectual property)?
   - **Impact assessment**: If vulnerability is exploited, what's the damage?
     - Confidentiality (data stolen)?
     - Integrity (data modified)?
     - Availability (system down)?

4. **Identify business impact**:
   - Which vulnerabilities matter most to the client?
   - A critical RCE is always important, but maybe the client is more concerned about insider threats or data exposure.
   - Align findings with client's risk tolerance.

**Output of Phase 4:**
- Prioritized vulnerability list (CVSS scores, business impact).
- Exploitation roadmap (which vulns to exploit, in what order).
- Risk assessment (likelihood × impact).

---

### Phase 5: Exploitation

**Goal**: Exploit identified vulnerabilities; gain access; demonstrate impact.

**Activities:**

#### Gaining Initial Access

```bash
# Web vulnerabilities
# SQL injection -> database access
sqlmap -u "http://<target>/login.php" --data="user=*&pass=*" -p user
# XSS -> session hijacking, credential theft
# Command injection -> RCE
# File upload -> web shell

# Network vulnerabilities
# Unpatched service (e.g., Heartbleed)
sslstrip, mitmproxy (MITM attacks if network access)
# Default credentials
# Weak credentials (brute force, dictionary attack)
hydra, medusa (credential spray)
# Physical access -> network access

# Social engineering
# Phishing -> credential harvesting
# Pretexting -> info gathering
# Tailgating -> physical access
```

#### Post-Exploitation

```bash
# Establish persistence (maintain access even if initial vector is patched)
Reverse shell, web shell, backdoor user account, scheduled task, rootkit

# Privilege escalation (user → admin/root)
UAC bypass (Windows), sudo misconfiguration (Linux), setuid exploitation

# Lateral movement (access other systems)
SMB pivoting, SSH key reuse, pass-the-hash, Kerberoasting (AD)

# Credential harvesting
Mimikatz (Windows credentials), keylogger, browser extension

# Data exfiltration
Steal customer data, intellectual property, employee records
Assess what's actually accessible with current privileges
```

#### Documenting Impact

- **Screenshots**: Proof of access (shell prompt, admin panel, database contents).
- **Evidence preservation**: Screenshots of sensitive data (customer names, SSNs, credit cards — redact for final report).
- **Objective proof**: Show business impact (deleted file, modified data, system downtime).

**Important**: Don't actually delete/modify production data; demonstrate the capability and roll back.

**Constraints** (from ROE):
- Don't crash systems.
- Don't exfiltrate customer data (demonstrate access, but don't actually steal).
- Don't escalate beyond what's necessary to demonstrate vulnerability.
- Report critical findings immediately (emergency escalation).

**Output of Phase 5:**
- Proof of exploitation (screenshots, shell access).
- Demonstration of impact (data accessible, system controllable).
- Evidence file (preserved for report).

---

### Phase 6: Post-Exploitation & Persistence (Optional)

**Goal**: Demonstrate long-term impact; test incident response.

**Activities:**

#### Persistence

```bash
# Establish backup access (if initial access is discovered)
Create admin account, web shell, reverse shell via cron/scheduled task
```

#### Lateral Movement

```bash
# Pivot to other systems
Use compromised system to scan internal network
Exploit trust relationships (SSH keys, Kerberos tickets)
Move toward high-value targets (database server, admin workstations)
```

#### Privilege Escalation

```bash
# Escalate to higher privilege
Kernel exploit, misconfigured sudo, weak permissions
Goal: Achieve domain admin, system admin, database admin
```

#### Cover Tracks (Optional; often explicitly disallowed)

```bash
# Delete logs, wipe forensic evidence
Usually NOT allowed (destroys evidence; client can't investigate)
Only if explicitly authorized and IR testing is goal
```

**Note**: Phase 6 is **high-risk**. ROE usually limits this; demonstrate capability, don't actually maintain persistent access (too dangerous).

---

### Phase 7: Reporting & Remediation

**Goal**: Document findings; provide clear, actionable remediation guidance; present to stakeholders.

#### Report Contents

**Executive Summary**:
- High-level overview (1–2 pages).
- Business impact in non-technical language.
- Overall risk rating (Critical, High, Medium, Low).
- Number and distribution of findings.

**Detailed Findings**:
- Per vulnerability:
  - **Name**: (SQL Injection, Unpatched RCE, etc.)
  - **CVSS Score**: Severity rating.
  - **Description**: What the vulnerability is; how it works.
  - **Proof of Concept**: Steps to reproduce; screenshot/evidence.
  - **Business Impact**: What's at risk (data, availability, compliance).
  - **Remediation**: Specific, actionable steps to fix.
  - **Reference**: CWE, OWASP Top 10, CVSS scoring details.

**Remediation Roadmap**:
- Prioritized fixes (critical first, then high, then medium).
- Timeline estimates (e.g., "Critical patch within 1 week, High within 30 days").
- Resource requirements (developer hours, vendor support, etc.).

**Methodology**:
- How testing was conducted (tools used, phases, scope).
- Timeline (test dates, duration).
- Constraints/limitations (what wasn't tested, why).

**Appendices**:
- Detailed tool output (nmap, vulnerability scanner results).
- Command-line examples.
- Engagement letter/ROE confirmation.

#### Report Delivery

**Presentation**:
- Executive briefing (findings, business impact, remediation priorities).
- Technical debrief (pentesters walk through methodology, findings, proof).
- Q&A (address concerns, discuss remediation).

**Distribution**:
- Typically under NDA; limited circulation.
- Often compartmentalized (exec summary to board, detailed findings to technical team).

**Remediation Tracking**:
- Follow-up assessments (re-test fixes; verify remediation).
- Ongoing monitoring (integrate findings into security program).

---

## PTES Testing Types

### Black Box (No Prior Knowledge)
- Tester has no information about target.
- Simulates external attacker.
- Most realistic; most time-consuming.

### White Box (Full Knowledge)
- Tester given system architecture, code, credentials, documentation.
- Simulates insider threat or authorized access testing.
- Faster; can be more thorough (but less realistic for external attack).

### Gray Box (Partial Knowledge)
- Tester given some info (IP ranges, tech stack, general architecture).
- Middle ground; realistic but with some efficiency gain.

---

## PTES Engagement Timeline

**Typical 2-week pentest:**

| Phase | Duration |
|---|---|
| Phase 1 (Pre-engagement) | 1–2 days (before testing starts; admin work) |
| Phase 2 (Reconnaissance) | 2–3 days (passive info gathering) |
| Phase 3 (Scanning & Enumeration) | 2–3 days (active probing; nmap, scanners) |
| Phase 4 (Vulnerability Analysis) | 1–2 days (reviewing findings, prioritizing) |
| Phase 5 (Exploitation) | 4–5 days (actual testing; gaining access, demonstrating impact) |
| Phase 6 (Post-Exploitation) | 1–2 days (persistence, lateral movement, if authorized) |
| Phase 7 (Reporting) | 3–5 days (writing report, creating evidence, presentation) |

**Total**: ~2–3 weeks for comprehensive pentest.

**Larger engagements** (month-long, full infrastructure): phases can extend to weeks each.

---

## PTES vs. Other Testing Methodologies

| Framework | Focus | Audience | Detail Level |
|---|---|---|---|
| **PTES** | Comprehensive penetration testing methodology | Pentesters, clients | Medium (actionable, not exhaustive) |
| **NIST SP 800-115** | Technical testing standard (federal systems) | U.S. government contractors | Very detailed (300+ pages) |
| **OWASP Testing Guide** | Web application testing checklist | Web developers, QA, pentesters | Very detailed (web-specific) |
| **Mitre ATT&CK** | Adversary tactics/techniques (post-exploitation focus) | Red teamers, defenders | Comprehensive (post-breach framework) |

---

## PTES Checklist

### Phase 1: Scope
- [ ] Engagement letter signed.
- [ ] ROE documented and agreed.
- [ ] Scope clearly defined (in-scope/out-of-scope systems).
- [ ] Escalation contacts established.
- [ ] Timeline confirmed.

### Phase 2: Reconnaissance
- [ ] Passive OSINT completed (no scanning).
- [ ] All subdomains enumerated.
- [ ] Employee information gathered.
- [ ] Technology stack identified.
- [ ] No evidence of active scanning (yet).

### Phase 3: Scanning
- [ ] Port scanning completed.
- [ ] Service versions identified.
- [ ] Vulnerability scanning performed.
- [ ] Web application enumeration done.
- [ ] Initial findings documented.

### Phase 4: Analysis
- [ ] Vulnerabilities prioritized (CVSS).
- [ ] False positives filtered.
- [ ] Exploitation strategy developed.
- [ ] Chained exploits identified.

### Phase 5: Exploitation
- [ ] Initial access demonstrated.
- [ ] Screenshots/evidence captured.
- [ ] Post-exploitation activities (if authorized).
- [ ] Impact measured.

### Phase 6: Post-Exploitation
- [ ] Persistence/lateral movement (if authorized).
- [ ] Privilege escalation attempted.
- [ ] Data access demonstrated.
- [ ] IR testing conducted (if applicable).

### Phase 7: Reporting
- [ ] Draft report written.
- [ ] Findings reviewed with client (optional).
- [ ] Final report delivered.
- [ ] Executive presentation scheduled.
- [ ] Remediation tracking established.

---


## See also

[[NIST-SP-800-115]], [[MITRE-ATT-CK]], [[OWASP-Top-10]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
