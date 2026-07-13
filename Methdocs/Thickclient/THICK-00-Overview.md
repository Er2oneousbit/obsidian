# Thick Client Penetration Testing Overview

## Purpose
Comprehensive methodology for assessing thick client application security vulnerabilities, with focus on client-side logic manipulation, insecure storage, network protocol abuse, and binary exploitation.

## Document Structure
- [[THICK-01-Admin-Checklist]] - Pre-engagement information gathering
- [[THICK-02-Technical-Testing-Checklist]] - Hands-on testing methodology
- [[THICK-03-Request-Tracker]] - Document successful/failed tests and exploits
- [[THICK-04-Evidence-Collection]] - Screenshot and evidence tracking
- [[THICK-05-Reporting-Template]] - Finding documentation structure
- [[THICK-06-Quick-Reference]] - Fast lookup for common attacks

## Engagement Workflow
1. Complete [[THICK-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[THICK-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[THICK-03-Request-Tracker|Request Tracker]]
4. Capture evidence per [[THICK-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[THICK-05-Reporting-Template|Reporting Template]]

## Key Concepts

### Attack Surface Areas
- **Client-Side Logic** - License validation, business rules, authentication
- **Local Storage** - Config files, databases, credential storage, temp files
- **Network Communication** - Protocol analysis, MitM, replay attacks
- **Binary Security** - DLL hijacking, code injection, memory corruption
- **Update Mechanisms** - Insecure updates, downgrade attacks
- **Thick-Thin Hybrid** - API security, session management
- **File System** - Permissions, sensitive file storage, log files

### Application Types Covered

#### Windows Desktop Applications
- .NET (WPF, WinForms)
- Native Win32/Win64
- C++/MFC applications
- Delphi applications
- Visual Basic 6

#### Cross-Platform Applications
- Electron/Chromium-based (Discord, Slack, VS Code)
- Java (Swing, JavaFX)
- Qt applications
- AIR (Adobe Integrated Runtime)

#### Client-Server Applications
- Two-tier (client + database)
- Three-tier (client + app server + database)
- SOA-based (client + web services)
- Rich Internet Applications (RIA)

###

 Common Vulnerability Classes

**OWASP Top 10 for Thick Clients** (Adapted):

1. **Improper Authorization** - Client-side checks only, missing server validation
2. **Sensitive Data Exposure** - Hardcoded credentials, plaintext storage, weak crypto
3. **Injection** - SQL, Command, LDAP via client inputs
4. **Security Misconfiguration** - Debug features enabled, verbose errors, insecure defaults
5. **Insecure Communication** - No TLS, weak crypto, certificate validation bypass
6. **Using Components with Known Vulnerabilities** - Outdated libraries, unpatched frameworks
7. **Insufficient Logging & Monitoring** - No audit trail, credentials in logs
8. **Code Quality Issues** - Buffer overflows, race conditions, memory leaks
9. **Insecure Update Mechanism** - No signature verification, MitM attacks
10. **Reverse Engineering** - No obfuscation, embedded secrets, easy decompilation

---
*Last Updated: 2026-01-22*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
