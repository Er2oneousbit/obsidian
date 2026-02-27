# Thick Client Admin Checklist

Quick reference for gathering administrative and architectural information before testing begins.

Related: [[THICK-02-Technical-Testing-Checklist]] | [[THICK-00-Overview]]

---

## Pre-Engagement

### Engagement Scope
- [ ] Application name/identifier documented
- [ ] Application version/build number
- [ ] Primary business function understood
- [ ] Deployment status confirmed (dev/staging/prod)
- [ ] Testing window scheduled
- [ ] Out-of-scope systems documented
- [ ] Emergency contact identified
- [ ] Rules of engagement signed
- [ ] Source code review included: Yes / No
- [ ] Decompilation/reverse engineering authorized: Yes / No

### Access Provided
- [ ] Test account credentials (multiple roles if possible)
  - [ ] Standard user: ________________
  - [ ] Power user: ________________
  - [ ] Admin user (if applicable): ________________
- [ ] Application installer/setup files
- [ ] License keys (if required)
- [ ] VPN/network access (if client-server)
- [ ] Documentation (user manual, admin guide, API docs)
- [ ] Source code access (if white-box)
- [ ] Test environment details (VM/physical machine specs)

### Initial Documentation Received
- [ ] Architecture diagram
- [ ] Technology stack documentation
- [ ] Database schema (if applicable)
- [ ] Network protocols used
- [ ] Known security controls
- [ ] Previous security assessments
- [ ] Incident response contact

---

## Application Architecture

### Platform & Type
- [ ] **Operating System**: [Windows / Linux / macOS / Cross-Platform]
- [ ] **Application Type**: 
  - [ ] Two-tier (client + database)
  - [ ] Three-tier (client + app server + database)
  - [ ] Standalone (no server component)
  - [ ] Hybrid (thick client + web services)

### Technology Stack

#### Windows Applications
- [ ] **Framework**: [.NET Framework / .NET Core / .NET 5+ / Native Win32]
- [ ] **.NET Version**: ________________
- [ ] **Language**: [C# / VB.NET / C++ / Delphi / VB6 / Other]
- [ ] **UI Framework**: [WPF / WinForms / UWP / Win32 / MFC / Other]
- [ ] **Target Architecture**: [x86 / x64 / AnyCPU]
- [ ] **Obfuscation**: [None / ConfuserEx / Dotfuscator / SmartAssembly / Other]
- [ ] **Packing**: [None / UPX / Themida / VMProtect / Other]

#### Linux Applications
- [ ] **Language**: [C / C++ / Python / Java / Go / Rust / Other]
- [ ] **UI Framework**: [GTK / Qt / Electron / Terminal-based / Other]
- [ ] **Distribution Format**: [AppImage / Snap / Flatpak / DEB / RPM / Binary]
- [ ] **Architecture**: [x86_64 / ARM / ARM64 / i386]
- [ ] **Linked Libraries**: [Static / Dynamic / Mixed]
- [ ] **Strip Status**: [Stripped / Not stripped]

#### Cross-Platform Applications
- [ ] **Technology**: [Electron / Java / Qt / Flutter / .NET MAUI / Other]
- [ ] **Electron Version**: ________________ (if applicable)
- [ ] **Node.js Version**: ________________ (if Electron)
- [ ] **Java Version**: ________________ (if Java)
- [ ] **Supported Platforms**: [Windows / Linux / macOS]

---

## Application Details

### Installation & Deployment
- [ ] **Installation method**: [Installer / Portable / MSI / DEB / RPM / AppImage]
- [ ] **Installer type**: [NSIS / Inno Setup / WiX / InstallShield / Other]
- [ ] **Installation directory**: ________________
- [ ] **Requires admin/root**: Yes / No
- [ ] **Service installation**: Yes / No
  - [ ] Service name: ________________
  - [ ] Service account: ________________
- [ ] **Auto-start enabled**: Yes / No
- [ ] **Registry modifications** (Windows): Yes / No
- [ ] **System integration**: [File associations / Protocol handlers / Shell extensions]

### File System Layout
Document application file locations:

**Windows**:
```
C:\Program Files\AppName\
C:\Program Files (x86)\AppName\
%APPDATA%\AppName\                    (User-specific data)
%LOCALAPPDATA%\AppName\               (Local cache/temp)
%PROGRAMDATA%\AppName\                (Shared data)
```

**Linux**:
```
/opt/appname/                         (Application binaries)
/usr/local/bin/appname                (Symlink)
~/.config/appname/                    (User config)
~/.local/share/appname/               (User data)
/etc/appname/                         (System config)
/var/log/appname/                     (Logs)
```

### File Inventory
- [ ] Main executable: ________________
- [ ] Configuration files: ________________
- [ ] Database files: ________________
- [ ] Log files: ________________
- [ ] DLL/SO files: ________________
- [ ] Resource files: ________________
- [ ] Temp file locations: ________________

---

## Authentication & Authorization

### Authentication Mechanisms
- [ ] **Auth type**: [Local / LDAP / Active Directory / OAuth / SAML / Database / None]
- [ ] **Credential storage**: [Local / Remote server / Keychain / Credential Manager]
- [ ] **Password policy**: [Enforced / Not enforced]
  - [ ] Min length: ________ characters
  - [ ] Complexity requirements: ________________
- [ ] **MFA/2FA**: Yes / No
- [ ] **Remember me/Stay logged in**: Yes / No
- [ ] **Biometric auth**: Yes / No (Windows Hello, TouchID, etc.)
- [ ] **Single Sign-On**: Yes / No
  - [ ] Provider: ________________

### Session Management
- [ ] **Session tokens**: Yes / No
  - [ ] Token format: [JWT / Custom / Cookie / Other]
  - [ ] Token location: [File / Registry / Memory / Keychain]
- [ ] **Session timeout**: ________ minutes
- [ ] **Persistent sessions**: Yes / No
- [ ] **Session storage location**: ________________

### Authorization Model
- [ ] **Authorization type**: [RBAC / File-based / Registry-based / Server-side / None]
- [ ] **Roles identified**:
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
- [ ] **Admin role exists**: Yes / No
- [ ] **Privilege escalation possible**: Unknown / To be tested

---

## Network Communication

### Network Protocols
- [ ] **Uses network**: Yes / No
- [ ] **Protocols**: [HTTP/HTTPS / TCP / UDP / WebSocket / gRPC / Custom]
- [ ] **Primary server**: ________________:________
- [ ] **Backup servers**: ________________
- [ ] **API endpoints**: ________________
- [ ] **Protocol encryption**: [TLS / SSL / Custom / None]
  - [ ] TLS version: ________________
  - [ ] Certificate validation: Yes / No / Unknown

### Network Behavior
- [ ] **Requires internet**: Yes / No / Optional
- [ ] **Offline mode available**: Yes / No
- [ ] **Local network only**: Yes / No
- [ ] **Proxy support**: Yes / No
  - [ ] Auto-detect proxy: Yes / No
  - [ ] Manual proxy config: Yes / No
- [ ] **VPN required**: Yes / No

### Third-Party Services
- [ ] **External APIs**: ________________
- [ ] **Update server**: ________________
- [ ] **Analytics/telemetry**: ________________
- [ ] **License server**: ________________
- [ ] **Cloud storage**: ________________

---

## Data Storage

### Local Storage Mechanisms

#### Windows-Specific
- [ ] **Registry usage**: Yes / No
  - [ ] HKEY_CURRENT_USER locations: ________________
  - [ ] HKEY_LOCAL_MACHINE locations: ________________
- [ ] **Windows Credential Manager**: Yes / No
- [ ] **DPAPI encryption**: Yes / No

#### Linux-Specific
- [ ] **Config files**: ________________
- [ ] **Gnome Keyring**: Yes / No
- [ ] **KDE Wallet**: Yes / No
- [ ] **Secret Service API**: Yes / No

#### Cross-Platform
- [ ] **Local database**: Yes / No
  - [ ] Type: [SQLite / Berkeley DB / LevelDB / Other]
  - [ ] Location: ________________
  - [ ] Encryption: Yes / No
- [ ] **Flat files**: [XML / JSON / INI / Binary / Custom]
- [ ] **Keychain/Keystore usage**: Yes / No

### Sensitive Data Types
Application stores/processes (check all that apply):
- [ ] User credentials
- [ ] Session tokens
- [ ] API keys
- [ ] Encryption keys
- [ ] PII (Personally Identifiable Information)
- [ ] PHI (Protected Health Information)
- [ ] PCI (Payment Card Information)
- [ ] Business confidential data
- [ ] Customer data
- [ ] Financial records
- [ ] Other: ________________

### Data Encryption
- [ ] **Encryption at rest**: Yes / No / Unknown
  - [ ] Algorithm: ________________
  - [ ] Key storage: ________________
- [ ] **Encryption in transit**: Yes / No
  - [ ] Protocol: ________________
- [ ] **Hardcoded keys**: Unknown / To be tested

---

## Update Mechanism

### Update Process
- [ ] **Auto-update**: Yes / No / Optional
- [ ] **Update frequency**: ________________
- [ ] **Update server**: ________________
- [ ] **Update protocol**: [HTTP / HTTPS / Custom]
- [ ] **Update file format**: [MSI / EXE / DEB / RPM / AppImage / Delta updates]
- [ ] **Signature verification**: Yes / No / Unknown
- [ ] **User notification**: Yes / No
- [ ] **Forced updates**: Yes / No
- [ ] **Rollback capability**: Yes / No

### Update Security
- [ ] **HTTPS enforced**: Yes / No
- [ ] **Certificate pinning**: Yes / No
- [ ] **Code signing**: Yes / No
  - [ ] Certificate authority: ________________
- [ ] **Hash verification**: Yes / No
  - [ ] Algorithm: ________________

---

## Security Controls

### Application-Level Security

#### Input Validation
- [ ] **Input validation**: Yes / No / Unknown
- [ ] **Validation location**: [Client-side / Server-side / Both]
- [ ] **SQL injection protection**: Yes / No / Unknown
- [ ] **Command injection protection**: Yes / No / Unknown
- [ ] **Path traversal protection**: Yes / No / Unknown

#### Output Encoding
- [ ] **Output encoding**: Yes / No / Unknown
- [ ] **XSS protection** (if web views): Yes / No / N/A

#### Logging & Monitoring
- [ ] **Application logging**: Yes / No
  - [ ] Log level: [Debug / Info / Warning / Error]
  - [ ] Log location: ________________
  - [ ] Log rotation: Yes / No
- [ ] **Audit trail**: Yes / No
  - [ ] Events logged: ________________
- [ ] **Sensitive data in logs**: Unknown / To be tested
- [ ] **Centralized logging**: Yes / No

### Binary Security (To Be Tested)

#### Windows Binary Protections
- [ ] **ASLR** (Address Space Layout Randomization): Unknown
- [ ] **DEP/NX** (Data Execution Prevention): Unknown
- [ ] **Stack Canaries**: Unknown
- [ ] **SafeSEH**: Unknown
- [ ] **Control Flow Guard (CFG)**: Unknown
- [ ] **Code signing**: Yes / No
  - [ ] Certificate: ________________

#### Linux Binary Protections
- [ ] **PIE** (Position Independent Executable): Unknown
- [ ] **Stack canaries**: Unknown
- [ ] **NX bit**: Unknown
- [ ] **RELRO**: Unknown
- [ ] **FORTIFY_SOURCE**: Unknown
- [ ] **Stripped symbols**: Unknown

### Anti-Tampering
- [ ] **Obfuscation**: Yes / No / Unknown
  - [ ] Tool: ________________
- [ ] **Packing**: Yes / No / Unknown
  - [ ] Packer: ________________
- [ ] **Anti-debugging**: Yes / No / Unknown
- [ ] **Integrity checks**: Yes / No / Unknown
- [ ] **Code signing validation**: Yes / No / Unknown

---

## Licensing & Trials

### License Model
- [ ] **License type**: [Perpetual / Subscription / Trial / Free / Freemium]
- [ ] **Trial period**: ________ days
- [ ] **License validation**: [Client-side / Server-side / Hybrid]
- [ ] **Offline validation**: Yes / No
- [ ] **Hardware locking**: Yes / No
  - [ ] Method: [MAC address / HDD serial / Other]
- [ ] **License file location**: ________________
- [ ] **License server**: ________________

### Feature Restrictions
- [ ] **Feature flags**: Yes / No
  - [ ] Location: [Config file / Registry / Database / Server]
- [ ] **Time-based restrictions**: Yes / No
- [ ] **Usage limits**: Yes / No (e.g., max transactions, users)

---

## Business Context

### Application Purpose
- [ ] **Primary function**: ________________
- [ ] **User base size**: ________________
- [ ] **Business criticality**: [Low / Medium / High / Critical]
- [ ] **Regulated industry**: Yes / No
  - [ ] Regulations: [HIPAA / PCI-DSS / GDPR / SOX / Other]
- [ ] **Revenue impact**: [Direct / Indirect / None]

### Deployment Scale
- [ ] **Number of installations**: ________________
- [ ] **Geographic distribution**: ________________
- [ ] **Update deployment method**: [Centralized / User-initiated / Both]

### Risk Assessment
- [ ] **Handles sensitive data**: Yes / No
- [ ] **Internet-facing**: Yes / No
- [ ] **Mission-critical**: Yes / No
- [ ] **Regulatory requirements**: ________________
- [ ] **Previous security incidents**: Yes / No
  - [ ] Details: ________________

---

## Development & Operations

### Development Team
- [ ] **Security champion identified**: Yes / No
  - [ ] Contact: ________________
- [ ] **Dev team contact**: ________________
- [ ] **DevOps contact**: ________________
- [ ] **Incident response contact**: ________________

### Security Posture
- [ ] **Previous pentests**: Yes / No
  - [ ] Date: ________________
  - [ ] Critical findings: ________________
- [ ] **Bug bounty program**: Yes / No
- [ ] **Security training**: Yes / No
- [ ] **Secure coding standards**: Yes / No
- [ ] **Code review process**: Yes / No

### CI/CD Pipeline
- [ ] **Version control**: [Git / SVN / Other]
- [ ] **Build automation**: Yes / No
- [ ] **SAST**: Yes / No
  - [ ] Tool: ________________
- [ ] **DAST**: Yes / No
- [ ] **Dependency scanning**: Yes / No
- [ ] **Binary signing**: Yes / No
- [ ] **Release frequency**: ________________

---

## Testing Constraints

### Known Limitations
Document any restrictions or special considerations:
- ________________
- ________________
- ________________

### Red Lines (Do Not Cross)
- ________________
- ________________
- ________________

### Testing Environment
- [ ] **Testing on**: [Production / Staging / Dev / Isolated VM]
- [ ] **OS version**: ________________
- [ ] **VM snapshot available**: Yes / No
- [ ] **Network isolation required**: Yes / No
- [ ] **Monitoring in place**: Yes / No

### Special Notes
________________
________________
________________

---

## Initial Observations

### Technology Fingerprinting
- [ ] **Detected framework**: ________________
- [ ] **Detected language**: ________________
- [ ] **Detected libraries**: ________________
- [ ] **Packed/obfuscated**: Yes / No

### Quick Checks (First 5 Minutes)
- [ ] Run `strings` on binary - any interesting strings?
- [ ] Check file properties (Windows: Right-click → Properties → Details)
- [ ] Check installation directory for config files
- [ ] Check %APPDATA% or ~/.config for app data
- [ ] Launch app and check network connections (TCPView/netstat)

### Quick Wins Identified
- [ ] ________________
- [ ] ________________

---

## Kickoff Meeting Notes

**Date**: ________________
**Attendees**: ________________

**Key Discussion Points**:
________________
________________

**Questions to Follow Up**:
- [ ] ________________
- [ ] ________________

---

## Administrative Checklist Complete
- [ ] All critical information gathered
- [ ] Scope clearly defined
- [ ] Access confirmed working
- [ ] Testing environment prepared
- [ ] Tools installed (dnSpy, Procmon, Wireshark, etc.)
- [ ] Baseline snapshot taken (if VM)
- [ ] Ready to proceed to [[THICK-02-Technical-Testing-Checklist|Technical Testing]]

---

## Tags
#admin #discovery #scoping #thick-client

---

## Related Documents
- [[THICK-00-Overview|Overview]]
- [[THICK-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[THICK-03-Request-Tracker|Request Tracker]]

---
*Created: 2026-01-22*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
