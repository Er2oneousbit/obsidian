# Thick Client Evidence Collection Guide

Comprehensive guide for capturing, organizing, and documenting evidence during thick client penetration testing. Proper evidence collection is critical for reproducibility and reporting.

Related: [[THICK-02-Technical-Testing-Checklist]] | [[THICK-03-Request-Tracker]] | [[THICK-05-Reporting-Template]]

---

## Evidence Collection Principles

### Core Principles
1. **Capture everything** - It's easier to discard extra evidence than recreate it
2. **Name systematically** - Use consistent naming conventions for easy retrieval
3. **Document context** - Screenshots should show timestamps, versions, and relevant context
4. **Preserve originals** - Never modify original evidence files
5. **Organize immediately** - Don't wait until end of engagement to organize
6. **Hash everything** - MD5/SHA256 hashes prove evidence integrity

### Evidence Types
- **Screenshots** - Visual proof of vulnerabilities and exploitation
- **Screen recordings** - Video demonstrations of exploits
- **Binary files** - Original and modified executables, DLLs, configs
- **Text files** - Strings output, decompiled code, logs
- **Network captures** - PCAPs of traffic
- **Memory dumps** - Process memory captures
- **Code snippets** - Decompiled/disassembled code showing vulnerabilities

---

## Directory Structure

Create this folder structure at the start of each engagement:

```
[ClientName]_ThickClient_[Date]/
│
├── 01_Documentation/
│   ├── scope.txt
│   ├── timeline.txt
│   └── notes.txt
│
├── 02_Original_Files/
│   ├── binaries/
│   │   ├── app.exe
│   │   ├── helper.exe
│   │   └── *.dll
│   ├── configs/
│   │   ├── config.xml
│   │   └── settings.ini
│   └── hashes.txt
│
├── 03_Modified_Files/
│   ├── patched_binaries/
│   │   ├── app_patched.exe
│   │   └── README.txt (what was changed)
│   ├── malicious_dlls/
│   │   ├── version.dll
│   │   └── version_source.cpp
│   └── modified_configs/
│       └── config_bypassed.xml
│
├── 04_Static_Analysis/
│   ├── strings/
│   │   ├── app_strings_ascii.txt
│   │   └── app_strings_unicode.txt
│   ├── decompiled/
│   │   └── [exported dnSpy projects]
│   ├── disassembly/
│   │   └── [Ghidra projects]
│   └── analysis_notes.txt
│
├── 05_Dynamic_Analysis/
│   ├── procmon/
│   │   ├── capture_001.pml
│   │   └── capture_001.csv
│   ├── memory_dumps/
│   │   ├── app_12345.dmp
│   │   └── memory_strings.txt
│   └── strace/
│       └── app_strace.log
│
├── 06_Network_Analysis/
│   ├── pcaps/
│   │   ├── capture_001.pcap
│   │   ├── capture_002.pcap
│   │   └── README.txt
│   ├── burp/
│   │   ├── project_state.burp
│   │   └── interesting_requests.xml
│   └── ssl_certs/
│       └── server_cert.pem
│
├── 07_Screenshots/
│   ├── 001_authentication_bypass/
│   │   ├── 001_01_original_login.png
│   │   ├── 001_02_decompiled_code.png
│   │   ├── 001_03_patched_code.png
│   │   └── 001_04_bypass_success.png
│   ├── 002_license_bypass/
│   └── 003_dll_hijacking/
│
├── 08_Videos/
│   ├── 001_authentication_bypass.mp4
│   ├── 002_license_bypass.mp4
│   └── 003_dll_hijacking.mp4
│
├── 09_Exploits/
│   ├── 001_auth_bypass/
│   │   ├── app_patched.exe
│   │   ├── exploit_steps.txt
│   │   └── proof.png
│   ├── 002_dll_hijack/
│   │   ├── malicious.dll
│   │   ├── source.cpp
│   │   └── compilation.txt
│   └── README.txt
│
├── 10_Registry/
│   ├── before_changes.reg
│   ├── after_changes.reg
│   └── interesting_keys.txt
│
├── 11_Logs/
│   ├── tool_output/
│   └── error_logs/
│
└── 12_Report_Evidence/
    ├── finding_001/
    ├── finding_002/
    └── [organized by finding for easy report writing]
```

---

## File Naming Convention

Use consistent naming for all evidence files:

### Screenshot Naming
```
[FindingNumber]_[SequenceNumber]_[Description].png

Examples:
001_01_original_login_prompt.png
001_02_decompiled_authentication_code.png
001_03_patched_authentication_always_true.png
001_04_bypass_successful_admin_access.png
002_01_trial_expired_message.png
002_02_registry_trial_end_date.png
```

### Video Naming
```
[FindingNumber]_[Description].mp4

Examples:
001_authentication_bypass_demonstration.mp4
002_license_bypass_walkthrough.mp4
003_dll_hijacking_poc.mp4
```

### Binary Files
```
[OriginalName]_[Modification]_[Date].ext

Examples:
app.exe (original)
app_patched_auth_bypass_20260122.exe
app_patched_license_bypass_20260122.exe
malicious_version_dll_20260122.dll
```

### Text Files
```
[Type]_[Component]_[Date].txt

Examples:
strings_app_exe_20260122.txt
memory_dump_analysis_20260122.txt
decompiled_LoginManager_20260122.cs
procmon_file_operations_20260122.csv
```

---

## Screenshot Requirements

### General Screenshot Guidelines
- **Resolution**: Minimum 1920x1080 for clarity
- **Format**: PNG (lossless) for technical screenshots
- **Annotations**: Use red boxes/arrows to highlight important areas
- **Timestamp**: Ensure system clock visible or include timestamp in filename
- **Window borders**: Capture full window with title bar (shows application name/version)
- **No sensitive data**: Redact any sensitive client data not relevant to finding

### Required Screenshots Per Finding Type

#### Authentication Bypass
1. **Before bypass**:
   - Login prompt requiring credentials
   - Access denied message for invalid credentials
2. **Code analysis**:
   - Decompiled authentication code in dnSpy/Ghidra
   - Highlight the vulnerable validation logic
3. **Patched code**:
   - Modified code showing bypass (e.g., `return true;`)
   - Save dialog or indicator that binary was saved
4. **After bypass**:
   - Successful login with invalid/no credentials
   - Access to protected functionality
   - User account details showing low-privilege account with admin access

#### License/Trial Bypass
1. **Before bypass**:
   - Trial expired message
   - Limited functionality notification
   - License validation prompt
2. **Analysis**:
   - Decompiled license validation code
   - Registry/config showing trial date or license key
3. **Bypass method**:
   - Patched code OR modified registry/config
   - Tool used (dnSpy, Registry Editor)
4. **After bypass**:
   - Full access message
   - Premium features accessible
   - Extended trial or validated license indicator

#### DLL Hijacking
1. **Discovery**:
   - Process Monitor showing "NAME NOT FOUND" for DLL
   - Filter settings showing included processes
2. **Exploitation**:
   - Malicious DLL in application directory (Explorer view)
   - DLL source code in editor
3. **Proof of concept**:
   - Calculator launched (or other PoC indicator)
   - Process Explorer showing malicious DLL loaded
   - DLL properties showing it's unsigned/from test location

#### Privilege Escalation
1. **Before escalation**:
   - Low-privilege account properties
   - Denied access to admin functions
2. **Code analysis**:
   - Insufficient authorization check in code
   - Role/permission validation logic
3. **Exploitation**:
   - Modified role in registry/config/database
   - Patched authorization check
4. **After escalation**:
   - Low-privilege account with admin access
   - Successful execution of privileged functions

#### Hardcoded Credentials
1. **Discovery location**:
   - Strings output showing credentials
   - Decompiled code with hardcoded values
   - Config file with plaintext credentials
2. **Context**:
   - Full function/class showing credential usage
   - Comments or variable names indicating purpose
3. **Validation**:
   - Successful use of discovered credentials
   - Access granted with hardcoded credentials

#### Sensitive Data Exposure
1. **Location**:
   - File Explorer showing unprotected file location
   - File permissions (icacls output)
   - Database structure (SQLite browser)
2. **Contents**:
   - File contents showing sensitive data
   - Highlight the sensitive fields
3. **Context**:
   - Process Monitor showing file access
   - When and how file is accessed

---

## Screen Recording Requirements

### When to Record Video
- **Complex exploitation** - Multi-step process better shown in video
- **Interactive exploitation** - Real-time interaction with application
- **Time-based exploitation** - Trial bypass, session hijacking
- **Proof of RCE** - Command execution, code injection
- **Client demonstrations** - For executive presentation

### Video Guidelines
- **Duration**: 2-5 minutes per video (longer videos should be edited)
- **Format**: MP4 (H.264) for compatibility
- **Resolution**: 1920x1080 minimum
- **Frame rate**: 30 fps minimum
- **Audio**: Optional but helpful for narration
- **Annotations**: Add text overlays for key steps
- **Speed**: Real-time or slightly sped up (1.5x max)

### Video Structure
1. **Introduction** (5-10 seconds):
   - Show clean state / before exploitation
   - Display application name and version
2. **Exploitation** (1-3 minutes):
   - Step through exploitation process
   - Pause briefly at key steps
   - Show each command/action clearly
3. **Proof** (10-20 seconds):
   - Demonstrate successful exploitation
   - Show impact (access gained, code executed, etc.)
4. **End card** (5 seconds):
   - Finding number and description
   - Your name/company

### Recording Tools
**Windows**:
- OBS Studio (free, professional)
- Windows Game Bar (Win+G, built-in)
- SnagIt (commercial)

**Linux**:
- SimpleScreenRecorder
- OBS Studio
- Kazam

---

## Code Documentation

### Decompiled Code
**Save both**:
1. **Raw format** - Exported from dnSpy/Ghidra as-is
2. **Annotated format** - With comments explaining vulnerability

**Annotation Example**:
```csharp
// VULNERABLE: Client-side authentication without server validation
// Location: App.Auth.LoginManager.ValidateLogin()
// Impact: Complete authentication bypass
// CWE-602: Client-Side Enforcement of Server-Side Security

public bool ValidateLogin(string username, string password) {
    // No server call - all validation is local!
    string storedHash = GetStoredPasswordHash(username); // Reads from local DB
    string inputHash = ComputeHash(password);
    
    if (storedHash == inputHash) {
        isAuthenticated = true;  // Can be patched to always true
        return true;
    }
    return false;
}

// REMEDIATION:
// 1. Move authentication to server
// 2. Never trust client-side validation
// 3. Implement proper session management
// 4. Add code integrity checks
```

### Patched Code
**Document changes clearly**:
```csharp
// ORIGINAL CODE:
public bool ValidateLogin(string username, string password) {
    string storedHash = GetStoredPasswordHash(username);
    string inputHash = ComputeHash(password);
    
    if (storedHash == inputHash) {
        isAuthenticated = true;
        return true;
    }
    return false;
}

// PATCHED CODE (for PoC):
public bool ValidateLogin(string username, string password) {
    // BYPASSED: Authentication check removed
    if (true) {  // <-- Changed: Always returns true
        isAuthenticated = true;
        return true;
    }
    return false;  // Never reached
}
```

---

## Network Traffic Capture

### PCAP Files
**Capture requirements**:
- Start capture before launching application
- Capture during all testing activities
- Stop after application closed
- Save multiple smaller files rather than one huge file

**Naming**:
```
capture_[date]_[time]_[description].pcap

Examples:
capture_20260122_0900_initial_connection.pcap
capture_20260122_1015_login_attempt.pcap
capture_20260122_1430_plaintext_credentials.pcap
```

**Wireshark annotations**:
- Add packet comments for interesting traffic
- Export specific conversations: Statistics → Conversations → Follow Stream
- Export HTTP objects: File → Export Objects → HTTP

### Burp Suite
**Save project state**:
```
File → Save Project → [ClientName]_[Date].burp
```

**Export interesting requests**:
- Right-click request → Copy as curl command
- Save to: `interesting_requests_[date].txt`
- Include both request and response

**Example export**:
```bash
# Request #15 - Plaintext credentials over HTTP
# Finding: HIGH - Credentials transmitted in cleartext
# Date: 2026-01-22 10:15

curl -X POST http://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SuperSecret123"}'

# Response:
# HTTP/1.1 200 OK
# {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","status":"success"}
```

---

## Binary Files

### Original Files
**Always preserve originals**:
- Copy original files before any modification
- Calculate hashes immediately:
  ```powershell
  Get-FileHash -Algorithm SHA256 app.exe | Format-List
  ```
- Store in `02_Original_Files/` with hash documentation

**Hash documentation** (`hashes.txt`):
```
File: app.exe
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Size: 2,458,624 bytes
Date: 2026-01-22 08:30:15

File: helper.exe
MD5: 098f6bcd4621d373cade4e832627b4f6
SHA256: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
Size: 1,125,376 bytes
Date: 2026-01-22 08:30:20
```

### Modified Files
**Document all changes**:
- Save patched binaries with descriptive names
- Include README.txt describing modifications
- Keep original and patched side-by-side for comparison

**README template** for modified files:
```
MODIFIED FILE: app_patched_auth_bypass.exe

ORIGINAL FILE: app.exe
ORIGINAL HASH: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

MODIFICATIONS:
1. Function: App.Auth.LoginManager.ValidateLogin()
2. Change: Modified authentication check to always return true
3. Line: Changed "if (storedHash == inputHash)" to "if (true)"
4. Purpose: Proof-of-concept for authentication bypass vulnerability

TOOL USED: dnSpy v6.1.8
MODIFIED BY: Er2oneousbit
DATE: 2026-01-22 11:30:00

INSTRUCTIONS TO REPRODUCE:
1. Open original app.exe in dnSpy
2. Navigate to App.Auth → LoginManager → ValidateLogin()
3. Right-click method → Edit Method (C#)
4. Change line 15 from "if (storedHash == inputHash)" to "if (true)"
5. Click Compile
6. File → Save Module → Save as app_patched_auth_bypass.exe

VERIFICATION:
- Launch patched binary
- Enter any username/password
- Application grants access without valid credentials

FINDING REFERENCE: See [[THICK-03-Request-Tracker#Test-005]]
```

---

## Memory Dumps

### Creating Memory Dumps
**Windows - ProcDump**:
```powershell
# Full memory dump
procdump64.exe -ma <PID> app_memory_dump.dmp

# With description
procdump64.exe -ma <PID> app_memory_dump.dmp -r "Post-login memory capture"
```

**Linux - gcore**:
```bash
sudo gcore -o app_memory $(pidof app)
```

### Analyzing Memory Dumps
```powershell
# Extract strings
strings64.exe app_memory_dump.dmp > memory_strings.txt

# Search for sensitive data
Select-String -Path memory_strings.txt -Pattern "password|api|key|token" -Context 2
```

### Documentation
**Create**: `memory_analysis_[date].txt`
```
MEMORY DUMP ANALYSIS

Dump File: app_memory_dump.dmp
Process: app.exe (PID: 12345)
Capture Time: 2026-01-22 14:30:00
Capture Point: After successful login, before logout
User Context: DOMAIN\testuser

SENSITIVE DATA FOUND:

[Finding #1: User Password in Memory]
Offset: 0x00ABC123
Data: "password=SuperSecret123"
Context: Appears immediately after username in heap
Risk: Password stored in cleartext in memory
Recommendation: Secure memory, use SecureString class

[Finding #2: Database Connection String]
Offset: 0x00DEF456
Data: "Server=db.internal.com;Database=AppDB;User Id=sa;Password=DBPass!23;"
Risk: Database credentials in memory
Recommendation: Use Windows Authentication, encrypt connection strings

[Finding #3: Session Token]
Offset: 0x00789ABC
Data: "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
Context: JWT token with 24-hour expiration
Risk: Token can be stolen from memory
Recommendation: Implement token encryption, reduce expiration time
```

---

## Process Monitor Captures

### Capture Configuration
**Essential filters**:
```
Include: Process Name is app.exe
Include: Process Name is updater.exe
Exclude: Process Name is System
Exclude: Operation is RegQueryValue AND Result is NAME NOT FOUND
```

**Save formats**:
1. **Native format**: `.pml` for reopening in Procmon
2. **CSV export**: For analysis in Excel/Python
3. **Text summary**: Annotated interesting operations

### CSV Analysis
**Important columns**:
- Time of Day
- Process Name
- Operation (CreateFile, RegQueryValue, TCP Send, etc.)
- Path (file/registry path)
- Result (SUCCESS, NAME NOT FOUND, ACCESS DENIED)
- Detail (additional context)

**Documentation** (`procmon_analysis_[date].txt`):
```
PROCESS MONITOR ANALYSIS

Capture Duration: 2026-01-22 09:00:00 to 10:30:00
Process: app.exe
Events Captured: 45,231 (after filtering: 2,145)

KEY FINDINGS:

[Finding #1: Plaintext Configuration Access]
09:15:23 - CreateFile: C:\ProgramData\App\config.xml - SUCCESS
09:15:23 - ReadFile: C:\ProgramData\App\config.xml - SUCCESS (2,048 bytes)
Impact: Config file contains plaintext database credentials
Permissions: BUILTIN\Users - Read/Write
Risk: Any user can read sensitive configuration

[Finding #2: DLL Hijacking Opportunity]
09:16:45 - CreateFile: C:\Windows\System32\version.dll - NAME NOT FOUND
09:16:45 - CreateFile: C:\Program Files\App\version.dll - NAME NOT FOUND
Impact: Application searches for missing DLL in application directory first
Risk: DLL hijacking attack possible

[Finding #3: Temp File with Session Data]
09:20:12 - CreateFile: C:\Users\test\AppData\Local\Temp\app_session_12345.tmp - SUCCESS
09:20:12 - WriteFile: C:\Users\test\AppData\Local\Temp\app_session_12345.tmp - SUCCESS
Detail: Contains session token (viewed with hex editor)
Permissions: User - Full Control
Risk: Session token theft from temp file
```

---

## Registry Exports

### Exporting Registry Keys
```powershell
# Export single key
reg export "HKCU\Software\App" app_registry_before.reg

# After modifications
reg export "HKCU\Software\App" app_registry_after.reg

# Compare
Compare-Object (Get-Content app_registry_before.reg) (Get-Content app_registry_after.reg)
```

### Documentation
**Create**: `registry_analysis_[date].txt`
```
REGISTRY ANALYSIS

[Finding #1: License Key in Registry]
Key: HKCU\Software\App
Value: LicenseKey
Data: "ABCD-1234-EFGH-5678"
Type: REG_SZ
Permissions: Current User - Full Control
Risk: License key easily viewable and modifiable
Exploitation: Changed to valid key from strings analysis

[Finding #2: Trial End Date]
Key: HKCU\Software\App
Value: TrialEndDate
Data: "2026-01-01" (expired)
Modified To: "2099-12-31"
Risk: Trial period can be extended indefinitely
Impact: License bypass

[Finding #3: User Role]
Key: HKCU\Software\App
Value: UserRole
Original: "User"
Modified To: "Administrator"
Risk: Client-side role enforcement only
Impact: Privilege escalation to admin
```

---

## Evidence Checklist

Use this checklist for each finding to ensure complete evidence collection:

### Authentication Bypass Finding
- [ ] Screenshot: Original login prompt/access denied
- [ ] Screenshot: Decompiled authentication code (full function)
- [ ] Screenshot: Patched code showing bypass
- [ ] Screenshot: Successful bypass (logged in with invalid creds)
- [ ] File: Patched binary saved
- [ ] File: Original binary hash documented
- [ ] File: Decompiled code exported (annotated)
- [ ] File: Exploitation steps documented
- [ ] Video: (Optional) Full exploitation walkthrough
- [ ] Test log entry in [[THICK-03-Request-Tracker]]

### License/Trial Bypass Finding
- [ ] Screenshot: Trial expired / License invalid message
- [ ] Screenshot: Decompiled license validation code
- [ ] Screenshot: Registry/config/database with trial/license data
- [ ] Screenshot: Modified registry/config/code
- [ ] Screenshot: Trial extended / License validated
- [ ] File: Patched binary OR modified config
- [ ] File: Before/after registry export
- [ ] File: Exploitation steps documented
- [ ] Video: (Optional) Bypass demonstration
- [ ] Test log entry in [[THICK-03-Request-Tracker]]

### DLL Hijacking Finding
- [ ] Screenshot: Procmon showing NAME NOT FOUND
- [ ] Screenshot: Procmon filter settings
- [ ] Screenshot: DLL in application directory
- [ ] Screenshot: Calculator/PoC indicator launched
- [ ] Screenshot: Process Explorer showing DLL loaded
- [ ] File: Malicious DLL binary
- [ ] File: DLL source code
- [ ] File: Compilation instructions
- [ ] File: Exploitation steps documented
- [ ] Video: (Recommended) DLL hijack PoC
- [ ] Test log entry in [[THICK-03-Request-Tracker]]

### Sensitive Data Exposure Finding
- [ ] Screenshot: File location in Explorer
- [ ] Screenshot: File permissions (icacls output)
- [ ] Screenshot: File contents showing sensitive data
- [ ] Screenshot: Procmon showing file access
- [ ] File: Copy of sensitive file (sanitized if needed)
- [ ] File: Procmon CSV export of file operations
- [ ] Text: Analysis of what sensitive data was found
- [ ] Test log entry in [[THICK-03-Request-Tracker]]

### Privilege Escalation Finding
- [ ] Screenshot: Low-privilege user account properties
- [ ] Screenshot: Access denied to privileged function
- [ ] Screenshot: Decompiled authorization code
- [ ] Screenshot: Modified role/permissions
- [ ] Screenshot: Low-privilege user accessing admin function
- [ ] File: Modified registry/config/database
- [ ] File: Exploitation steps documented
- [ ] Video: (Recommended) Full escalation demonstration
- [ ] Test log entry in [[THICK-03-Request-Tracker]]

---

## Final Evidence Package

Before delivering the report, create a final evidence package:

### Package Structure
```
[ClientName]_ThickClient_Evidence_[Date].zip
│
├── 00_README.txt (describes package contents)
├── 01_Executive_Summary.pdf
├── 02_Full_Report.pdf
├── 03_Technical_Appendix.pdf
│
├── Evidence_by_Finding/
│   ├── Finding_001_Authentication_Bypass/
│   │   ├── screenshots/
│   │   ├── code/
│   │   ├── binaries/
│   │   └── README.txt
│   ├── Finding_002_License_Bypass/
│   └── Finding_003_DLL_Hijacking/
│
├── Original_Application_Files/
│   └── (with hashes.txt)
│
├── Tool_Outputs/
│   ├── procmon/
│   ├── wireshark/
│   └── memory_dumps/
│
└── Exploitation_Scripts/
    └── (with README for each)
```

### README Template
```
THICK CLIENT PENETRATION TEST - EVIDENCE PACKAGE

Client: [Client Name]
Application: [Application Name] v[Version]
Test Period: [Start Date] to [End Date]
Tester: Er2oneousbit
Report Date: [Date]

PACKAGE CONTENTS:
1. Executive Summary Report (PDF)
2. Full Technical Report (PDF)
3. Technical Appendix with detailed findings (PDF)
4. Evidence organized by finding number
5. Original application files with integrity hashes
6. Tool outputs and analysis files
7. Proof-of-concept exploits with source code

EVIDENCE INTEGRITY:
All evidence files include MD5/SHA256 hashes for verification.
See hashes.txt in each subdirectory.

SENSITIVE DATA:
Some evidence files contain sanitized/redacted data to protect sensitive information.
Original unsanitized evidence available upon request with proper authorization.

REPRODUCTION:
Each finding includes detailed reproduction steps.
All exploits include source code and compilation instructions.
Testing environment details documented in Technical Appendix.

CONTACT:
For questions about evidence or reproduction, contact:
Er2oneousbit - [contact info]

CONFIDENTIALITY:
This evidence package contains sensitive security information.
Distribution should be limited to authorized personnel only.
```

---

## Tips for Effective Evidence Collection

### During Testing
1. **Screenshot as you go** - Don't wait until the end
2. **Use consistent naming** - Future you will thank present you
3. **Annotate immediately** - While context is fresh
4. **Backup frequently** - Copy evidence to multiple locations
5. **Test reproduction** - Verify exploits work before marking complete

### Screenshots
1. **Context matters** - Show window title bars, timestamps
2. **Highlight key areas** - Red boxes/arrows for clarity
3. **Multiple angles** - Before, during, after
4. **Clean background** - Close unnecessary windows
5. **High resolution** - Better to scale down than scale up

### Videos
1. **Script it out** - Plan before recording
2. **Slow down** - Go slower than feels natural
3. **Narrate** - Explain what you're doing
4. **Edit** - Remove dead time, mistakes
5. **Test playback** - Verify video quality before continuing

### Organization
1. **One finding = One folder** - Everything related in one place
2. **README files** - Explain what's in each folder
3. **Consistent structure** - Same layout for every finding
4. **Clear naming** - No "Screenshot1.png" nonsense
5. **Link everything** - Cross-reference in [[THICK-03-Request-Tracker]]

---

## Tags
#evidence #documentation #screenshots #poc #thick-client

---

## Related Documents
- [[THICK-00-Overview|Overview]]
- [[THICK-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[THICK-03-Request-Tracker|Request Tracker]]
- [[THICK-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
