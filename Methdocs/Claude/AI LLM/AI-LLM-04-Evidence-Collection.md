# AI/LLM Evidence Collection Guide

Systematic approach to capturing, organizing, and documenting evidence during AI/LLM penetration testing. Proper evidence collection is critical for report writing and demonstrating impact to stakeholders.

Related: [[AI-LLM-02-Technical-Testing-Checklist]] | [[AI-LLM-03-Payload-Tracker]] | [[AI-LLM-05-Reporting-Template]]

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
- Include **full context** (URL bar, timestamps visible)
- Show **complete request/response** when relevant
- Capture **error messages** verbatim
- Document **exact steps** to reproduce

---

## File Naming Convention

**Format**: `[EngagementID]_[Category]_[FindingID]_[SequenceNumber]_[Description].png`

**Examples**:
- `ACME_SystemPrompt_F001_01_Initial-Request.png`
- `ACME_SystemPrompt_F001_02_Partial-Leak.png`
- `ACME_ToolAbuse_F003_01_Code-Execution.png`
- `ACME_BizLogic_F005_01_Before-Discount.png`
- `ACME_BizLogic_F005_02_After-Discount.png`

**Benefits**:
- Sorts chronologically
- Groups by finding
- Self-documenting
- Easy to reference in report

---

## Screenshot Checklist

### Every Screenshot Should Include

- [ ] **Visible URL/endpoint** (if web-based)
- [ ] **Timestamp** (system clock or app timestamp)
- [ ] **User account** (show who's logged in)
- [ ] **Full context** (don't crop critical info)
- [ ] **Readable text** (zoom if needed, use high DPI)
- [ ] **Relevant UI elements** (buttons clicked, dropdowns selected)

### Screenshots to ALWAYS Capture

- [ ] Initial system behavior (baseline)
- [ ] Attack payload being sent
- [ ] Successful exploitation result
- [ ] Any error messages or warnings
- [ ] Privilege escalation proof (before/after)
- [ ] Data exfiltration proof
- [ ] Business impact (pricing changes, unauthorized access, etc)

---

## Evidence Categories

### Initial Interface

**Purpose**: Document starting point and normal behavior

**Captures**:
- [ ] Login page (if applicable)
- [ ] Main chat/interaction interface
- [ ] Settings/configuration options visible
- [ ] Initial greeting or default response
- [ ] Network traffic in Burp (baseline)

**Naming**: `[Engagement]_Initial_[Sequence]_[Description].png`

**Example**:
```
ACME_Initial_01_Login-Page.png
ACME_Initial_02_Main-Interface.png
ACME_Initial_03_Burp-Baseline-Traffic.png
```

---

### System Prompt Extraction

**Purpose**: Document system prompt disclosure

**Captures**:
- [ ] Injection payload in input field
- [ ] Full response showing leaked prompt
- [ ] Multiple attempts (if incremental extraction)
- [ ] Burp request/response showing exact payload
- [ ] Any partial leaks (even fragments are valuable)

**Critical Details**:
- Highlight leaked text
- Show full payload used
- Capture timestamp of successful extraction
- Document any filtering bypassed

**Naming**: `[Engagement]_SystemPrompt_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_SystemPrompt_F001_01_Injection-Attempt.png
ACME_SystemPrompt_F001_02_Partial-Leak.png
ACME_SystemPrompt_F001_03_Full-Response.png
ACME_SystemPrompt_F001_04_Burp-Request.png
```

**Reference**: Link to [[AI-LLM-03-Payload-Tracker|Payload Tracker]] entry (e.g., PT-003)

---

### Guardrail Bypasses

**Purpose**: Show content filtering was circumvented

**Captures**:
- [ ] Normal request getting blocked (baseline)
- [ ] Bypass payload being sent
- [ ] Successful bypass response
- [ ] Side-by-side comparison (blocked vs bypassed)

**Critical Details**:
- Show refusal message (before)
- Show bypass technique
- Show successful response (after)
- Demonstrate policy violation

**Naming**: `[Engagement]_Bypass_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Bypass_F002_01_Initial-Block.png
ACME_Bypass_F002_02_Encoding-Bypass.png
ACME_Bypass_F002_03_Success.png
```

---

### Prompt Injection

**Purpose**: Demonstrate control over AI behavior

**Captures**:
- [ ] Normal query/response (baseline)
- [ ] Injection payload
- [ ] Manipulated behavior (proof of control)
- [ ] Any unintended actions taken

**Critical Details**:
- Show clear deviation from normal behavior
- Capture exact injection syntax
- Demonstrate instruction override
- Show any cascading effects

**Naming**: `[Engagement]_Injection_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_Injection_F003_01_Normal-Behavior.png
ACME_Injection_F003_02_Injection-Payload.png
ACME_Injection_F003_03_Controlled-Response.png
```

---

### Tool/Function Exploitation

**Purpose**: Document unauthorized tool/function access

**Captures**:
- [ ] Tool enumeration (list of available tools)
- [ ] Exploitation attempt
- [ ] Tool execution result
- [ ] Impact (file read, code exec, API call, etc)
- [ ] Error messages if access denied (for comparison)

**Critical Details**:
- Show tool name and parameters
- Capture output/result
- Demonstrate unauthorized access
- Show data obtained or action performed

**Naming**: `[Engagement]_ToolAbuse_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_ToolAbuse_F004_01_Tool-List.png
ACME_ToolAbuse_F004_02_File-Read-Attempt.png
ACME_ToolAbuse_F004_03_Passwd-File-Contents.png
ACME_ToolAbuse_F004_04_Burp-Request.png
```

**Reference**: Link to [[AI-LLM-03-Payload-Tracker|Payload Tracker]] entry

---

### File-Based Injection

**Purpose**: Show malicious file processing

**Captures**:
- [ ] File upload interface
- [ ] File contents (show embedded payload)
- [ ] Upload confirmation
- [ ] Query that triggers injection
- [ ] Exploited behavior result

**Critical Details**:
- Screenshot of file contents before upload
- Upload process
- Trigger mechanism
- Result of processing malicious file

**Naming**: `[Engagement]_FileInject_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_FileInject_F005_01_Malicious-File-Contents.png
ACME_FileInject_F005_02_Upload-Interface.png
ACME_FileInject_F005_03_Trigger-Query.png
ACME_FileInject_F005_04_Injected-Response.png
```

---

### Business Logic Flaws

**Purpose**: Demonstrate financial or access control impact

**Captures**:
- [ ] **Before state** (legitimate price/access level)
- [ ] Exploitation payload
- [ ] **After state** (manipulated price/elevated access)
- [ ] Proof of impact (receipt, access to restricted data, etc)

**Critical Details**:
- Clear before/after comparison
- Dollar amounts visible (if financial)
- Access levels shown (if privilege escalation)
- Transaction confirmation

**Naming**: `[Engagement]_BizLogic_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_BizLogic_F006_01_Original-Price-$99.png
ACME_BizLogic_F006_02_Discount-Request.png
ACME_BizLogic_F006_03_Price-Changed-$0.png
ACME_BizLogic_F006_04_Order-Confirmation.png
```

---

### Data Exfiltration

**Purpose**: Prove sensitive data disclosure

**Captures**:
- [ ] Query requesting sensitive data
- [ ] Response containing PII/PHI/secrets
- [ ] Highlight sensitive fields
- [ ] Volume of data (if bulk extraction)

**Critical Details**:
- Redact real PII in screenshots (use test data or blur)
- Show data classification/sensitivity
- Demonstrate scope of disclosure
- Capture access logs (if available)

**Naming**: `[Engagement]_DataExfil_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_DataExfil_F007_01_Query-All-Users.png
ACME_DataExfil_F007_02_PII-Disclosed-REDACTED.png
ACME_DataExfil_F007_03_Burp-Response.png
```

**IMPORTANT**: Always redact real PII/PHI in evidence!

---

### RAG Poisoning

**Purpose**: Document knowledge base contamination

**Captures**:
- [ ] Malicious document contents
- [ ] Upload/indexing process
- [ ] Query that retrieves poisoned content
- [ ] Manipulated response based on poisoned data
- [ ] Persistence check (still works after time?)

**Critical Details**:
- Show poisoned document
- Timestamp of upload
- Trigger query
- Backdoor activation

**Naming**: `[Engagement]_RAGPoison_F[###]_[Sequence]_[Description].png`

**Example**:
```
ACME_RAGPoison_F008_01_Poisoned-Doc.png
ACME_RAGPoison_F008_02_Upload-Success.png
ACME_RAGPoison_F008_03_Trigger-Query.png
ACME_RAGPoison_F008_04_Backdoor-Active.png
```

---

### Advanced Exploitation

**Purpose**: Complex multi-step attacks

**Captures**:
- [ ] Each step in the chain
- [ ] Intermediate results
- [ ] Final impact
- [ ] Timeline/sequence diagram (if complex)

**Critical Details**:
- Number screenshots in sequence
- Show causal relationship (step 1 enables step 2, etc)
- Demonstrate full attack path
- Highlight critical pivot points

**Naming**: `[Engagement]_Advanced_F[###]_[Step]_[Description].png`

**Example**:
```
ACME_Advanced_F009_Step1_Prompt-Leak.png
ACME_Advanced_F009_Step2_Tool-Discovery.png
ACME_Advanced_F009_Step3_Code-Exec.png
ACME_Advanced_F009_Step4_Data-Exfil.png
ACME_Advanced_F009_Final_Impact-Summary.png
```

---

## Burp Suite Evidence

### What to Export from Burp

- [ ] **Full project file** (`.burp`)
- [ ] **Request/response for each finding** (`.txt` or `.xml`)
- [ ] **Site map** showing scope
- [ ] **Proxy history** (filtered to target)
- [ ] **Scanner results** (if used)
- [ ] **Intruder results** (if applicable)

### Burp Screenshots

**Essential captures**:
- [ ] Request tab showing full payload
- [ ] Response tab showing result
- [ ] Headers (both request and response)
- [ ] Parameters tab (if parameter tampering)
- [ ] Repeater tab (for PoC reproducibility)

**Naming**: `[Engagement]_Burp_F[###]_[ReqResp]_[Description].png`

**Example**:
```
ACME_Burp_F001_Request_System-Prompt-Injection.png
ACME_Burp_F001_Response_Leaked-Prompt.png
ACME_Burp_F003_Request_Tool-Abuse.png
ACME_Burp_F003_Response_Code-Execution.png
```

### Exporting Requests/Responses

**Right-click request in Burp → Save item**:
- Save as: `[Engagement]_Burp_F[###]_Request.txt`
- Include full headers and body
- Save corresponding response
- Keep directory organized by finding

---

## Screen Recording

### When to Record Video

Use screen recording for:
- [ ] Complex multi-step exploits
- [ ] Real-time exploitation (hard to capture in screenshots)
- [ ] Demonstrations for non-technical stakeholders
- [ ] Proof of timing-based attacks
- [ ] Interactive tool abuse

### Recording Best Practices

- **Announce what you're doing** (narrate or text overlay)
- **Show timestamps** clearly
- **Keep recordings short** (2-5 min max per finding)
- **Edit out dead time** (waiting, typos, false starts)
- **Add captions** if no audio narration
- **Export in common format** (MP4, WebM)

**Naming**: `[Engagement]_Video_F[###]_[Description].mp4`

**Example**:
```
ACME_Video_F004_Tool-Abuse-Chain.mp4
ACME_Video_F009_Full-Exploitation-Demo.mp4
```

---

## Evidence Organization

### Directory Structure

```
[Engagement-Name]-Evidence/
├── 01-Initial/
│   ├── ACME_Initial_01_Login-Page.png
│   ├── ACME_Initial_02_Main-Interface.png
│   └── ACME_Initial_03_Burp-Baseline.png
├── 02-Findings/
│   ├── F001-System-Prompt/
│   │   ├── ACME_SystemPrompt_F001_01_Attempt.png
│   │   ├── ACME_SystemPrompt_F001_02_Leak.png
│   │   └── ACME_Burp_F001_Request.txt
│   ├── F002-Guardrail-Bypass/
│   │   └── [screenshots]
│   └── F003-Tool-Abuse/
│       ├── [screenshots]
│       └── ACME_Video_F003_Demo.mp4
├── 03-Burp/
│   ├── ACME_Project.burp
│   └── [exported requests/responses]
├── 04-Payloads/
│   ├── payload-library.txt
│   └── successful-exploits.txt
└── 05-Notes/
    ├── 03-Payload-Tracker.md (copy from Obsidian)
    └── testing-notes.txt
```

---

## Evidence Tracking Table

Use this table to track all evidence collected:

| Finding ID | Finding Name | Evidence Type | Filename(s) | Date Captured | Notes |
|-----------|-------------|--------------|-------------|---------------|-------|
| F001 | System Prompt Leak | Screenshots (3) | ACME_SystemPrompt_F001_*.png | 2026-01-21 | Partial leak, PT-003 |
| F001 | System Prompt Leak | Burp Request | ACME_Burp_F001_Request.txt | 2026-01-21 | Full payload |
| F002 | Guardrail Bypass | Screenshots (2) | ACME_Bypass_F002_*.png | 2026-01-21 | Encoding bypass |
| F003 | Code Execution | Screenshots (4) | ACME_ToolAbuse_F003_*.png | 2026-01-21 | PT-502 |
| F003 | Code Execution | Video | ACME_Video_F003_Demo.mp4 | 2026-01-21 | Full demo |
| | | | | | |

---

## Evidence Quality Checklist

Before finalizing evidence collection:

### Completeness
- [ ] Every finding has at least 2-3 screenshots
- [ ] Critical findings have Burp exports
- [ ] Complex exploits have video demonstrations
- [ ] All evidence is named consistently
- [ ] Directory structure is organized

### Quality
- [ ] All text is readable (no blur, adequate zoom)
- [ ] Context is clear (URLs, timestamps visible)
- [ ] Before/after states captured for comparisons
- [ ] No extraneous desktop clutter in frame
- [ ] Sensitive data redacted appropriately

### Documentation
- [ ] Evidence tracking table populated
- [ ] Each file referenced in [[AI-LLM-03-Payload-Tracker]]
- [ ] Findings mapped to evidence in [[AI-LLM-05-Reporting-Template]]
- [ ] Client-provided data clearly marked
- [ ] Testing timeline documented

---

## Tools for Evidence Collection

### Screenshot Tools
- **Windows**: Snipping Tool, ShareX, Greenshot
- **Linux**: Flameshot, Spectacle, GNOME Screenshot
- **macOS**: Command+Shift+4, Skitch
- **Cross-platform**: Lightshot

### Screen Recording
- **Windows**: OBS Studio, ShareX (video mode)
- **Linux**: OBS Studio, SimpleScreenRecorder, Kazam
- **macOS**: QuickTime, OBS Studio
- **Browser**: Loom, Screencastify (for web-based targets)

### Annotation
- **Markup tools**: Draw arrows, highlight important areas
- **Add text**: Label components, add explanations
- **Redaction**: Black boxes over PII/PHI
- Tools: GIMP, Paint.NET, Preview (macOS), Krita

### Burp Plugins
- **Logger++**: Enhanced logging and filtering
- **Copy As Python-Requests**: Export as reproducible script
- **Flow**: Visualize request sequences

---

## Evidence Retention

### During Engagement
- Keep all evidence on encrypted drive
- Daily backups to separate location
- Don't delete "failed" attempts (might be useful later)
- Maintain chain of custody

### Post-Engagement
- Deliver evidence package to client (encrypted)
- Retain copy per company policy (usually 1-3 years)
- Securely delete after retention period
- Document destruction date

---

## Tips for High-Quality Evidence

### Do
✅ Capture context (full browser window, not just response)
✅ Use high DPI/resolution (text must be readable)
✅ Number sequences for multi-step attacks
✅ Annotate screenshots to highlight key details
✅ Test reproducibility before finalizing
✅ Keep raw and annotated versions

### Don't
❌ Crop out critical context (URLs, timestamps)
❌ Use low-quality compression (keep PNGs sharp)
❌ Mix evidence from different findings in one folder
❌ Forget to capture Burp traffic
❌ Leave real PII/PHI unredacted
❌ Assume you'll remember context later (document NOW)

---

## Evidence Handoff Checklist

Before delivering evidence to client:

- [ ] All evidence organized per directory structure
- [ ] Sensitive data redacted
- [ ] Evidence tracking table complete
- [ ] Burp project file included
- [ ] Payload list included
- [ ] README.txt with structure explanation
- [ ] Evidence package encrypted (7z with password, or similar)
- [ ] Password delivered via separate channel
- [ ] Client confirms receipt

---

## Tags
#evidence #screenshots #documentation #ai-testing #burp

---

## Related Documents
- [[AI-LLM-00-Overview|Overview]]
- [[AI-LLM-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[AI-LLM-03-Payload-Tracker|Payload Tracker]]
- [[AI-LLM-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-21*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
