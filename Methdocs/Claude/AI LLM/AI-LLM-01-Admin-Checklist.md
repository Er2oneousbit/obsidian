# AI/LLM Admin Checklist

Quick reference for gathering administrative and architectural information before testing begins.

Related: [[AI-LLM-02-Technical-Testing-Checklist]] | [[AI-LLM-00-Overview]]

---

## Pre-Engagement

### Engagement Scope
- [ ] System name/identifier documented
- [ ] Primary use case understood
- [ ] Deployment status confirmed (dev/staging/prod)
- [ ] Testing window scheduled
- [ ] Out-of-scope items documented
- [ ] Emergency contact identified
- [ ] Rules of engagement signed

### Access Provided
- [ ] Test account credentials (username/password/API key)
- [ ] Test account role/permissions documented
- [ ] VPN/network access (if required)
- [ ] Additional accounts for privilege testing
- [ ] Admin account for comparison (read-only)

### Initial Documentation Received
- [ ] Architecture diagram
- [ ] API documentation
- [ ] User documentation
- [ ] Known security controls
- [ ] Previous security assessments
- [ ] Incident response contact

---

## System Architecture Discovery

### Model Information
- [ ] **Model Type**: [LLM / Vision / Multimodal / Agent / RAG / Other]
- [ ] **Model Source**: [GPT-4 / Claude / Llama / Gemini / Custom / Unknown]
- [ ] **Model Version**: ________________
- [ ] **Fine-tuned**: Yes / No / Unknown
- [ ] **Training Data Source**: [Public / Internal / Mixed / Unknown]
- [ ] **Context Window**: ________ tokens (if known)
- [ ] **Temperature Setting**: ________ (if accessible)

### Deployment Architecture
- [ ] **Hosting**: [Cloud / On-prem / Hybrid]
- [ ] **Cloud Provider**: [AWS / Azure / GCP / N/A]
- [ ] **Region**: ________________
- [ ] **Platform**: [SageMaker / Azure ML / Vertex AI / Custom / Other]
- [ ] **Containerized**: Yes / No
- [ ] **Container Registry**: ________________

### Network Position
- [ ] **Internet-facing**: Yes / No
- [ ] **Internal network access**: Yes / No
  - [ ] Scope: ________________
- [ ] **VPC/Network isolation**: Yes / No / Unknown
- [ ] **WAF/CDN present**: Yes / No
  - [ ] Provider: ________________

---

## Access Control & Authentication

### Authentication Mechanisms
- [ ] **Auth required**: Yes / No
- [ ] **Auth type**: [SSO / Username+Password / API Key / OAuth / None]
- [ ] **SSO Provider**: ________________ (if applicable)
- [ ] **MFA enforced**: Yes / No / Optional
- [ ] **Session timeout**: ________ minutes

### Authorization Model
- [ ] **Role-based access**: Yes / No
- [ ] **Roles identified**:
  - [ ] ________________
  - [ ] ________________
  - [ ] ________________
- [ ] **Admin accounts exist**: Yes / No
- [ ] **Service accounts exist**: Yes / No
- [ ] **Can users access others' data**: Yes / No

### Rate Limiting
- [ ] **Rate limiting present**: Yes / No / Unknown
- [ ] **Limits documented**: ________________ requests per ________________
- [ ] **Bypass observed**: Yes / No / Not tested

---

## Interface Mapping

### User-Facing Interfaces
- [ ] **Web UI**: Yes / No
  - URL: ________________
  - Framework: ________________
- [ ] **Mobile app**: Yes / No
  - Platform: [iOS / Android / Both]
  - App name: ________________
- [ ] **API endpoints**: Yes / No
  - Base URL: ________________
  - Documentation: ________________
- [ ] **Chat widget**: Yes / No
  - Embedded on: ________________
- [ ] **Messaging integration**: Yes / No
  - Platform: [Slack / Teams / Discord / Other]
- [ ] **Voice interface**: Yes / No
- [ ] **CLI tool**: Yes / No

### Input Capabilities
- [ ] **Text input**: Yes / No
  - Max length: ________ characters/tokens
- [ ] **File upload**: Yes / No
  - Accepted types: ________________
  - Max size: ________ MB
- [ ] **Image input**: Yes / No
- [ ] **Audio input**: Yes / No
- [ ] **Multi-turn conversation**: Yes / No
- [ ] **Conversation history retained**: Yes / No
  - Duration: ________________

---

## Integration Points (Critical for Exploitation)

### Agentic Capabilities
- [ ] **Can execute code**: Yes / No
  - Languages: ________________
- [ ] **Can make API calls**: Yes / No
- [ ] **Can access tools/functions**: Yes / No
- [ ] **Human approval required**: Always / Sometimes / Never
- [ ] **Tool list documented**: Yes / No

### External Integrations
- [ ] **Web search access**: Yes / No
- [ ] **Email capability**: Yes / No
- [ ] **File system access**: Yes / No
  - Paths: ________________
- [ ] **Database access**: Yes / No
  - Databases: ________________
  - Permissions: [Read / Write / Execute]

### Internal API Access
List all internal APIs/services the AI can access:
- [ ] ________________ - Permissions: ________________
- [ ] ________________ - Permissions: ________________
- [ ] ________________ - Permissions: ________________

### RAG/Knowledge Base
- [ ] **Uses RAG**: Yes / No
- [ ] **Vector database**: ________________
- [ ] **Document sources**:
  - [ ] ________________
  - [ ] ________________
- [ ] **Real-time web access**: Yes / No
- [ ] **Can query internal docs**: Yes / No

---

## Data Handling

### Sensitive Data Types
System has access to (check all that apply):
- [ ] PII (Personally Identifiable Information)
- [ ] PHI (Protected Health Information)
- [ ] PCI (Payment Card Information)
- [ ] Credentials/API keys
- [ ] Business confidential data
- [ ] Customer data
- [ ] Financial records
- [ ] Legal documents
- [ ] Source code
- [ ] Other: ________________

### Data Storage
- [ ] **User inputs logged**: Yes / No / Unknown
  - Retention: ________________
- [ ] **Model outputs logged**: Yes / No / Unknown
  - Retention: ________________
- [ ] **Conversation history stored**: Yes / No
  - Location: ________________
- [ ] **Training data location**: ________________
- [ ] **Encryption at rest**: Yes / No / Unknown
- [ ] **Encryption in transit**: Yes / No / Unknown

---

## Security Controls

### Input Validation
- [ ] **Input sanitization present**: Yes / No / Unknown
- [ ] **Blocked keywords/patterns**: Yes / No
  - Examples: ________________
- [ ] **Content filtering**: Yes / No
  - Type: ________________
- [ ] **File type restrictions**: ________________

### Output Handling
- [ ] **Output filtering**: Yes / No / Unknown
  - Type: ________________
- [ ] **Can return code**: Yes / No / Unknown
- [ ] **Can return HTML**: Yes / No / Unknown
- [ ] **Can include user input verbatim**: Yes / No / Unknown
- [ ] **Markdown rendering**: Yes / No

### Monitoring & Logging
- [ ] **Security monitoring**: Yes / No / Unknown
- [ ] **Anomaly detection**: Yes / No
  - Type: ________________
- [ ] **SIEM integration**: Yes / No
- [ ] **Failed request logging**: Yes / No
- [ ] **Alerting configured**: Yes / No
  - Alert triggers: ________________

---

## Business Context

### Risk Assessment
- [ ] **Business criticality**: [Low / Medium / High / Critical]
- [ ] **User base size**: ________________
- [ ] **Customer-facing**: Yes / No
- [ ] **Revenue-generating**: Yes / No
- [ ] **Regulatory compliance required**: Yes / No
  - Regulations: ________________

### Impact Scenarios
- [ ] **Can approve financial transactions**: Yes / No
- [ ] **Can modify user data**: Yes / No
- [ ] **Can access production systems**: Yes / No
- [ ] **Can provide pricing/discounts**: Yes / No
- [ ] **Makes automated decisions**: Yes / No
  - Decision types: ________________

---

## Development & Operations

### Development Team
- [ ] **Security champion identified**: Yes / No
  - Contact: ________________
- [ ] **AI/ML team contact**: ________________
- [ ] **DevOps contact**: ________________
- [ ] **Incident response contact**: ________________

### Security Posture
- [ ] **Previous pentests**: Yes / No
  - Date: ________________
  - Critical findings: ________________
- [ ] **Bug bounty program**: Yes / No
- [ ] **Security training for AI**: Yes / No
- [ ] **Incident response plan (AI-specific)**: Yes / No
- [ ] **Rollback capability**: Yes / No

### CI/CD Pipeline
- [ ] **Code repository**: [GitHub / GitLab / BitBucket / Other]
- [ ] **Dependency scanning**: Yes / No / Unknown
- [ ] **Container scanning**: Yes / No / Unknown
- [ ] **Secrets management**: ________________
- [ ] **Model versioning**: Yes / No

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

### Special Notes
________________
________________
________________

---

## Initial Observations

### First Impressions
- [ ] System appears to use: ________________
- [ ] Obvious security controls: ________________
- [ ] Potential weak points: ________________
- [ ] Interesting behaviors: ________________

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
- [ ] Ready to proceed to [[AI-LLM-02-Technical-Testing-Checklist|Technical Testing]]

---

## Tags
#admin #discovery #scoping #ai-testing

---

## Related Documents
- [[AI-LLM-00-Overview|Overview]]
- [[AI-LLM-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[AI-LLM-03-Payload-Tracker|Payload Tracker]]

---
*Created: 2026-01-21*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
