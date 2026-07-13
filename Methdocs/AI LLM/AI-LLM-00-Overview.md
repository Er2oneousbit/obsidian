# AI/LLM Penetration Testing Overview

## Purpose
Comprehensive methodology for assessing AI/LLM systems for security vulnerabilities, with focus on prompt injection, data leakage, and business logic abuse.

## Document Structure
- [[AI-LLM-01-Admin-Checklist]] - Pre-engagement information gathering
- [[AI-LLM-02-Technical-Testing-Checklist]] - Hands-on testing methodology
- [[AI-LLM-03-Payload-Tracker]] - Document successful/failed payloads
- [[AI-LLM-04-Evidence-Collection]] - Screenshot and evidence tracking
- [[AI-LLM-05-Reporting-Template]] - Finding documentation structure
- [[AI-LLM-06-Quick-Reference]] - Fast lookup for common attacks

## Engagement Workflow
1. Complete [[AI-LLM-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[AI-LLM-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[AI-LLM-03-Payload-Tracker|Payload Tracker]]
4. Capture evidence per [[AI-LLM-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[AI-LLM-05-Reporting-Template|Reporting Template]]

## Key Concepts

### Attack Surface Areas
- **Input Validation** - Prompt injection, delimiter confusion
- **Output Handling** - Data leakage, unsafe rendering
- **Integration Points** - Tool abuse, API exploitation
- **Business Logic** - Pricing manipulation, unauthorized access
- **Training/RAG** - Data poisoning, knowledge base injection

### Common Vulnerability Classes
- LLM01: Prompt Injection
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning
- LLM04: Model Denial of Service
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance
- LLM10: Model Theft

Reference: [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Tools
- Burp Suite (primary)
- Custom payload lists ([[AI-LLM-06-Quick-Reference#Payload Library]])
- Browser dev tools
- Postman/Insomnia (API testing)
- Python scripts (automation)

## Tags for Obsidian
#ai-testing #llm #prompt-injection #methodology #checklist

---
*Last Updated: 2026-01-21*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
