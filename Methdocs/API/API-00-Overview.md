#api-testing #rest #graphql #soap #grpc #websocket #owasp #methodology #checklist

# API Penetration Testing Overview

Comprehensive methodology for assessing API security vulnerabilities, with focus on authentication, authorization, data exposure, and business logic flaws.

> [!note] Per-Engagement Setup
> Copy the entire `Methdocs/API/` folder into `_Pentest Artifacts/[EngagementName]/` before testing begins. Fill in and track everything there — never edit the master templates directly.

---

## Engagement Workflow

1. Complete [[API-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[API-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[API-03-Request-Tracker|Request Tracker]]
4. Capture evidence per [[API-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[API-05-Reporting-Template|Reporting Template]]
6. Use [[API-06-Quick-Reference|Quick Reference]] for fast payload lookup during active testing

---

## Document Structure

| File | Purpose |
|------|---------|
| [[API-01-Admin-Checklist]] | Pre-engagement — scope, access, architecture, auth model |
| [[API-02-Technical-Testing-Checklist]] | 8-phase hands-on testing methodology |
| [[API-03-Request-Tracker]] | Log all requests, payloads, and findings |
| [[API-04-Evidence-Collection]] | Screenshot and evidence tracking per finding |
| [[API-05-Reporting-Template]] | Standardized finding write-up and report structure |
| [[API-06-Quick-Reference]] | Fast lookup — payloads, attack patterns, cURL templates |

---

## API Types Covered

### REST APIs
- JSON/XML payloads
- HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Standard authentication (Bearer tokens, API keys)

### GraphQL APIs
- Query/mutation/subscription testing
- Introspection attacks
- Batching and aliasing abuse
- Nested query DoS

### SOAP APIs
- XML-based messaging
- WSDL enumeration
- XXE vulnerabilities
- XPath injection in authentication
- SOAPAction header manipulation
- WS-Security token attacks

### gRPC APIs
- Protocol Buffers (protobuf) serialization
- Reflection service enumeration
- BOLA testing via grpcurl
- Input validation and injection in proto fields
- Authentication metadata testing

### WebSocket APIs
- Real-time bidirectional communication
- Message injection
- Session hijacking

---

## OWASP API Security Top 10 (2023)

| # | Category | Key Risk |
|---|----------|---------|
| API1 | Broken Object Level Authorization (BOLA) | Users access other users' data via predictable IDs — most common critical finding |
| API2 | Broken Authentication | Weak credentials, missing token validation, credential stuffing |
| API3 | Broken Object Property Level Authorization | Mass assignment, excessive data exposure in responses |
| API4 | Unrestricted Resource Consumption | No rate limits, no pagination, resource exhaustion |
| API5 | Broken Function Level Authorization | Regular users invoking admin-only endpoints |
| API6 | Unrestricted Access to Sensitive Business Flows | Automating workflows, bypassing business logic, bulk abuse |
| API7 | Server-Side Request Forgery (SSRF) | API makes unvalidated requests internally, cloud metadata exposure |
| API8 | Security Misconfiguration | Verbose errors, CORS wildcards, unnecessary HTTP methods, missing headers |
| API9 | Improper Inventory Management | Undocumented endpoints, accessible old API versions, shadow APIs |
| API10 | Unsafe Consumption of APIs | Trusting third-party API data without validation, blind redirects |

Reference: [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

## Testing Methodology

The full methodology is broken into 8 phases in [[API-02-Technical-Testing-Checklist]]. Summary:

| Phase | Focus |
|-------|-------|
| Phase 1 | Reconnaissance — endpoint discovery, spec analysis, version enumeration |
| Phase 2 | Authentication — JWT attacks, credential brute force, token analysis |
| Phase 3 | Authorization — BOLA/IDOR, BFLA, horizontal/vertical privilege escalation |
| Phase 4 | Input Validation — SQLi, NoSQL injection, XXE, mass assignment, parameter pollution |
| Phase 5 | Business Logic — workflow bypass, payment abuse, race conditions |
| Phase 6 | Rate Limiting — brute force resilience, resource exhaustion, header bypass |
| Phase 7 | Security Headers & Config — CORS, TLS, error disclosure, HTTP method abuse |
| Phase 8 | Advanced — SSRF, GraphQL attacks, SOAP/gRPC, inventory management |

---

## Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Primary proxy — intercept, repeat, intruder, scanner |
| Postman / Insomnia | API collections, environment variables, automated flows |
| ffuf | Endpoint and parameter fuzzing |
| Arjun | Hidden parameter discovery |
| Kiterunner | API-aware endpoint discovery (routes/wordlists) |
| jwt_tool | JWT decode, brute force, algorithm confusion attacks |
| sqlmap | Automated SQL injection detection and exploitation |
| grpcurl | gRPC enumeration and testing via reflection |
| SoapUI | SOAP/WSDL-based API testing |
| nuclei | Template-based vulnerability scanning |
| httpx | HTTP probing, response analysis at scale |
| hashcat | JWT secret brute force, credential cracking |
| SecLists | Wordlists — API endpoints, parameters, payloads |
| Python requests | Custom scripted testing and PoC automation |

---

## Related Documents
- [[API-01-Admin-Checklist|Admin Checklist]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]
- [[API-04-Evidence-Collection|Evidence Collection]]
- [[API-05-Reporting-Template|Reporting Template]]
- [[API-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-21*
*Updated: 2026-03-05*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.6*
