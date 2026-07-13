# API Penetration Testing Overview

## Purpose
Comprehensive methodology for assessing API security vulnerabilities, with focus on authentication, authorization, data exposure, and business logic flaws.

## Document Structure
- [[API-01-Admin-Checklist]] - Pre-engagement information gathering
- [[API-02-Technical-Testing-Checklist]] - Hands-on testing methodology
- [[API-03-Request-Tracker]] - Document successful/failed requests and payloads
- [[API-04-Evidence-Collection]] - Screenshot and evidence tracking
- [[API-05-Reporting-Template]] - Finding documentation structure
- [[API-06-Quick-Reference]] - Fast lookup for common attacks

## Engagement Workflow
1. Complete [[API-01-Admin-Checklist|Admin Checklist]] during kickoff/discovery
2. Use [[API-02-Technical-Testing-Checklist|Technical Checklist]] for systematic testing
3. Log all attempts in [[API-03-Request-Tracker|Request Tracker]]
4. Capture evidence per [[API-04-Evidence-Collection|Evidence Collection]]
5. Document findings using [[API-05-Reporting-Template|Reporting Template]]

## Key Concepts

### Attack Surface Areas
- **Authentication** - Token theft, session hijacking, credential stuffing
- **Authorization** - BOLA/IDOR, privilege escalation, function-level access control
- **Data Exposure** - Excessive data exposure, sensitive data in responses
- **Input Validation** - Injection attacks, mass assignment, parameter pollution
- **Rate Limiting** - Resource exhaustion, brute force, scraping
- **Business Logic** - Workflow manipulation, pricing abuse, state confusion

### OWASP API Security Top 10 (2023)

**API1:2023 - Broken Object Level Authorization (BOLA)**
- Users accessing other users' data via predictable IDs
- Most common and critical API vulnerability

**API2:2023 - Broken Authentication**
- Weak credential policies
- Credential stuffing vulnerabilities
- Missing or improper token validation

**API3:2023 - Broken Object Property Level Authorization**
- Mass assignment vulnerabilities
- Excessive data exposure in responses

**API4:2023 - Unrestricted Resource Access**
- Missing rate limits
- Lack of pagination
- Resource exhaustion attacks

**API5:2023 - Broken Function Level Authorization**
- Accessing admin functions as regular user
- Missing authorization checks on sensitive operations

**API6:2023 - Unrestricted Access to Sensitive Business Flows**
- Automating critical workflows
- Bypassing intended business logic
- Bulk operations on sensitive data

**API7:2023 - Server Side Request Forgery (SSRF)**
- API making unvalidated requests to internal resources
- Cloud metadata exposure

**API8:2023 - Security Misconfiguration**
- Verbose error messages
- CORS misconfiguration
- Unnecessary HTTP methods enabled
- Missing security headers

**API9:2023 - Improper Inventory Management**
- Undocumented endpoints
- Old API versions still accessible
- Shadow APIs

**API10:2023 - Unsafe Consumption of APIs**
- Trusting third-party API data without validation
- Following redirects blindly

Reference: [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

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

### WebSocket APIs
- Real-time bidirectional communication
- Message injection
- Session hijacking

## Tools
- Burp Suite (primary)
- Postman/Insomnia (collections and automation)
- Custom Python scripts (requests library)
- Arjun (parameter discovery)
- Kiterunner (endpoint discovery)
- ffuf/wfuzz (fuzzing)
- jwt_tool (JWT analysis)
- GraphQL introspection tools
- SecLists (wordlists)

## Testing Methodology

### 1. Discovery Phase
- Map all endpoints
- Identify authentication mechanisms
- Enumerate parameters
- Document API specification (if available)

### 2. Authentication Testing
- Test credential policies
- Analyze token structure
- Session management review
- Multi-factor authentication bypass attempts

### 3. Authorization Testing
- BOLA/IDOR testing (most critical)
- Horizontal privilege escalation
- Vertical privilege escalation
- Function-level authorization

### 4. Input Validation
- Injection testing (SQL, NoSQL, Command, XXE)
- Mass assignment
- Type confusion
- Parameter pollution

### 5. Business Logic Testing
- Workflow manipulation
- Rate limit bypass
- Pricing/payment abuse
- State management flaws

### 6. Information Disclosure
- Verbose error messages
- Sensitive data in responses
- API version disclosure
- Internal path disclosure

## Tags for Obsidian
#api-testing #rest #graphql #owasp #methodology #checklist

---
*Last Updated: 2026-01-21*
*Owner: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
