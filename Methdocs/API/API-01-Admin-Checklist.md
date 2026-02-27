# API Admin Checklist

Quick reference for gathering administrative and architectural information before testing begins.

Related: [[API-02-Technical-Testing-Checklist]] | [[API-00-Overview]]

---

## Pre-Engagement

### Engagement Scope
- [ ] API name/identifier documented
- [ ] Primary business function understood
- [ ] Deployment status confirmed (dev/staging/prod)
- [ ] Testing window scheduled
- [ ] Out-of-scope endpoints documented
- [ ] Emergency contact identified
- [ ] Rules of engagement signed
- [ ] Data handling restrictions noted

### Access Provided
- [ ] Test account credentials (multiple roles if possible)
- [ ] API keys/tokens
- [ ] Documentation (Swagger/OpenAPI spec, Postman collection)
- [ ] VPN/network access (if required)
- [ ] Admin account for comparison (read-only)
- [ ] Rate limit exceptions (if needed for testing)

### Initial Documentation Received
- [ ] API specification (OpenAPI/Swagger, RAML, etc.)
- [ ] Authentication/authorization model
- [ ] Known security controls
- [ ] Previous security assessments
- [ ] Incident response contact
- [ ] API versioning strategy

---

## API Architecture Discovery

### API Type & Technology
- [ ] **API Type**: [REST / GraphQL / SOAP / gRPC / WebSocket / Other]
- [ ] **Data Format**: [JSON / XML / Protocol Buffers / Other]
- [ ] **API Gateway**: [Kong / Apigee / AWS API Gateway / Azure APIM / None / Unknown]
- [ ] **Framework**: [Express / Django / Spring Boot / .NET / Laravel / Other]
- [ ] **Language**: [Node.js / Python / Java / C# / PHP / Go / Ruby / Other]

### Deployment Architecture
- [ ] **Hosting**: [Cloud / On-prem / Hybrid]
- [ ] **Cloud Provider**: [AWS / Azure / GCP / N/A]
- [ ] **Region**: ________________
- [ ] **Container Platform**: [Docker / Kubernetes / ECS / AKS / None]
- [ ] **Serverless**: Yes / No
  - [ ] Platform: [Lambda / Azure Functions / Cloud Functions / N/A]

### Network Position
- [ ] **Internet-facing**: Yes / No
- [ ] **Internal network access**: Yes / No
  - [ ] Scope: ________________
- [ ] **VPC/Network isolation**: Yes / No / Unknown
- [ ] **WAF present**: Yes / No
  - [ ] Provider: [Cloudflare / AWS WAF / Azure WAF / Akamai / Other]
- [ ] **CDN**: Yes / No
  - [ ] Provider: ________________
- [ ] **Load Balancer**: Yes / No
  - [ ] Type: ________________

---

## Authentication & Authorization

### Authentication Mechanisms
- [ ] **Auth required**: Yes / No / Partial
- [ ] **Auth type**: [OAuth 2.0 / JWT / API Key / Basic Auth / Session Cookie / mTLS / None]
- [ ] **OAuth flow**: [Authorization Code / Client Credentials / Implicit / Password / N/A]
- [ ] **Token location**: [Header / Query param / Cookie]
- [ ] **Token format**: [JWT / Opaque / Other]
- [ ] **SSO Integration**: Yes / No
  - [ ] Provider: ________________
- [ ] **MFA enforced**: Yes / No / Optional

### JWT Details (if applicable)
- [ ] **Algorithm**: [RS256 / HS256 / ES256 / Other]
- [ ] **Claims documented**: Yes / No
- [ ] **Token expiration**: ________ minutes/hours
- [ ] **Refresh tokens**: Yes / No
- [ ] **Token signing key**: [Symmetric / Asymmetric]

### API Key Details (if applicable)
- [ ] **Key location**: [Header / Query param]
- [ ] **Key rotation**: Yes / No
  - [ ] Frequency: ________________
- [ ] **Key scope**: [Per-user / Per-app / Global]

### Authorization Model
- [ ] **Authorization type**: [RBAC / ABAC / ACL / Claims-based / None]
- [ ] **Roles identified**:
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
  - [ ] ________________ (permissions: ________________)
- [ ] **Permission granularity**: [Endpoint-level / Resource-level / Field-level]
- [ ] **Admin role exists**: Yes / No
- [ ] **Service accounts exist**: Yes / No
- [ ] **Cross-user data access**: Possible / Restricted / Unknown

### Session Management
- [ ] **Session tokens used**: Yes / No
- [ ] **Session timeout**: ________ minutes
- [ ] **Concurrent sessions**: Allowed / Blocked
- [ ] **Session invalidation**: Logout endpoint exists / N/A

---

## API Inventory & Documentation

### API Specification
- [ ] **Spec available**: Yes / No
- [ ] **Spec format**: [OpenAPI/Swagger / RAML / API Blueprint / GraphQL Schema / WSDL / None]
- [ ] **Spec version**: ________________
- [ ] **Spec location**: ________________
- [ ] **Spec accuracy**: [Up-to-date / Outdated / Unknown]

### Versioning
- [ ] **API versions in use**: ________________
- [ ] **Version location**: [URL path / Header / Query param / None]
- [ ] **Old versions accessible**: Yes / No / Unknown
- [ ] **Version deprecation policy**: ________________

### Endpoint Inventory
Total endpoints documented: ________

**Critical Endpoints** (High-value targets):
- [ ] ________________ (Function: ________________)
- [ ] ________________ (Function: ________________)
- [ ] ________________ (Function: ________________)

**Public vs Private**:
- [ ] Public (unauthenticated): ________ endpoints
- [ ] Authenticated: ________ endpoints
- [ ] Admin-only: ________ endpoints

---

## Rate Limiting & Throttling

### Rate Limit Configuration
- [ ] **Rate limiting present**: Yes / No / Unknown
- [ ] **Limit type**: [Per-user / Per-IP / Per-API-key / Global]
- [ ] **Limits**:
  - [ ] Requests per second: ________
  - [ ] Requests per minute: ________
  - [ ] Requests per hour: ________
  - [ ] Requests per day: ________
- [ ] **Rate limit headers**: Present / Absent
  - [ ] Headers: ________________
- [ ] **Behavior on exceed**: [429 response / Temporary ban / Permanent ban / Unknown]
- [ ] **Rate limit bypass observed**: Yes / No / Not tested

### Resource Limits
- [ ] **Request size limit**: ________ KB/MB
- [ ] **Response size limit**: ________ KB/MB
- [ ] **Timeout**: ________ seconds
- [ ] **Pagination**: Required / Optional / None
  - [ ] Max page size: ________

---

## Data Handling

### Data Classification
API has access to (check all that apply):
- [ ] PII (Personally Identifiable Information)
- [ ] PHI (Protected Health Information)
- [ ] PCI (Payment Card Information)
- [ ] Authentication credentials
- [ ] API keys/secrets
- [ ] Business confidential data
- [ ] Customer data
- [ ] Financial records
- [ ] Legal documents
- [ ] User-generated content
- [ ] Other: ________________

### Data Storage & Logging
- [ ] **Request logging**: Yes / No / Unknown
  - [ ] Retention: ________________
  - [ ] Logged fields: ________________
- [ ] **Response logging**: Yes / No / Unknown
  - [ ] Retention: ________________
- [ ] **Sensitive data in logs**: Yes / No / Unknown
- [ ] **Database type**: [PostgreSQL / MySQL / MongoDB / DynamoDB / SQL Server / Other]
- [ ] **Encryption at rest**: Yes / No / Unknown
- [ ] **Encryption in transit**: Yes / No / Unknown (should always be HTTPS)

### Data Exposure in Responses
- [ ] **Excessive data in responses**: Yes / No / To be tested
- [ ] **Sensitive fields returned**: ________________
- [ ] **Response filtering available**: Yes / No
- [ ] **Field-level permissions**: Yes / No

---

## Security Controls

### Input Validation
- [ ] **Input validation present**: Yes / No / Unknown
- [ ] **Validation type**: [Whitelist / Blacklist / Schema-based / None]
- [ ] **Parameter types enforced**: Yes / No / Unknown
- [ ] **Max length enforcement**: Yes / No
- [ ] **Special character handling**: ________________
- [ ] **Content-Type validation**: Yes / No
- [ ] **File upload allowed**: Yes / No
  - [ ] Allowed types: ________________
  - [ ] Max size: ________ MB

### Output Encoding
- [ ] **Output encoding**: Yes / No / Unknown
- [ ] **HTML encoding**: Yes / No / N/A
- [ ] **JSON escaping**: Yes / No
- [ ] **Error message sanitization**: Yes / No

### HTTP Security Headers
- [ ] **HSTS**: Present / Absent
- [ ] **X-Content-Type-Options**: Present / Absent
- [ ] **X-Frame-Options**: Present / Absent
- [ ] **Content-Security-Policy**: Present / Absent
- [ ] **CORS configuration**: ________________
  - [ ] Wildcard origins: Yes / No
  - [ ] Credentials allowed: Yes / No

### Monitoring & Logging
- [ ] **Security monitoring**: Yes / No / Unknown
- [ ] **Anomaly detection**: Yes / No
  - [ ] Type: ________________
- [ ] **SIEM integration**: Yes / No
- [ ] **Failed request logging**: Yes / No
- [ ] **Alerting configured**: Yes / No
  - [ ] Alert triggers: ________________
- [ ] **Audit logging**: Yes / No
  - [ ] Fields logged: ________________

---

## Integration Points

### Third-Party APIs
- [ ] **Calls external APIs**: Yes / No
- [ ] **External APIs**:
  - [ ] ________________ (Purpose: ________________)
  - [ ] ________________ (Purpose: ________________)
- [ ] **Webhook support**: Yes / No
  - [ ] Webhook validation: ________________

### Database Access
- [ ] **Direct database queries**: Yes / No
- [ ] **ORM used**: [Yes - specify: ________ / No]
- [ ] **Stored procedures**: Yes / No
- [ ] **Database permissions**: [Read / Write / Execute / Admin]

### Message Queues / Event Streams
- [ ] **Uses message queue**: Yes / No
  - [ ] Technology: [RabbitMQ / Kafka / SQS / Azure Service Bus / Other]
- [ ] **Event-driven architecture**: Yes / No

### Microservices
- [ ] **Microservices architecture**: Yes / No
- [ ] **Service mesh**: Yes / No
  - [ ] Technology: [Istio / Linkerd / Consul / Other]
- [ ] **Inter-service auth**: [mTLS / API keys / None / Unknown]

---

## Business Context

### API Purpose & Functionality
- [ ] **Primary function**: ________________
- [ ] **User base size**: ________________
- [ ] **Customer-facing**: Yes / No
- [ ] **Revenue-generating**: Yes / No
- [ ] **Business criticality**: [Low / Medium / High / Critical]
- [ ] **Regulatory compliance required**: Yes / No
  - [ ] Regulations: [HIPAA / PCI-DSS / GDPR / SOX / Other]

### High-Value Operations
List operations that are most critical or dangerous:
- [ ] ________________ (Impact: ________________)
- [ ] ________________ (Impact: ________________)
- [ ] ________________ (Impact: ________________)

### Impact Scenarios
- [ ] **Can approve financial transactions**: Yes / No
- [ ] **Can modify user data**: Yes / No
- [ ] **Can delete data**: Yes / No
- [ ] **Can access production systems**: Yes / No
- [ ] **Can trigger notifications/emails**: Yes / No
- [ ] **Makes automated decisions**: Yes / No
  - [ ] Decision types: ________________

---

## Development & Operations

### Development Team
- [ ] **Security champion identified**: Yes / No
  - [ ] Contact: ________________
- [ ] **API team contact**: ________________
- [ ] **DevOps contact**: ________________
- [ ] **Incident response contact**: ________________

### Security Posture
- [ ] **Previous pentests**: Yes / No
  - [ ] Date: ________________
  - [ ] Critical findings: ________________
- [ ] **Bug bounty program**: Yes / No
- [ ] **API security training**: Yes / No
- [ ] **Incident response plan (API-specific)**: Yes / No
- [ ] **Rollback capability**: Yes / No
- [ ] **Blue team notification process**: ________________

### CI/CD Pipeline
- [ ] **Code repository**: [GitHub / GitLab / BitBucket / Other]
- [ ] **API testing in pipeline**: Yes / No
  - [ ] Tools: ________________
- [ ] **Dependency scanning**: Yes / No
- [ ] **Container scanning**: Yes / No
- [ ] **SAST/DAST**: Yes / No
  - [ ] Tools: ________________
- [ ] **Secrets management**: [Vault / AWS Secrets Manager / Azure Key Vault / Environment variables / Other]

---

## GraphQL-Specific (if applicable)

### GraphQL Configuration
- [ ] **GraphQL version**: ________________
- [ ] **Introspection enabled**: Yes / No / Unknown
- [ ] **Query depth limit**: ________ (or unlimited)
- [ ] **Query complexity limit**: ________ (or unlimited)
- [ ] **Batching allowed**: Yes / No
- [ ] **Aliasing allowed**: Yes / No
- [ ] **Max query length**: ________ characters

### GraphQL Security
- [ ] **Field-level authorization**: Yes / No
- [ ] **Query cost analysis**: Yes / No
- [ ] **Persistent queries only**: Yes / No
- [ ] **Automatic persisted queries**: Yes / No

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
- [ ] API appears to use: ________________
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
- [ ] Burp configured and traffic capturing
- [ ] Postman collection imported (if provided)
- [ ] Ready to proceed to [[API-02-Technical-Testing-Checklist|Technical Testing]]

---

## Tags
#admin #discovery #scoping #api-testing

---

## Related Documents
- [[API-00-Overview|Overview]]
- [[API-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[API-03-Request-Tracker|Request Tracker]]

---
*Created: 2026-01-21*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
