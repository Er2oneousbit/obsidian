### 🧠 **AI / LLM Security**

- **Prompt Injection**: Manipulating model behavior via crafted input.
- **Data Poisoning**: Corrupting training data to influence model output.
- **Model Inversion**: Reconstructing training data from model outputs.
- **Membership Inference**: Identifying if specific data was used in training.
- **Hallucination**: LLM generating false or misleading information.
- **Guardrails**: Safety mechanisms to restrict harmful model outputs.
- **Retrieval-Augmented Generation (RAG)**: Combining LLMs with external data sources.
- **LLM Agent**: Autonomous system using LLMs and tools to complete tasks.
- **Model Context Protocol (MCP)**: Standard for connecting LLMs to external tools.
- **Embedding**: Vector representation of text for semantic search or similarity.

---

### 🔌 **API / SOAP / REST**

- **OpenAPI**: Specification format for REST API documentation.
- **Swagger**: Toolset for designing and documenting REST APIs.
- **Web Services Description Language (WSDL)**: XML-based descriptor for SOAP services.
- **Server-Side Request Forgery (SSRF)**: Abuse of server to make internal/external requests.
- **Mass Assignment**: Overwriting sensitive fields via unrestricted input binding.
- **Broken Object Level Authorization (BOLA)**: Unauthorized access to objects via ID manipulation.
- **Rate Limiting**: Restricting request frequency to prevent abuse.
- **JSON Web Token (JWT)**: Compact token format for authentication and authorization.
- **OAuth2**: Authorization framework for delegated access.
- **API Gateway**: Centralized entry point for managing API traffic.
- **GraphQL**: Query language for APIs with introspection and nested query risks.
- **Cross-Origin Resource Sharing (CORS)**: Browser policy controlling cross-domain requests.

---

### 🖥️ **Thick Client / Desktop Apps**

- **Binary Reversing**: Analyzing compiled code to understand functionality or find flaws.
- **Dynamic-Link Library (DLL) Injection**: Forcing a DLL into a process to alter behavior.
- **Hardcoded Credentials**: Embedded usernames/passwords in application code.
- **Local Storage Abuse**: Sensitive data stored insecurely on disk or registry.
- **Protocol Analysis**: Capturing and inspecting app traffic for vulnerabilities.
- **Insecure Updates**: Lack of integrity checks or secure channels during software updates.
- **Component Object Model (COM)**: Windows interface for inter-process communication.
- **Distributed COM (DCOM)**: Networked extension of COM for remote communication.
- **Remote Procedure Call (RPC)**: Protocol allowing execution of code on remote systems.
- **ClickOnce**: Microsoft deployment technology for Windows apps.
- **Microsoft Installer (MSI)**: Package format for installing software on Windows.

---

### 🌐 **Web Application Security**

- **Cross-Site Scripting (XSS)**: Injecting scripts into web pages viewed by others.
- **Cross-Site Request Forgery (CSRF)**: Forcing a user to perform actions without consent.
- **SQL Injection (SQLi)**: Manipulating SQL queries via user input.
- **NoSQL Injection**: Exploiting NoSQL query structures via crafted input.
- **DOM-based XSS**: XSS triggered by client-side JavaScript manipulation.
- **Content Security Policy (CSP)**: Header-based protection against XSS and data injection.
- **HTTP Strict Transport Security (HSTS)**: Enforces HTTPS to prevent downgrade attacks.
- **Session Fixation**: Forcing a known session ID onto a user.
- **Clickjacking**: Tricking users into clicking hidden or disguised UI elements.
- **Prototype Pollution**: Modifying `Object.prototype` to affect all JS objects.
- **Business Logic Flaw**: Exploiting unintended workflows or rules in an app.

---

### ☁️ **Cloud Security**

- **Identity and Access Management (IAM)**: Controls who can access what in cloud environments.
- **Role-Based Access Control (RBAC)**: Permissions assigned based on roles.
- **Misconfigured Buckets**: Publicly accessible cloud storage containers.
- **Metadata Service Abuse**: SSRF targeting cloud instance metadata for credentials.
- **Infrastructure as Code (IaC)**: Managing infrastructure via code (e.g., Terraform, CloudFormation).
- **AWS CloudTrail**: Logging service for AWS API activity.
- **AWS GuardDuty**: Threat detection service for AWS environments.
- **Shared Responsibility Model**: Defines cloud provider vs. customer security duties.
- **Lambda Privilege Escalation**: Gaining elevated access via serverless misconfigurations.
- **Key Management Service (KMS)**: Secure storage and usage of encryption keys.
- **Container Escape**: Breaking out of container isolation to access host system.
- **Pod Privilege Escalation**: Gaining elevated access within Kubernetes pods.

---

### 🧰 **General Pentest Concepts**

- **MITRE ATT&CK**: Framework of adversary tactics and techniques.
- **Persistence**: Maintaining access to a compromised system.
- **Command and Control (C2)**: Infrastructure used to control compromised systems.
- **Living off the Land (LotL)**: Using native tools for stealthy attacks.
- **Initial Access**: First foothold into a target environment.
- **Privilege Escalation**: Gaining higher-level access than initially granted.
- **Lateral Movement**: Spreading across systems within a network.
- **Exfiltration**: Stealing data from a target environment.
- **Evasion**: Avoiding detection by security tools.
- **Dradis**: Tool for managing and reporting pentest findings.

---
