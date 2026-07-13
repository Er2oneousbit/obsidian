

## ✅ **Web & AppSec Vulnerability Checklist**

|**Topic**|**Description**|
|---|---|
|**XSS – Cross-Site Scripting**|Injecting JavaScript into a website to execute in another user’s browser.|
|**CSRF – Cross-Site Request Forgery**|Forcing a logged-in user’s browser to perform unwanted actions.|
|**SQLi – SQL Injection**|Injecting SQL commands to manipulate or extract data from a database.|
|**LFI – Local File Inclusion**|Reading local files on the server via path manipulation.|
|**RFI – Remote File Inclusion**|Including and executing remote files via user-controlled input.|
|**IDOR – Insecure Direct Object Reference**|Accessing unauthorized resources by modifying object identifiers.|
|**SSRF – Server-Side Request Forgery**|Forcing the server to make requests to internal or external systems.|
|**XXE – XML External Entity Injection**|Exploiting XML parsers to read files or perform SSRF.|
|**SSTI – Server-Side Template Injection**|Injecting code into server-side templates for execution.|
|**Command Injection**|Executing system commands via unsanitized user input.|
|**File Upload Vulnerability**|Uploading malicious files (e.g., webshells) due to poor validation.|
|**Web Shells**|Scripts uploaded to a server to provide remote command execution.|
|**JWT Attacks**|Forging or tampering with JSON Web Tokens to bypass auth.|
|**Authentication Attacks**|Brute force, credential stuffing, or bypassing login mechanisms.|
|**Authorization Bypass**|Gaining access to restricted resources without proper permissions.|
|**Open Redirect**|Redirecting users to untrusted sites via manipulated URLs.|
|**Deserialization**|Executing code by manipulating serialized objects passed to the server.|
|**OAuth Misconfigurations**|Exploiting flaws in OAuth flows to hijack accounts or escalate access.|
|**SAML Attacks**|Tampering with SAML assertions to impersonate users.|
|**Clickjacking**|Tricking users into clicking hidden elements using iframes.|
|**CORS Misconfigurations**|Allowing unauthorized cross-origin access to sensitive APIs.|
|**Subdomain Takeover**|Claiming unconfigured subdomains to serve malicious content.|
|**DNS Rebinding**|Bypassing same-origin policies by rebinding DNS to internal IPs.|
|**Race Conditions**|Exploiting timing issues to perform unauthorized actions.|
|**Business Logic Flaws**|Abusing intended functionality to gain unintended access or impact.|

---

## ✅ **SQL Database Testing Checklist (Non-SQLi)**

|**Topic**|**Description**|
|---|---|
|**Authentication Bypass**|Test for weak/default credentials or exposed DB interfaces (e.g., `sa` with no password).|
|**Privilege Escalation**|Identify misconfigured roles or permissions allowing lateral movement or privilege gain.|
|**Stored Procedures Abuse**|Abuse built-in procedures (e.g., `xp_cmdshell`, `xp_dirtree`, `sp_configure`) for code execution or file access.|
|**Linked Servers**|Enumerate and pivot through linked SQL servers using `sp_linkedservers` and `OPENQUERY`.|
|**Command Execution**|Execute OS commands via SQL Server (`xp_cmdshell`, `sp_OACreate`) or MySQL (`sys_exec()`, UDFs).|
|**File Read/Write**|Use functions like `BULK INSERT`, `OPENROWSET`, or `LOAD_FILE()` to read/write local files.|
|**Hash Extraction**|Dump password hashes from system tables (e.g., `sys.sql_logins`, `mysql.user`).|
|**Hash Cracking**|Crack extracted hashes offline (e.g., SQL Server’s SHA1, MySQL’s old/new hash formats).|
|**Database Enumeration**|List databases, tables, columns using `INFORMATION_SCHEMA` or system views.|
|**Data Exfiltration**|Extract sensitive data (e.g., PII, credentials, tokens) from accessible tables.|
|**Audit Bypass**|Identify and disable or evade logging/auditing mechanisms.|
|**Misconfigured Roles**|Look for overly permissive roles (e.g., `db_owner`, `sysadmin`) assigned to low-privilege users.|
|**CLR Abuse (SQL Server)**|Load and execute custom .NET assemblies for advanced post-exploitation.|
|**UDF Abuse (MySQL/Postgres)**|Create or abuse User Defined Functions for code execution or privilege escalation.|
|**Out-of-Band Interaction**|Trigger DNS/HTTP callbacks using SQL functions to confirm blind data access or RCE.|
|**Service Account Abuse**|Use captured NTLM hashes or tokens from SQL service accounts for lateral movement.|
|**Backup/Restore Abuse**|Abuse backup/restore features to overwrite or extract data from other databases.|
|**Job Scheduler Abuse**|Create or hijack scheduled jobs (e.g., SQL Agent Jobs) to execute payloads.|
|**Trust Relationships**|Identify and abuse trust relationships between DBs or domains.|
|**Unpatched Vulnerabilities**|Check for known CVEs in the DBMS version (e.g., MySQL, MSSQL, Oracle, Postgres).|

---

## ✅ **Host & Operating System Testing Checklist**

|**Topic**|**Description**|
|---|---|
|**Local Enumeration**|Gather system info: hostname, OS version, users, groups, network interfaces.|
|**Privilege Escalation**|Identify misconfigurations or exploits to elevate from user to admin/root.|
|**Password Hunting**|Search for plaintext creds in config files, scripts, registry, or memory.|
|**Scheduled Task Abuse**|Hijack or create scheduled tasks (e.g., cron jobs, Windows Task Scheduler) for persistence or execution.|
|**Service Misconfigurations**|Abuse services running as SYSTEM/root or with weak permissions.|
|**Unquoted Service Paths (Windows)**|Exploit services with unquoted paths and writable directories.|
|**SUID/SGID Binaries (Linux)**|Identify and exploit binaries with elevated privileges.|
|**DLL Hijacking (Windows)**|Drop malicious DLLs in paths searched by vulnerable applications.|
|**Startup Folder Persistence**|Drop payloads in user or system startup folders for persistence.|
|**Registry Persistence (Windows)**|Modify registry keys (e.g., `Run`, `RunOnce`) to maintain access.|
|**Log File Poisoning**|Inject payloads into logs for later execution via LFI or other vectors.|
|**AV/EDR Evasion**|Identify and bypass endpoint defenses using LOLBins, obfuscation, or process injection.|
|**Token Impersonation (Windows)**|Steal or impersonate tokens to access other user contexts.|
|**Kerberos Abuse**|Perform attacks like Pass-the-Ticket, Kerberoasting, or AS-REP Roasting.|
|**LSASS Dumping**|Extract credentials from memory using tools like `procdump`, `mimikatz`, or `comsvcs.dll`.|
|**Named Pipe Abuse**|Interact with or impersonate named pipes for privilege escalation or lateral movement.|
|**Mountable Shares**|Enumerate and access SMB/NFS shares for data exfiltration or pivoting.|
|**Firewall/AV Misconfigurations**|Identify overly permissive rules or disabled protections.|
|**Sensitive File Discovery**|Search for `.env`, `.bak`, `.git`, `id_rsa`, `config.xml`, etc.|
|**Command Execution**|Execute commands via exposed services, misconfigured binaries, or scheduled tasks.|
|**Lateral Movement**|Use RDP, WinRM, SSH, or PsExec to move between systems.|
|**Persistence Mechanisms**|Establish long-term access via services, registry, cron, or startup scripts.|

---


## ✅ **Network Testing Checklist (Generalized)**

|**Topic**|**Description**|
|---|---|
|**Host Discovery**|Identify live systems using ping sweeps, ARP scans, or passive monitoring.|
|**Port Scanning**|Enumerate open TCP/UDP ports to identify exposed services.|
|**Service Enumeration**|Fingerprint services (e.g., HTTP, SMB, RDP, SSH) to gather version and banner info.|
|**Network Mapping**|Build a topology of the environment using traceroute, SNMP, or routing tables.|
|**Firewall & ACL Testing**|Identify filtering rules, blocked ports, and segmentation boundaries.|
|**Protocol Analysis**|Inspect protocols (e.g., NetBIOS, mDNS, LLMNR, ICMP) for misconfigurations or abuse.|
|**SMB/Windows Networking**|Enumerate shares, users, sessions, and trust relationships.|
|**SNMP Enumeration**|Query SNMP for system info, routing tables, and community strings.|
|**DNS Enumeration**|Perform zone transfers, brute-force subdomains, or analyze misconfigured records.|
|**Man-in-the-Middle (MitM)**|Intercept traffic via ARP spoofing, DHCP poisoning, or rogue services.|
|**Cleartext Protocols**|Identify unencrypted services (e.g., FTP, Telnet, HTTP) for credential leakage.|
|**Credential Harvesting**|Capture or replay credentials from network traffic or exposed services.|
|**Vulnerability Scanning**|Use tools like Nessus, OpenVAS, or Nmap scripts to identify known issues.|
|**Rogue Device Detection**|Identify unauthorized hosts or access points on the network.|
|**Wireless Testing**|Assess Wi-Fi security, encryption, rogue APs, and client isolation.|
|**VoIP/Telephony Testing**|Analyze SIP, RTP, or PBX systems for misconfigurations or abuse.|
|**VPN Testing**|Evaluate VPN access, split tunneling, and credential handling.|
|**Network Segmentation Testing**|Verify isolation between VLANs, zones, or trust levels.|
|**Outbound Filtering**|Test for egress restrictions using DNS, HTTP, ICMP, or custom protocols.|
|**Data Exfiltration Paths**|Identify channels for covert or overt data exfiltration.|

---

## ✅ **Cloud Security Testing Checklist (Generalized)**

|**Topic**|**Description**|
|---|---|
|**Credential Discovery**|Identify exposed API keys, secrets, or tokens in code, repos, or metadata.|
|**Identity & Access Management (IAM)**|Review roles, policies, and permissions for privilege escalation or lateral movement.|
|**Public Resource Exposure**|Detect publicly accessible buckets, blobs, databases, or services.|
|**Metadata Service Abuse**|Query instance metadata endpoints to extract credentials or tokens.|
|**Misconfigured Storage**|Access or modify data in misconfigured S3 buckets, Azure blobs, or GCP storage.|
|**Overly Permissive Policies**|Identify wildcard permissions (e.g., `*:*`) or broad role assignments.|
|**Serverless Function Abuse**|Invoke or modify cloud functions (e.g., Lambda, Azure Functions) for code execution.|
|**Container Misconfigurations**|Exploit exposed Docker APIs, weak Kubernetes RBAC, or insecure images.|
|**Cloud Shell/Console Access**|Abuse cloud shell environments or web consoles for persistence or lateral movement.|
|**Logging & Monitoring Gaps**|Identify missing or misconfigured audit logs, alerts, or SIEM integrations.|
|**Key Management Service (KMS)**|Test for improper access to encryption keys or key rotation issues.|
|**CI/CD Pipeline Exposure**|Review build pipelines for secrets, hardcoded credentials, or insecure scripts.|
|**API Gateway Testing**|Test for broken access controls, insecure endpoints, or SSRF via API gateways.|
|**Cloud SQL/DB Exposure**|Identify publicly exposed or weakly secured managed databases.|
|**IAM Privilege Escalation Paths**|Chain permissions to escalate (e.g., create new roles, attach policies).|
|**Cross-Account Trust Abuse**|Exploit trust relationships between cloud accounts or tenants.|
|**Resource Tagging/Discovery**|Use tags or naming conventions to identify sensitive resources.|
|**Cloud-Specific Enumeration**|Use tools like `ScoutSuite`, `Pacu`, `CloudSploit`, or `Azucar` for automated discovery.|
|**Egress Path Testing**|Identify outbound access from cloud workloads for data exfiltration or C2.|
|**Persistence Mechanisms**|Establish long-term access via IAM roles, startup scripts, or scheduled tasks.|

---

## ✅ **AI / LLM Security Testing Checklist (Generalized)**

|**Topic**|**Description**|
|---|---|
|**Prompt Injection**|Inject malicious input to override or manipulate the model’s behavior or instructions.|
|**Data Leakage**|Extract sensitive training data, internal prompts, or system instructions via crafted queries.|
|**Indirect Prompt Injection**|Embed malicious prompts in third-party content (e.g., emails, websites) that the LLM later processes.|
|**Function Call Abuse**|Manipulate LLM-generated function calls to trigger unintended or dangerous backend actions.|
|**Overreliance on Output**|Identify where the app blindly trusts LLM output (e.g., for code execution, SQL queries, or routing).|
|**Insecure Tool Integration**|Abuse tools or plugins the LLM can invoke (e.g., file access, shell commands, APIs).|
|**Training Data Poisoning**|Inject malicious data into public sources that may be used in future model training.|
|**Model Misuse**|Test for generation of harmful, biased, or policy-violating content.|
|**Excessive Context Retention**|Abuse long-term memory or context windows to persist malicious instructions.|
|**Insecure API Exposure**|Test for unauthenticated or overly permissive LLM API endpoints.|
|**Rate Limiting & Abuse**|Check for lack of throttling or abuse detection on LLM endpoints.|
|**Prompt Chaining Flaws**|Identify logic flaws in multi-step LLM workflows (e.g., summarization → action).|
|**Data Injection via Output**|Inject HTML, JS, or markdown into LLM output that renders in a client (e.g., stored XSS).|
|**Model Identity Confusion**|Trick the model into impersonating users, roles, or systems.|
|**Sensitive Data Echo**|Test if the model repeats secrets, credentials, or internal data from prior sessions.|
|**Jailbreak Testing**|Attempt to bypass safety filters using obfuscation, encoding, or roleplay scenarios.|
|**Token Stuffing / DoS**|Overload the model with long inputs or nested prompts to degrade performance.|
|**Model Fingerprinting**|Infer model type, version, or fine-tuning details via crafted queries.|
|**Output Injection into Downstream Systems**|Inject payloads that affect downstream consumers (e.g., logs, dashboards, pipelines).|

---

## ✅ **API Security Testing Checklist (Generalized)**

|**Topic**|**Description**|
|---|---|
|**Endpoint Enumeration**|Discover available endpoints via fuzzing, documentation, or proxy tools.|
|**Authentication Testing**|Test for missing, weak, or bypassable authentication mechanisms.|
|**Authorization Testing**|Check for IDOR, role escalation, or horizontal/vertical privilege issues.|
|**Rate Limiting & Throttling**|Test for lack of request limits that allow brute-force or abuse.|
|**Input Validation**|Send unexpected or malicious input to test for injection or logic flaws.|
|**Mass Assignment**|Attempt to set restricted fields by guessing or injecting extra parameters.|
|**Parameter Pollution**|Send duplicate or conflicting parameters to bypass filters or logic.|
|**HTTP Method Abuse**|Try unsupported or unexpected methods (e.g., `PUT`, `DELETE`, `OPTIONS`).|
|**Token Handling**|Test for JWT tampering, token reuse, or insecure storage of tokens.|
|**CORS Misconfigurations**|Check for overly permissive cross-origin resource sharing policies.|
|**Error Handling**|Trigger errors to leak stack traces, debug info, or internal logic.|
|**Data Exposure**|Look for excessive or sensitive data returned in API responses.|
|**Versioning Issues**|Test different API versions for inconsistent security controls.|
|**GraphQL-Specific Testing**|Use introspection, aliasing, and batching to discover and abuse schema.|
|**WebSocket Testing**|Inspect real-time APIs for auth, input validation, and message tampering.|
|**Replay Attacks**|Resend captured requests to test for idempotency or lack of nonce/timestamp checks.|
|**Broken Object Level Authorization (BOLA)**|Access or modify objects belonging to other users.|
|**Broken Function Level Authorization (BFLA)**|Invoke admin or restricted functions as a regular user.|
|**Third-Party API Abuse**|Test integrations for insecure tokens, excessive permissions, or trust assumptions.|
|**Logging & Monitoring Gaps**|Check if API activity is logged and monitored for anomalies.|

---

