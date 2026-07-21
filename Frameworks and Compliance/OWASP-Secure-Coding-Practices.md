# OWASP Secure Coding Practices

#OWASP #SecureCoding #AppSec #Development

## What is this?

**OWASP Secure Coding Practices** — Comprehensive guide to building secure software. Published by OWASP; the free Quick Reference Guide is a non-prescriptive checklist covering **14** coding practice areas (input validation, output encoding, authentication, session management, access control, cryptography, error handling & logging, data protection, communication security, system configuration, database security, file management, memory management, general coding). Focuses on developer education: how to avoid introducing vulnerabilities during development.

---

## Overview

**Secure Coding Practices Basics:**
- **Purpose**: Teach developers how to write secure code; prevent common vulnerabilities at the source.
- **Audience**: Software developers, code reviewers, security champions in dev teams.
- **Scope**: Design, development, testing practices; language-agnostic (applies to Java, Python, C, Node.js, etc.).

**Relation to Other Standards**:
- **OWASP Testing Guide** = testing checklist (find vulns after code is written).
- **OWASP Secure Coding Practices** = prevent vulns before code is written (proactive).
- **NIST SP 800-218 SSDF** = secure software development framework (similar scope, more prescriptive).
- **CWE Top 25** = common software weaknesses (preventable with secure coding practices).

---

## The 12 Secure Coding Practice Areas

### 1. Input Validation

**Goal**: Validate all input (user input, API data, file uploads, etc.) before use.

**Principle**: "Untrusted input is the #1 source of web app vulnerabilities."

#### Whitelist vs. Blacklist

**Blacklist** (bad — don't do this):
```python
# Block known bad characters
if not any(char in user_input for char in ['<', '>', '"', "'"]):
    process_input(user_input)
# Problem: Easy to bypass with encoding (e.g., &#60; for <)
```

**Whitelist** (good):
```python
# Only allow known-good characters
if re.match(r'^[a-zA-Z0-9\s._-]{1,100}$', user_input):
    process_input(user_input)
# Problem: May reject valid input (international chars, special chars)
```

#### Input Validation by Type

| Input Type | Validation | Example |
|---|---|---|
| **Email** | Format check (regex) + optional domain verification | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` |
| **Phone** | Format check; length validation | ^[0-9\-\(\)\s]+$ |
| **File Upload** | File type (MIME), size limit, scan for malware | Allow PDF/DOCX only; max 10MB; scan with ClamAV |
| **URL** | URL parse; protocol check (http/https only); domain whitelist | Must start with https://; domain must be in whitelist |
| **Date/Time** | Format check; range validation (not past/future) | YYYY-MM-DD format; not > 1 year in future |

#### SQL Injection Prevention

**Vulnerable Code**:
```python
# Attacker sends: ' OR '1'='1
query = f"SELECT * FROM users WHERE id={user_id}"
db.execute(query)
```

**Secure Code** (Parameterized Queries):
```python
# Parameterized query (placeholders, not string interpolation)
query = "SELECT * FROM users WHERE id=?"
db.execute(query, (user_id,))
# Database driver handles escaping; injection impossible
```

#### Command Injection Prevention

**Vulnerable Code**:
```bash
# Attacker sends: "test.txt; rm -rf /"
os.system(f"cat {user_file}")
```

**Secure Code**:
```python
# Use subprocess with list of args (not shell=True)
subprocess.run(['cat', user_file], check=True)
# Treats "test.txt; rm -rf /" as filename, not shell command
```

---

### 2. Output Encoding / Escaping

**Goal**: Encode output to prevent injection attacks (XSS, LDAP injection, etc.).

**Principle**: Different contexts require different encoding.

#### HTML Encoding (Prevent XSS)

**Vulnerable Code**:
```html
<!-- User input: <img src=x onerror="alert('XSS')"> -->
<p><?php echo $_GET['user_comment']; ?></p>
<!-- Renders as: <img src=x onerror="alert('XSS')"> -->
<!-- Onerror event fires; attacker's code runs -->
```

**Secure Code**:
```php
<!-- HTML-encode special characters -->
<p><?php echo htmlspecialchars($_GET['user_comment'], ENT_QUOTES, 'UTF-8'); ?></p>
<!-- Renders as: &lt;img src=x onerror=&quot;alert('XSS')&quot;&gt; -->
<!-- Browser displays as literal text; no code execution -->
```

#### Context-Specific Encoding

| Context | Encoding Method | Example |
|---|---|---|
| **HTML Body** | HTML entities | `<` → `&lt;` / `>` → `&gt;` |
| **HTML Attribute** | HTML entities + quote escaping | `"` → `&quot;` |
| **JavaScript String** | JavaScript escaping | `'` → `\'` / `\n` → `\\n` |
| **URL Parameter** | URL encoding | Space → `%20` / `/` → `%2F` |
| **CSS Value** | CSS encoding | Special chars → `\XX` hex escape |

---

### 3. Authentication

**Goal**: Verify user identity; prevent unauthorized access.

#### Multi-Factor Authentication (MFA)

**Best Practice**: Require MFA for all accounts, especially privileged (admin, database, cloud).

**MFA Types**:
- **Something you know**: Password, PIN.
- **Something you have**: Hardware token, authenticator app (TOTP), SMS code.
- **Something you are**: Fingerprint, facial recognition (biometric).

#### Password Security

**Do NOT**:
- Store plaintext passwords (always hash).
- Limit password length (no max length enforced).
- Force frequent password changes (encourages weak passwords).
- Require complex rules (encourages predictable patterns like Password123!).

**Do**:
- Hash with strong algorithm (bcrypt, scrypt, Argon2; NOT MD5/SHA1).
- Support long passphrases (encourage 15+ chars).
- No arbitrary expiration (change only if compromised).
- Rate limit login attempts (prevent brute force).

**Example: Secure Password Hashing (Python)**:
```python
import bcrypt

# Hash password
password = "my_secure_passphrase_123"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Store hashed in database

# Verify password on login
if bcrypt.checkpw(password.encode(), hashed):
    login_user()
```

#### Session Management

**Best Practices**:
- Use secure session tokens (long, random, cryptographically generated).
- Store session server-side (not in JWT, which can be forged).
- Set session timeout (30–60 minutes inactivity).
- Regenerate session ID after login (prevent session fixation).
- Use secure cookie flags: `HttpOnly` (no JS access), `Secure` (HTTPS only), `SameSite=Strict` (prevent CSRF).

---

### 4. Access Control

**Goal**: Enforce least privilege; users get only necessary permissions.

#### Role-Based Access Control (RBAC)

**Example: User Roles**:
- **Admin**: All permissions.
- **Editor**: Create/modify content; not delete, not system settings.
- **Viewer**: Read-only; no write access.

**Implementation**:
```python
# Check role before allowing action
if user.role in ['Admin', 'Editor'] and action == 'create_post':
    allow_action()
else:
    deny_action()
```

#### Principle of Least Privilege

**Bad**:
```python
# Everyone gets all permissions
user_permissions = ['read', 'write', 'delete', 'admin']
```

**Good**:
```python
# Users get only what they need
if user.role == 'viewer':
    user_permissions = ['read']
elif user.role == 'editor':
    user_permissions = ['read', 'write']
elif user.role == 'admin':
    user_permissions = ['read', 'write', 'delete', 'admin']
```

#### Access Control Vulnerabilities

**Broken Access Control (OWASP Top 10 #1)**:
- **Horizontal escalation**: User accesses another user's data (change URL: /user/123 → /user/456).
- **Vertical escalation**: User gains admin permissions (privilege escalation).

**Example Vulnerability**:
```python
# VULNERABLE: No check that user owns the resource
@app.route('/post/<post_id>/edit', methods=['POST'])
def edit_post(post_id):
    post = Post.query.get(post_id)
    post.content = request.form['content']
    db.session.commit()
    # Any logged-in user can edit any post (horizontal escalation)
```

**Fix**:
```python
# SECURE: Verify user owns the resource
@app.route('/post/<post_id>/edit', methods=['POST'])
def edit_post(post_id):
    post = Post.query.get(post_id)
    if post.owner_id != current_user.id:
        abort(403)  # Forbidden
    post.content = request.form['content']
    db.session.commit()
```

---

### 5. Cryptography

**Goal**: Protect sensitive data using strong encryption.

#### Data at Rest Encryption

```python
from cryptography.fernet import Fernet

# Generate key (store securely; don't hardcode)
key = Fernet.generate_key()

# Encrypt data
cipher = Fernet(key)
encrypted_data = cipher.encrypt(b"sensitive_data")

# Decrypt data
decrypted_data = cipher.decrypt(encrypted_data)
```

#### Data in Transit Encryption

**Use TLS 1.2+ for all HTTPS connections**:
- No plaintext HTTP (except internal, isolated networks).
- Certificate validation (don't ignore certificate errors).
- Strong ciphers (AES, not RC4 or DES).

#### Key Management

**Do NOT**:
- Hardcode keys in source code.
- Commit keys to version control (git).
- Use weak key generation (random.random() in Python).

**Do**:
- Store keys in secrets management system (Vault, AWS Secrets Manager, Azure Key Vault).
- Use cryptographically secure random generation (os.urandom(), secrets module).
- Rotate keys regularly (annually minimum).

**Example: Key Storage**:
```python
import os
from cryptography.fernet import Fernet

# Load key from environment (set by ops team)
key = os.environ['ENCRYPTION_KEY']
cipher = Fernet(key)
```

---

### 6. Error Handling & Logging

**Goal**: Handle errors securely; log activity for auditing/forensics.

#### Secure Error Handling

**Bad Error Messages** (leak sensitive info):
```python
try:
    user = User.query.filter_by(email=email).first()
    # If user not found, error reveals email doesn't exist (user enumeration)
except Exception as e:
    return f"Error: {str(e)}"  # Details expose internal system
```

**Good Error Messages** (generic, no info leakage):
```python
try:
    user = User.query.filter_by(email=email).first()
except Exception as e:
    logger.error(f"Login error: {str(e)}")  # Log details server-side
    return "Invalid email or password"  # Generic message to user
```

#### Secure Logging

**What to Log**:
- Failed login attempts (with timestamp, IP, username).
- Privilege escalation (who elevated, when, what actions).
- Data access (who accessed what data).
- System changes (configuration, policy changes).
- Security events (failed authorization, potential attacks).

**What NOT to Log**:
- Plaintext passwords.
- Credit card numbers, SSN.
- API keys, secrets.

**Example**:
```python
import logging

logger = logging.getLogger(__name__)

# Good logging
logger.warning(f"Failed login attempt for user {username} from IP {request.remote_addr}")
# Bad logging
logger.info(f"User {username} logged in with password {password}")  # Don't log passwords!
```

---

### 7. Communication Security

**Goal**: Protect data in transit; prevent MITM (man-in-the-middle) attacks.

#### TLS/SSL Configuration

```python
# GOOD: Enforce HTTPS; require strong TLS version
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection

# Configure minimum TLS 1.2
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
```

#### Certificate Validation

**Bad**:
```python
# Disable certificate validation (NEVER do this in production)
requests.get('https://api.example.com', verify=False)
```

**Good**:
```python
# Validate certificate (default in requests library)
requests.get('https://api.example.com', verify=True)
# Or verify against specific CA bundle
requests.get('https://api.example.com', verify='/path/to/ca-bundle.crt')
```

---

### 8. Database Security

**Goal**: Protect database from unauthorized access, injection, and data leakage.

#### Parameterized Queries (Prevent SQL Injection)

```python
# VULNERABLE: String concatenation
query = f"SELECT * FROM users WHERE id={user_id}"

# SECURE: Parameterized query
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_id,))
```

#### Least Privilege Database Users

```sql
-- Create low-privilege user for application
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'app_user'@'localhost';
-- Don't grant DELETE, DROP, or admin privileges to app user
```

#### Encryption at Rest

```python
# Encrypt sensitive columns in database
from sqlalchemy_utils import EncryptedType

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    ssn = db.Column(EncryptedType(db.String, 'encryption_key'))  # Encrypted
```

---

### 9. File Upload Security

**Goal**: Prevent malicious file uploads (web shells, malware, etc.).

#### File Type Validation

```python
# VULNERABLE: Trust filename extension
if user_file.filename.endswith('.pdf'):
    user_file.save('uploads/' + user_file.filename)

# SECURE: Validate MIME type + check file contents
import magic
file_mimetype = magic.from_buffer(user_file.read(1024), mime=True)
if file_mimetype == 'application/pdf':
    # Also check magic bytes (first few bytes of file)
    user_file.seek(0)
    magic_bytes = user_file.read(4)
    if magic_bytes == b'%PDF':  # PDF magic bytes
        user_file.save('uploads/' + secure_filename(user_file.filename))
```

#### File Storage Security

```python
# Store uploaded files outside web root (not accessible via HTTP)
# Serve via controller (can log access, check permissions)

# Don't expose original filename (rename to random ID)
import uuid
filename = f"{uuid.uuid4()}.pdf"
user_file.save(f'/secure/uploads/{filename}')
# Later: serve via GET /download/<file_id>
```

---

### 10. Memory Management

**Goal**: Prevent memory-based vulnerabilities (buffer overflow, use-after-free, etc.).

#### Buffer Overflow Prevention

**C/C++ Code** (memory-unsafe languages need manual prevention):

```c
// VULNERABLE: Fixed-size buffer, no bounds checking
char buffer[10];
strcpy(buffer, user_input);  // If input > 10 chars, overflow

// SECURE: Use safe string functions
char buffer[10];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';  // Null terminate
```

**Python/Java** (memory-safe languages; automatic prevention):
- Python/Java handle memory automatically; buffer overflows not possible.
- Focus on other vulnerabilities instead.

---

### 11. General Coding Practices

#### Code Review

**Mandatory**:
- All code must be reviewed by at least one other developer before merge.
- Reviewer checks for security issues (input validation, crypto, access control, etc.).
- Documented review (who reviewed, when, any issues found).

#### Secure Defaults

```python
# GOOD: Secure by default
DEBUG = False  # Never debug in production
SECURE_COOKIES = True  # Always use secure cookie flags
VERIFY_SSL = True  # Always verify SSL certs by default

# Bad: Insecure defaults (required explicit hardening)
DEBUG = True  # Default on; easily forgotten
```

#### Avoid Hardcoding Secrets

```python
# BAD
API_KEY = "sk_live_abc123..."  # In code; committed to git

# GOOD
API_KEY = os.environ.get('API_KEY')  # Read from environment
# Set in deployment (Docker env, Kubernetes secrets, etc.)
```

---

### 12. Security Build Process

**Goal**: Integrate security into development workflow.

#### Automated Security Testing (CI/CD)

```yaml
# .github/workflows/security.yml
name: Security Checks
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Static analysis (SAST)
      - name: Run SonarQube
        run: sonar-scanner
      
      # Dependency scanning
      - name: Check dependencies
        run: pip install safety && safety check
      
      # Secrets scanning
      - name: Scan for secrets
        run: gitleaks scan
      
      # DAST (dynamic testing)
      - name: Run OWASP ZAP
        run: docker run -t owasp/zap2docker-stable -t http://localhost:8080
```

---

## Secure Coding Checklist

### Design Phase
- [ ] Security requirements defined (what needs protection?).
- [ ] Threat modeling conducted (what attacks are possible?).
- [ ] Security architecture reviewed (layered defense, defense-in-depth?).

### Development Phase
- [ ] Input validation implemented on all user input.
- [ ] Output encoding/escaping applied (context-specific).
- [ ] Authentication/MFA required for sensitive actions.
- [ ] Access control enforced (least privilege).
- [ ] Encryption used (at rest, in transit).
- [ ] Error handling secure (no info leakage).
- [ ] Logging enabled (audit trail).
- [ ] Secrets not hardcoded (environment variables, key management).

### Testing Phase
- [ ] Code review (security-focused).
- [ ] SAST (static analysis) run; findings remediated.
- [ ] DAST (dynamic testing) performed; findings remediated.
- [ ] Dependency scanning (known-vulnerable libraries identified).
- [ ] Penetration testing conducted.

### Deployment Phase
- [ ] Security headers configured (CSP, X-Frame-Options, etc.).
- [ ] TLS configured (1.2+, strong ciphers, valid certificate).
- [ ] Database hardened (least-privilege accounts, encryption).
- [ ] Secrets managed (not in code, not in logs).
- [ ] Monitoring/alerting enabled (detect breaches).

---

## Common Secure Coding Mistakes

| Mistake | Impact | Fix |
|---|---|---|
| No input validation | SQL injection, XSS, command injection | Validate all user input (whitelist) |
| Trusting user input | Vulnerability to injection attacks | Always escape/encode output |
| Plaintext password storage | Breach = all passwords compromised | Hash with bcrypt, Argon2 |
| Hardcoded secrets | Secrets in git history; leaked in repos | Use environment variables, secrets management |
| No access control | Horizontal/vertical privilege escalation | Check ownership before allowing action |
| Weak crypto | Data easily decrypted | Use AES-256, TLS 1.2+; strong keys |
| Logging sensitive data | Logs contain passwords, credit cards | Never log secrets; use generic error messages |
| No rate limiting | Brute force attacks succeed | Rate limit login, password reset, API endpoints |

---

## Resources

- **OWASP Secure Coding Practices Full Document**: Free PDF download.
- **OWASP Top 10 Web Application Security Risks**: Most common web vulns.
- **CWE/SANS Top 25**: Most dangerous software weaknesses.
- **NIST SP 800-218 SSDF**: Secure software development framework (more detailed).

---


## See also

[[OWASP-Proactive-Controls]], [[Secure-SDLC]], [[CWE-Top-25]], [[OWASP-Top-10]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
