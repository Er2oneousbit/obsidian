# OWASP API Top 10

#OWASP #API #APITop10 #WebAppAttacks #BOLA

## What is this?

**OWASP API Top 10** — Top 10 most critical API security risks. API-specific vulnerabilities (beyond traditional web app risks). Published 2019; updated 2023. Essential for testing REST APIs, GraphQL, gRPC, and other API architectures.

---

## Overview

**OWASP API Top 10 Basics:**
- **Purpose**: Highlight API-specific vulnerabilities (different from web app Top 10).
- **Scope**: All API types (REST, GraphQL, SOAP, gRPC, WebSocket).
- **Audience**: API developers, API security testers, DevOps teams.
- **Why Different from Top 10**: APIs have unique attack surface (stateless, no sessions, token-based auth, massive scale).

**Versions**: 2019, **2023 (current)** — added SSRF (API7) and Unrestricted Access to Sensitive Business Flows (API6); merged the old Mass Assignment + Excessive Data Exposure into Broken Object Property Level Authorization (API3); dropped Insufficient Logging & Monitoring as a standalone item.

---

## OWASP API Top 10 2023

### 1. Broken Object Level Authorization (BOLA)

**What It Is**: Attacker accesses objects belonging to other users by manipulating identifiers.

**API Context**: RESTful APIs often use predictable IDs; no authorization check.

#### Examples

**Horizontal Escalation** (access other users' data):
```
GET /api/v1/users/123/profile  (own profile)
GET /api/v1/users/456/profile  (other user's profile)
Returns data without checking if requester owns resource
```

**Predictable IDs**:
```
Order IDs sequential: /api/orders/1001, /api/orders/1002, ...
Attacker increments; accesses all orders in system
```

#### Prevention

```python
# VULNERABLE
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return user.to_json()

# SECURE
@app.route('/api/users/<user_id>')
@require_auth
def get_user(user_id):
    if int(user_id) != current_user.id:
        abort(403)
    user = User.query.get(user_id)
    return user.to_json()
```

**Mitigation**:
- Always check authorization (user owns resource).
- Use UUIDs instead of sequential IDs (unpredictable).
- Deny by default; allow only authenticated + authorized users.

---

### 2. Broken Authentication

**What It Is**: Weak API authentication; tokens not validated, sessions not managed.

**API Context**: APIs use tokens (JWT, OAuth); mishandled tokens = auth bypass.

#### Common Issues

**JWT Token Handling**:
```python
# VULNERABLE: No signature verification
import jwt
token = request.headers['Authorization'].split(' ')[1]
payload = jwt.decode(token, options={"verify_signature": False})
# Attacker forges token; server accepts it

# SECURE: Verify signature
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
# If signature invalid; raises exception
```

**Token Expiration**:
```
Tokens never expire; attacker steals old token, uses forever
```

**No Token Revocation**:
```
User logs out; token still valid
Attacker who intercepted token can still use it
```

**Weak Credentials**:
```
API key "123456" or no API key requirement
Attacker guesses/finds key; accesses API
```

#### Prevention

```python
# SECURE: Use strong authentication
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']  # Strong secret
jwt = JWTManager(app)

@app.route('/api/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and bcrypt.checkpw(request.form['password'].encode(), user.password):
        # Short-lived token (15 min); refresh tokens for longer sessions
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=15))
        return {'access_token': access_token}, 200
    abort(401)

@app.route('/api/protected')
@jwt_required()
def protected():
    return {'message': f'Hello {get_jwt_identity()}'}, 200
```

**Mitigation**:
- Require MFA for API access (if user-facing).
- Use short-lived tokens (15–60 min); refresh tokens for longer sessions.
- Implement token revocation (blacklist, database check).
- Validate token signatures (don't skip verification).
- Use HTTPS-only; secure token storage (httponly cookies, secure key store).

---

### 3. Broken Object Property Level Authorization

**What It Is**: API returns properties user shouldn't see (over-exposure of data).

**API Context**: APIs often return full objects; no field-level access control.

#### Examples

**Over-Exposure**:
```json
GET /api/v1/users/123
{
  "id": 123,
  "email": "user@example.com",
  "internal_id": "emp_abc123",  // Exposed; shouldn't be in API response
  "salary": 120000,  // Exposed; sensitive
  "ssn": "123-45-6789",  // Exposed; PII
  "is_admin": true  // Exposed; could lead to privilege escalation
}
```

#### Prevention

```python
# VULNERABLE: Return all fields
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return user.to_json()  # Includes all fields

# SECURE: Return only safe fields
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email
        # Exclude: salary, ssn, is_admin, internal_id
    }

# Or use serializer with field restrictions
class UserSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    email = fields.Email()
    # salary, ssn not included
    
    class Meta:
        fields = ['id', 'name', 'email']
```

**Mitigation**:
- Define allowed fields per endpoint (whitelist, not blacklist).
- Use serializers/schema validation (marshmallow, pydantic).
- Test API responses (ensure no sensitive fields leaked).
- Data classification (mark fields as sensitive; exclude from APIs).

---

### 4. Unrestricted Resource Consumption (Rate Limiting Bypass)

**What It Is**: Attacker consumes excessive API resources; DoS or expensive operations.

**API Context**: APIs can be abused (brute force login, enumerate resources, exhaust quota).

#### Examples

**No Rate Limiting**:
```
Attacker sends unlimited login attempts
500 requests/second; no throttling
```

**Expensive Operations**:
```
GET /api/reports/generate?start=2000&end=2024
Complex query; takes 30 seconds to execute
Attacker sends 100 concurrent requests; server overwhelmed
```

**File Upload Limits**:
```
No size limit on uploaded files
Attacker uploads 1GB files; fills disk
```

#### Prevention

```python
# Rate limiting (Flask-Limiter)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # 5 login attempts per minute
def login():
    ...

@app.route('/api/users', methods=['GET'])
@limiter.limit("100 per hour")  # 100 requests per hour
def list_users():
    ...

# File upload size limit
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

# Timeout for expensive queries
@app.route('/api/reports')
def generate_report():
    # Query timeout: 30 seconds
    # Return error if query takes longer
    ...
```

**Mitigation**:
- Rate limit by IP, user, API key.
- Implement quotas (API keys get X calls/day).
- Timeout expensive operations (30–60 sec max).
- Limit file upload size.
- Pagination (max 100 results per request).
- Alert on suspicious usage patterns.

---

### 5. Broken Function Level Authorization

**What It Is**: User can call API endpoints they shouldn't access.

**API Context**: APIs expose admin endpoints; no role check.

#### Examples

**Admin Endpoint Accessible**:
```
GET /api/admin/users/list  (should be admin-only)
Regular user accesses; gets all users
```

**Hidden Admin Functions**:
```
POST /api/admin/delete_user (attacker guesses URL)
No authentication; user deleted
```

#### Prevention

```python
# VULNERABLE: No role check
@app.route('/api/admin/users/delete/<user_id>', methods=['POST'])
def delete_user(user_id):
    User.query.get(user_id).delete()
    return 'User deleted'

# SECURE: Check role
@app.route('/api/admin/users/delete/<user_id>', methods=['POST'])
@require_auth
@require_role('admin')
def delete_user(user_id):
    User.query.get(user_id).delete()
    return 'User deleted'

# Or middleware-based
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
```

**Mitigation**:
- Enforce role-based access control (RBAC) on all endpoints.
- Deny by default (require explicit permission).
- Don't rely on obscurity (hiding endpoints doesn't secure them).
- Test all endpoints (including hidden/admin ones).

---

### 6. Unrestricted Access to Sensitive Business Flows

**What It Is**: Attacker abuses business logic (order multiple times, race conditions, etc.).

**API Context**: Unique to APIs; business logic vulnerabilities.

#### Examples

**Multiple Order Placement**:
```
POST /api/orders with discount code
Attacker sends request 10 times concurrently
10 orders placed; each with discount (inventory depleted, revenue lost)
```

**Race Condition**:
```
Check balance → Deduct funds
Attacker sends transfer twice concurrently
Race condition; both succeed (double transfer)
```

**Bypass Business Logic**:
```
Age gate: "users < 18 can't buy alcohol"
API accepts age in request: POST /api/purchase?age=50
Attacker changes to: POST /api/purchase?age=25
```

#### Prevention

```python
# VULNERABLE: No idempotency
@app.route('/api/orders', methods=['POST'])
def create_order():
    order = Order(user_id=current_user.id, total=request.form['total'])
    db.session.add(order)
    db.session.commit()
    return order.to_json()

# SECURE: Idempotency key (prevent duplicates)
@app.route('/api/orders', methods=['POST'])
def create_order():
    idempotency_key = request.headers.get('Idempotency-Key')
    
    # Check if order already created with this key
    existing = Order.query.filter_by(idempotency_key=idempotency_key).first()
    if existing:
        return existing.to_json()  # Return existing order
    
    order = Order(user_id=current_user.id, total=request.form['total'], 
                  idempotency_key=idempotency_key)
    db.session.add(order)
    db.session.commit()
    return order.to_json()

# SECURE: Validate business logic
@app.route('/api/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    recipient = request.form['recipient']
    
    # Validation: amount > 0, balance sufficient, recipient exists
    if amount <= 0:
        abort(400)  # Invalid amount
    if current_user.balance < amount:
        abort(400)  # Insufficient funds
    
    # Database transaction (atomic; can't be split)
    with db.session.begin():
        current_user.balance -= amount
        recipient_user = User.query.get(recipient)
        recipient_user.balance += amount
    
    return {'status': 'success'}, 200
```

**Mitigation**:
- Implement idempotency keys (prevent duplicate operations).
- Use database transactions (atomic operations).
- Validate business logic (amount > 0, balance sufficient, etc.).
- Race condition testing (send concurrent requests; verify no double-spending).

---

### 7. Server-Side Request Forgery (SSRF)

**What It Is**: Attacker tricks API into making requests to unintended hosts.

**API Context**: APIs often fetch external data; no validation of URLs.

#### Examples

```python
# VULNERABLE
@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.form['url']
    data = requests.get(url)  # No validation
    return data

# Attacker sends: http://169.254.169.254/latest/meta-data/
# Server fetches AWS metadata; attacker gets credentials
```

**Prevention** (see OWASP Top 10 #10 SSRF).

---

### 8. Security Misconfiguration

**What It Is**: Missing hardening across the API stack — permissive CORS, verbose errors, unnecessary features enabled, missing security headers, or unpatched components.

#### Examples
```
- CORS: Access-Control-Allow-Origin: *  with credentials (any site can call the API)
- Verbose stack traces / debug mode returned to clients
- Default accounts or admin/debug endpoints left enabled
- Missing security headers; unpatched framework or server
```

#### Prevention
- Repeatable hardening applied to every environment; restrict CORS to known origins.
- Disable verbose errors/debug in production; remove unused features and default creds.
- Patch the framework, server, and dependencies; enforce security headers.

---

### 9. Improper Inventory Management

**What It Is**: Undocumented, deprecated, or "shadow" API versions and hosts remain accessible (renamed from 2019's "Improper Assets Management").

**API Context**: APIs evolve; old versions and non-production hosts aren't decommissioned.

#### Examples

**Old API Version Running**:
```
GET /api/v1/users (deprecated; no auth required)
GET /api/v2/users (current; requires auth)
Attacker uses v1 endpoint; bypasses auth
```

**Undocumented Endpoints**:
```
/api/admin/backup (not in API docs; still accessible)
```

#### Prevention
- Maintain a complete API inventory (all hosts, versions, environments) via OpenAPI/Swagger.
- Retire old versions on a deprecation timeline (e.g. return `410 Gone`); enforce auth on all versions.
- Track and lock down non-production/beta hosts; don't expose them publicly.

---

### 10. Unsafe Consumption of APIs

**What It Is**: An API trusts data from third-party/upstream APIs without validation or sanitization.

**API Context**: Microservices; API chains (API → API → API).

#### Examples

**No Validation of 3rd-Party Data**:
```python
# VULNERABLE
external = requests.get('https://weather-api.com/today')
return external.json()   # returned directly — if the upstream is compromised, malicious data flows through
```

**SSRF via 3rd-Party API**: your API passes a user-controlled URL to a vendor API that fetches it, reaching internal services.

#### Prevention
- Validate / schema-check external API responses before using them.
- Don't pass raw user input to upstream APIs; use allowlisted parameters.
- Enforce timeouts; handle upstream errors without leaking details.

> [!note]
> "Insufficient Logging & Monitoring" was **API10 in 2019 but was dropped from the 2023 list** (logging is now covered under general practices). Still test for audit-trail gaps — it's good practice — but it is no longer a numbered API risk.

---

## API Testing Checklist

```
[ ] BOLA — Can I access other users' data by changing IDs?
[ ] Broken Auth — Can I forge/steal/bypass tokens?
[ ] Broken Props — Does API expose sensitive fields?
[ ] Rate Limiting — Can I DoS via unlimited requests?
[ ] Function Auth — Can I call admin endpoints?
[ ] Business Logic — Can I abuse race conditions, duplicates?
[ ] SSRF — Can I fetch internal URLs?
[ ] Security Misconfig — Permissive CORS, verbose errors, debug endpoints?
[ ] Inventory — Undocumented/deprecated endpoints or shadow hosts accessible?
[ ] Unsafe Consumption — Third-party API responses validated? User input passed unsafely?
```

---

## API Security Best Practices

| Practice | Why |
|---|---|
| **API Versioning** | Deprecate old versions cleanly; no auth bypass via old API |
| **Input Validation** | Whitelist expected inputs; reject malformed requests |
| **Output Filtering** | Return only necessary fields; no data over-exposure |
| **Rate Limiting** | Prevent abuse (brute force, DoS, quota exhaustion) |
| **HTTPS Only** | Encrypt data in transit; prevent credential interception |
| **Strong Auth** | MFA, strong tokens (JWT, OAuth), short expiration |
| **Authorization Checks** | Verify user owns resource before returning/modifying |
| **Idempotency Keys** | Prevent duplicate operations (race conditions) |
| **Monitoring** | Detect anomalies, brute force, unusual usage patterns |
| **Documentation** | API inventory; makes unauthorized endpoints easier to identify |

---


## See also

[[OWASP-Top-10]], [[OWASP-ASVS]], [[OWASP-LLM-Top-10]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
