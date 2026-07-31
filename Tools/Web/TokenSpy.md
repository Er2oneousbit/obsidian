# TokenSpy

**Tags:** #TokenSpy #OAuth #OIDC #JWT #TokenTheft #Recon #WebAppAttacks #JavaScript

`TokenSpy` hunts for authentication tokens — JWTs, OAuth access/refresh tokens, bearer tokens — leaking into places they shouldn't be: JavaScript source, `localStorage`/`sessionStorage`, and network responses. A token exposed to client-side JS is reachable by any XSS, so surfacing them turns "there's an XSS somewhere" into a concrete account-takeover path.

**Source:** https://github.com/dub-flow/tokenspy
**Install:** `git clone https://github.com/dub-flow/tokenspy` (see the repo for the current run instructions)

```bash
# Point it at a target and let it surface tokens in the page's JS / storage
# (exact invocation per the repo README — the tool is small and self-describing)
python3 tokenspy.py -u https://<TARGET>

# Manual equivalent when TokenSpy isn't handy — grep bundles for token shapes
curl -s https://<TARGET>/main.js | grep -oiE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'   # JWTs
```

> [!tip] Any token you find in client-reachable JS or storage is XSS-exploitable — pair a find here with [[Class notes/HTB Academy/CPTS v2 (claude)/Cross-Site Scripting (XSS)|XSS]] to demonstrate exfiltration, and feed captured JWTs into [[Tools/Web/jwt_tool|jwt_tool]] for tampering.

> [!note] Tokens belong in `HttpOnly` cookies precisely so JS can't read them — finding an access/refresh token in `localStorage` is itself a reportable finding regardless of whether you can currently trigger it.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/OAuth-OIDC-SAML|OAuth / OIDC / SAML Attacks]] — locating exposed OAuth/OIDC tokens for theft and replay.

---

*Created: 2026-07-31*
*Updated: 2026-07-31*
*Model: claude-opus-5*
