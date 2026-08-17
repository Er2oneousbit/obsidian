# Standards & Protocols — Index

#MOC #Standards #Protocols #Identity #Reference

Map of content for the **technical protocols, data formats, and identity/auth standards** in this folder. These are *concept* notes — what a standard is, how it works, and why its design is attackable — the counterpart to the *attack* notes (CPTS/CWES/Services) that cover how to break it. The technical analog to [[_Frameworks and Compliance]] (governance) and the vuln-class notes in [[Sr Tester Role/Topics/OWASP API Top 10|Sr Tester Role/Topics]].

New here? Read [[template]] for the note format and the bar for what earns a note.

---

## Identity & Federation

| Note | What it covers | Status |
|---|---|---|
| [[SAML]] | XML-based SSO assertions between IdP and SP; signature trust model | ✅ |
| [[OAuth-OIDC]] | OAuth 2.0 authorization + OIDC authentication (tokens, flows, PKCE) | ✅ |
| [[JWT]] | JSON Web Tokens (JWS/JWE/JWK) — the token format OIDC & APIs carry | ✅ |
| [[NTLM]] | Windows challenge-response auth; relay & pass-the-hash trust model | ✅ |
| [[WebAuthn-FIDO2\|WebAuthn / FIDO2]] | Passwordless public-key auth (passkeys / security keys); phishing-resistant | ✅ |
| [[SPNEGO-GSS\|SPNEGO / GSS-API]] | The Negotiate layer that picks Kerberos vs NTLM (and downgrades between them) | ✅ |
| [[SCIM]] | Cross-domain identity **provisioning** — user lifecycle (create / deprovision) across SaaS via REST/JSON | ✅ |

---

## Data Formats & Markup

| Note | What it covers | Status |
|---|---|---|
| [[XML]] | Elements / DTD / entities / namespaces — the XXE and signed-XML (SAML) substrate | ✅ |
| [[HTML]] | The DOM + lenient-parsing injection substrate behind XSS, HTML injection & clickjacking | ✅ |
| [[JSON]] | Schemaless text → live object — mass assignment, prototype pollution, type confusion, JSONP | ✅ |

---

## APIs & Web Services

| Note | What it covers | Status |
|---|---|---|
| [[REST]] | HTTP-verb resource APIs — why the style's *absent* authz gives BOLA/BFLA/mass-assignment (defines CRUD, AJAX inline) | ✅ |
| [[SOAP]] | XML-envelope messaging + WSDL contract + WS-Security — enterprise/legacy API attack surface | ✅ |

*GraphQL — the third API style — lives in the CWES attack notes: [[Class notes/HTB Academy/CWES Claude/Intro to GraphQL|Intro to GraphQL]].*

---

## PKI & Certificates

| Note | What it covers | Status |
|---|---|---|
| [[X509-PKI\|X.509 / PKI]] | Digital certificates + chains of trust — the substrate under TLS, AD CS, and signed SAML/JWT | ✅ |

---

## Roadmap (candidates)

Scoped per the [[template]] bar (protocol/format/standard · design-must-be-understood-to-attack · cross-cutting). Built strongest-first.

| Tier | Candidates | Why |
|---|---|---|
| **Strong** — ✅ done | [[SAML]], [[OAuth-OIDC]], [[JWT]], [[NTLM]] | Cross-cut Web + Cloud + AD; design-critical |
| **Second** — ✅ done | XML, WebAuthn/FIDO2, SPNEGO/GSS, SCIM | Real but narrower reach |
| **Extended** — started | **X.509/PKI ✅ · HTML ✅ · JSON ✅ · REST ✅ · SOAP ✅**; next: TLS · SPF/DKIM/DMARC · RADIUS | Net-new beyond the original plan — narrower but real |
| **Leave in `Services/`** | Kerberos, LDAP | Already have substantial Service notes — cross-link, don't duplicate |
| **Not built (fail the bar)** | CRUD, AJAX, API | Pattern acronym / dated technique / umbrella category — defined *inline* in [[REST]]/[[SOAP]], not standalone notes |

---

## How they relate

- **Federation trio**: [[SAML]] (XML assertions) and [[OAuth-OIDC]] (tokens) are the two enterprise SSO standards; [[OAuth-OIDC]] carries identity as a [[JWT]].
- **Where they're broken**: the attacks live in [[Class notes/HTB Academy/CPTS v2 (claude)/OAuth-OIDC-SAML|OAuth / OIDC / SAML Attacks]], [[Class notes/HTB Academy/CPTS v2 (claude)/JWT Attacks|JWT Attacks]], and — for the AD/cloud identity side — [[Services/Active Directory/ADFS|ADFS]] (Golden SAML) and [[Services/Active Directory/Entra ID|Entra ID]] (Silver SAML, token theft).
- **Windows auth**: [[NTLM]] underpins relay/PtH; [[Services/Active Directory/Kerberos|Kerberos]] (in `Services/`) is its ticket-based successor.
- **XML substrate**: [[XML]] is the format under [[SAML]]'s signed assertions and every XXE — learn the entity/DTD model once, apply it to both.
- **Web markup**: [[HTML]]'s lenient parsing + code/content mixing is the substrate under XSS / HTML-injection / clickjacking — the [[XML]] of the browser, with SVG/XHTML bridging the two.
- **Passwordless**: [[WebAuthn-FIDO2|WebAuthn / FIDO2]] is the phishing-resistant answer to the credential theft the others suffer — so it's attacked by *downgrade* to a weaker factor, not head-on.
- **Negotiate layer**: [[SPNEGO-GSS|SPNEGO / GSS-API]] chooses [[NTLM]] vs [[Services/Active Directory/Kerberos|Kerberos]] on the wire (`Authorization: Negotiate`) — and is where a client gets *downgraded* from Kerberos to relayable NTLM.
- **Login vs lifecycle**: [[OAuth-OIDC]]/[[SAML]] log a user *in*; [[SCIM]] governs whether the account *exists* (provisioning / deprovisioning) — the other half of enterprise identity, best attacked via [[Class notes/HTB Academy/CWES Claude/API Attacks|API Attacks]].
- **Certificate substrate**: [[X509-PKI|X.509 / PKI]] is the trust format under [[Services/Network management/TLS|TLS]], [[Services/Active Directory/ADCS|ADCS]] (ESC), and the signing certs in [[SAML]]/[[JWT]] — one trust-chain model, many attack surfaces.
- **The two API styles**: [[REST]] (HTTP verbs + [[JSON]], no built-in authz → BOLA/mass-assignment) vs [[SOAP]] (XML envelopes + WSDL contract + WS-Security → XXE/WSDL-enum/signature-wrapping); GraphQL is the third (one endpoint + typed schema, in [[Class notes/HTB Academy/CWES Claude/Intro to GraphQL|Intro to GraphQL]]).
- **Data-format trio**: [[JSON]] is the modern wire format (carried by [[REST]]/[[JWT]]/[[SCIM]]) — the schemaless-object twin of [[XML]] (which SOAP/SAML ride) and the sibling of [[HTML]]; each is "untrusted text → live structure," differing only in *which* trust the parser misplaces.

---

*Created: 2026-07-31*
*Updated: 2026-08-14*
*Model: claude-opus-5*
