# _Techniques (MOC)

Map of content for **Techniques/** — Claude-authored offensive **attack-technique** notes that don't belong to a single CPTS/CWES module, a service, a tool, a protocol, or a framework.

## What lives here

Attack-technique references that stand on their own, independent of *how* you reached the situation. Two flavours: **cross-cutting workflows** ([[Techniques/Container Escape|Container Escape]] — you can land in a container from a web RCE, an SSH cred, or a chained privesc; the escape workflow is the same), and **web/app attack classes that aren't a CPTS/CWES module of their own** (CSRF, JWT, deserialization, NoSQLi, …). Both would otherwise be buried inside a module note that only half-owns them, so each earns a standalone note.

## What does *not* live here

| Content | Home |
|---|---|
| A technique that **is** a CPTS/CWES module | `Class notes/HTB Academy/CPTS v2 (claude)/` or `CWES Claude/` |
| Enumerating/attacking a specific listening **service** | `Services/` |
| Using a specific third-party **tool** | `Tools/` |
| **Our own** scripts / offensive kit + lessons | `Exploits/` |
| A **protocol / data-format** concept (what it is, why attackable) | `Standards & Protocols/` |
| A **framework / compliance** reference | `Frameworks and Compliance/` |

Notes here follow the [[Class notes/HTB Academy/Notes|CWES/CPTS note skeleton]] (tag line → What is this? → Tools table → body → Quick Reference → footer).

---

## Notes

### Web / application
- [[Techniques/CORS Misconfiguration|CORS Misconfiguration]] — attacker-origin reads of authenticated responses; browser-enforced only.
- [[Techniques/CSRF Attacks|CSRF Attacks]] — forcing authenticated state-changing requests; token / SameSite bypasses.
- [[Techniques/Null Origin Attacks|Null Origin Attacks]] — abusing `Origin: null` trust (sandboxed iframes, redirects, local files).
- [[Techniques/JWT Attacks|JWT Attacks]] — `alg:none`, RS256→HS256 confusion, `kid`/`jku`/`jwk` injection, secret cracking.
- [[Techniques/OAuth-OIDC-SAML|OAuth-OIDC-SAML]] — SSO/token attacks: `redirect_uri` abuse, XSW, signature stripping, device-code phishing.
- [[Techniques/Deserialization|Deserialization]] — object-injection → RCE gadget chains (Java / PHP / Python / Ruby / .NET).
- [[Techniques/NoSQL Injection|NoSQL Injection]] — operator injection, auth bypass, blind extraction (Mongo et al.).
- [[Techniques/LDAP Injection|LDAP Injection]] — filter injection → auth bypass, attribute enumeration, blind extraction.
- [[Techniques/WebSockets|WebSockets]] — CSWSH, message tampering, auth gaps over `ws://`.
- [[Techniques/Non-PHP Web App Attacks|Non-PHP Web App Attacks]] — LFI→RCE / injection chains on non-PHP stacks (SSTI, deserialization).

### Infrastructure / host
- [[Techniques/Container Escape|Container Escape]] — breaking out of a container to the host: socket, capabilities, `release_agent`, host mounts, K8s pod→node.
- [[Techniques/Network Device Pentesting|Network Device Pentesting]] — routers/switches/firewalls: SNMP, default creds, vendor CVEs (Cisco/Palo/Fortinet/Juniper/F5).

### Evasion
- [[Techniques/AV & EDR Evasion|AV & EDR Evasion]] — AMSI bypass, payload obfuscation, process injection, EDR unhooking.

---

*Created: 2026-08-28*
*Updated: 2026-08-28*
*Model: claude-opus-5*
