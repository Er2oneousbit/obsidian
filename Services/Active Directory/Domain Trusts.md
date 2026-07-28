# Domain Trusts

#DomainTrusts #ActiveDirectory #SIDHistory #CrossForest #Privesc

## What is Domain Trusts (abuse)?

Domains and forests can establish trust relationships (one-way, two-way, parent-child, cross-forest) that let authentication flow between them. Misconfigured or overly-permissive trusts enable lateral movement across trust boundaries — SID History injection, forging inter-realm TGTs with a stolen trust key, and abusing gaps in selective authentication or unconstrained delegation across the trust to escalate from a compromised child domain to the forest root, or between separate forests entirely.

*Content pending — see TODO.md for planned scope.*

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
