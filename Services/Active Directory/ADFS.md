# ADFS

#ADFS #Federation #SAML #ActiveDirectory #GoldenSAML

## What is ADFS?

Active Directory Federation Services is Microsoft's on-prem SAML/WS-Fed identity provider, most commonly used to federate on-prem AD with Entra ID or other SaaS relying parties. Compromising the ADFS server — or extracting its DKM encryption key from AD without ever touching the server directly — exposes the token-signing certificate, enabling Golden SAML: forging SAML assertions for any federated user, entirely offline, bypassing the real authentication stack. See [[Services/Active Directory/Entra ID|Entra ID]]'s Golden Ticket-adjacent Golden SAML section for the cloud-side consumption of a forged token; this note is meant to own the on-prem ADFS-side enumeration and key-extraction methodology, which is currently only thinly covered there.

*Content pending — see TODO.md for planned scope.*

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
