# SCIM

#SCIM #Provisioning #Identity #REST #JSON #Lifecycle #SaaS #Standard #APIAttacks #Deprovisioning

## What is it?

**SCIM (System for Cross-domain Identity Management)** — RFCs 7642/7643/7644 — is the standard **REST + JSON API for automating the user lifecycle** across applications: create, update, and *deprovision* accounts. Where SSO ([[OAuth-OIDC]] / [[SAML]]) handles *logging in*, SCIM handles *account existence* — when HR/IdP (Okta, Entra, OneLogin) onboards or offboards someone, it pushes that change to every connected SaaS via a uniform `/scim/v2` endpoint. Security-wise it's a paradox: a **highly privileged, internet-facing, machine-to-machine API that creates and mutates user accounts**, usually guarded by a single long-lived **bearer token**. That combination is exactly why it's a rising attack target. This note is the standard; the attack surface (which is API security applied to identity) is under [[#Attacked by]].

---

## How it works

The **Identity Provider is the SCIM client**; the **application is the Service Provider** exposing the endpoint. Resources are **Users** and **Groups**, each with a schema (`userName`, `name`, `emails`, `active`, `groups`, an enterprise extension) plus `id`, `externalId`, and `meta`.

```mermaid
sequenceDiagram
    autonumber
    participant IdP as Identity Provider
    participant SP as Service Provider
    Note over IdP,SP: IdP (Okta / Entra) is the SCIM client; SP exposes /scim/v2.<br/>One bearer token authenticates every call.
    IdP->>SP: POST /Users  (onboard new hire)
    SP-->>IdP: 201 Created — id, externalId, meta
    IdP->>SP: PATCH /Users/ID  (attribute / group change)
    IdP->>SP: PATCH /Users/ID active:false  OR  DELETE  (offboard)
    SP-->>IdP: 200 OK
```

| Endpoint | Purpose |
|---|---|
| `/scim/v2/Users` , `/Groups` | CRUD on identities and groups (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`) |
| `?filter=userName eq "alice"` | Query/lookup — the SCIM filter language |
| `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` | Discovery — what the SP supports (unauth on some deployments) |
| `/Bulk` | Batch operations |

---

## Trust model — where it breaks

The SP grants a bearer token the power to *be the source of truth for who exists and what they can do* — then trusts everything that token says. Every SCIM attack pulls on that.

| Assumption the design rests on | When it fails… | Attack (methodology in the linked note) |
|---|---|---|
| The token stays secret **and tightly scoped** | Leaked, or scoped to tenant-wide CRUD | Full user CRUD — **create an admin, exfiltrate every identity** (one token = keys to the kingdom) |
| The provisioning source can be **trusted for identity** | `PATCH` of `userName`/`email` accepted without re-verification | **Account takeover** — change a victim's email → password-reset to attacker (GitLab-class bug) |
| Attributes map **safely** to roles | Over-generous attribute→role mapping / unvetted custom attrs | **Privilege escalation** — nudge a `groups`/role/custom value the role engine trusts |
| Per-tenant **isolation** is enforced | Broken object/tenant authz | Cross-tenant read/write — **BOLA** on `/Users/ID` |
| Deprovisioning is **honored and timely** | SP ignores or delays deactivation | **Persistence** — a deactivated (or attacker) account keeps SaaS access |
| Filtering doesn't **overexpose** | `?filter` returns all users + PII | Enumeration / excessive data exposure |
| Input is validated | **SCIM filter injection**, mass-assignment of `active`/roles | Logic bypass |

> [!warning]
> The single highest-impact SCIM bug is the **`userName`/email PATCH → ATO**: because the SP trusts the provisioning channel, a SCIM email change often skips the verification a normal profile edit would trigger. If you hold (or can reach) a SCIM token, test that first.

---

## Attacked by

- [[Class notes/HTB Academy/CWES Claude/API Attacks|API Attacks]] — SCIM *is* a REST API, so the whole toolkit applies directly: **BOLA** on `/Users/ID`, **mass assignment** (`active`, `groups`, custom attributes), **excessive data exposure** via `?filter`, and **broken auth** on the bearer token. This is the primary lens.
- [[OAuth-OIDC]] — the SCIM bearer token is typically an OAuth token; stealing it grants full provisioning power, and SSO (OIDC login) + SCIM (lifecycle) are the two halves of every enterprise identity integration.

**Recon/testing:** enumerate `/ServiceProviderConfig` and `/Schemas` (often unauthenticated) to map capabilities; test the token's blast radius with a benign `GET /Users?count=1` before anything destructive. Doyensec's "SCIM Hunting" (2025) is the current pentest reference.

---

## See also

[[OAuth-OIDC]] / [[SAML]] (the *login* half — SCIM is the *lifecycle* half), [[JWT]] (what the bearer token often is)  ·  Index: [[_Standards & Protocols]]

*Created: 2026-07-31*
*Updated: 2026-07-31*
*Model: claude-opus-4-8*
