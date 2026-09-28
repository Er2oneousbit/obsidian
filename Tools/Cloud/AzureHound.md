# AzureHound

**Tags:** `#azurehound` `#bloodhound` `#entraid` `#azuread` `#cloud` `#enumeration` `#attackpaths`

Go-based BloodHound data collector for Entra ID and Azure RBAC — the cloud counterpart to
on-prem SharpHound. Walks the tenant's users, groups, applications, service principals,
devices, directory roles, and Azure resource role assignments (over **MS Graph + ARM**),
then outputs BloodHound-compatible JSON for attack-path analysis. Pairs with
[[Tools/Cloud/BARK|BARK]]: collect the graph with AzureHound, identify a path in BloodHound,
execute each hop with the matching BARK primitive.

**Source:** https://github.com/SpecterOps/AzureHound (moved from BloodHoundAD; old URL redirects)
**Install:** download a prebuilt binary from the SpecterOps/AzureHound releases (most reliable), or build from source with `go build`

---

## Authentication

AzureHound needs a credential that can read the directory. Pick by what you hold — and
mind the MFA trap below:

```bash
# Username / password (ROPC) — simplest, but see the warning: usually blocked by MFA/CA
./azurehound -u "user@company.com" -p "Password1" list --tenant "<tenant-id>" -o output.json

# Access token (JWT) — no interactive auth; get one from az (see bridge below)
./azurehound --jwt "<access-token>" list --tenant "<tenant-id>" -o output.json

# Refresh token — PREFERRED for a full run: AzureHound refreshes tokens for BOTH the
# Graph and ARM audiences itself, so you get identity + resource-RBAC data in one pass
./azurehound -r "<refresh-token>" list --tenant "<tenant-id>" -o output.json
```

> [!warning] **ROPC (`-u`/`-p`) usually fails on real tenants.** Resource-Owner-Password-
> Credential auth is blocked by MFA and most Conditional-Access policies, and is disabled
> outright when Security Defaults are on. On a live engagement prefer a **refresh token** or
> a **JWT** obtained through a flow the tenant actually allows (device code, a stolen token,
> or an `az` session), not raw username/password.

### Bridge from azure-cli

Reuse an existing [[Tools/Cloud/azure-cli|az]] session instead of re-authenticating — grab a
Graph token and hand it to AzureHound:

```bash
TOKEN=$(az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv)
./azurehound --jwt "$TOKEN" list --tenant "$(az account show --query tenantId -o tsv)" -o output.json
```

---

## Commands

```bash
./azurehound list --tenant "<tid>" -o output.json     # one-shot: collect everything → JSON
./azurehound list users --tenant "<tid>"              # narrow to one object type (see `list --help` for all)
./azurehound configure                                # write a config file (creds, BHE instance) to reuse
./azurehound start --tenant "<tid>"                   # continuous collection service for BloodHound Enterprise
```

- **`list`** is the pentest workhorse: run it once, take the JSON.
- **`start`** streams data to a **BloodHound Enterprise** instance on a schedule (config-driven) — for standing monitoring, not a one-off assessment.
- Run `./azurehound list --help` for the full set of narrow collection targets rather than guessing their names.

---

## Import & Analyse

```
# BloodHound CE: log in → Administration / File Ingest (or drag output.json onto the UI),
# then run the pre-built Azure cypher queries / mark tier-zero and find shortest paths to
# Global Admin, Privileged Role Administrator, or Owner on a subscription.
```

> [!tip] **Large tenants throttle.** MS Graph rate-limits aggressive enumeration; a big
> tenant collection can take a while and may need re-runs. A refresh token survives the run
> better than a short-lived JWT that can expire mid-collection.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] for the broader attack methodology; [[Tools/Cloud/azure-cli|azure-cli]] to source a token (and to enumerate the same RBAC by hand); [[Tools/Cloud/BARK|BARK]] for executing abuse primitives once a path is identified; [[Tools/Cloud/ROADtools|ROADtools]] for token/refresh-token acquisition to feed `-r`.

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
