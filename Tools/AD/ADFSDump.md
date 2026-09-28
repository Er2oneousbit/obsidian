# ADFSDump

**Tags:** `#adfsdump` `#adfs` `#goldensaml` `#federation` `#activedirectory`

C# tool (Mandiant) that runs **on a compromised ADFS server** in the context of the ADFS service account and dumps everything needed to forge tokens: the token-signing key material, the encrypted config, and the relying-party/claims data from the ADFS configuration database. Its output feeds [[Tools/AD/ADFSpoof|ADFSpoof]] to produce Golden SAML assertions. The non-AADInternals path to the same outcome.

**Source:** https://github.com/mandiant/ADFSDump
**Install:** Build the C# project in Visual Studio (.NET 4.5); run `ADFSDump.exe` on the ADFS host.

> [!warning] **Three hard runtime constraints** — miss any one and it fails:
> 1. **Must run as the AD FS *service account*.** Only that account can read the configuration database — **not even a Domain Admin can.** Grab the account from a process listing on the ADFS server or `Get-ADFSProperties`, then run ADFSDump in its context (e.g. a stolen ticket / `runas /netonly`, or after impersonating the service's token).
> 2. **Must run *locally* on an AD FS server, not the Web Application Proxy (WAP).** The default store is the Windows Internal Database (WID), reachable only over a local named pipe.
> 3. Assumes **WID**. For a remote SQL config store, pass `/database:` with the connection string.

```powershell
# Standard run — dumps all three artifacts to STDOUT (redirect to a file to feed ADFSpoof)
ADFSDump.exe > adfs_dump.txt

# Skip the DKM key line (if you already have it, or want a smaller dump)
ADFSDump.exe /nokey

# Remote SQL config store instead of WID (wrap the whole connstring in quotes)
ADFSDump.exe /database:"Data Source=sql.domain.com;Initial Catalog=AdfsConfigurationV4;Integrated Security=True"
```

**What it outputs (all to STDOUT), and why each piece matters:**

| Artifact | Source | Used for |
|---|---|---|
| **DKM master key** | Active Directory (the AD FS DKM container) | Decrypts the EncryptedPFX below — **without it the signing key is useless**. This is the piece a plain cert-export misses. |
| **EncryptedPFX blob** | Config DB | The **token-signing** key/cert pair (encrypted with the DKM key). Decrypt → sign forged SAML/JWT. |
| **Relying parties** | Config DB | Per-app: RP identifier, signature algorithm, **token-encryption cert**, issuance/claims rules, access-control rules — everything ADFSpoof needs to mint a token a specific RP will accept. |

> [!note] Feed the DKM key + EncryptedPFX to [[Tools/AD/ADFSpoof|ADFSpoof]]'s `-b` (blob) argument, and the per-RP identifier/endpoint to its `o365`/`saml2` sub-commands. This is the **non-AADInternals** path — AADInternals' `Export-AADIntADFSSigningCertificate` reaches the same signing key from a DA on the DC via DKM, off-box.

---

> [!note] **See also** — [[Services/Active Directory/ADFS|ADFS]] — on-server extraction of the token-signing key + config for Golden SAML (pairs with [[Tools/AD/ADFSpoof|ADFSpoof]]).

---

*Created: 2026-09-25*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
