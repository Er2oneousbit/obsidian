# ADFSDump

**Tags:** `#adfsdump` `#adfs` `#goldensaml` `#federation` `#activedirectory`

C# tool (Mandiant) that runs **on a compromised ADFS server** in the context of the ADFS service account and dumps everything needed to forge tokens: the token-signing key material, the encrypted config, and the relying-party/claims data from the ADFS configuration database. Its output feeds [[Tools/AD/ADFSpoof|ADFSpoof]] to produce Golden SAML assertions. The non-AADInternals path to the same outcome.

**Source:** https://github.com/mandiant/ADFSDump
**Install:** Build the C# project in Visual Studio; run `ADFSDump.exe` on the ADFS host.

```powershell
# Run as the ADFS service account on the ADFS server
ADFSDump.exe
#  → prints the token-signing private key + config; save it to feed ADFSpoof
```

---

> [!note] **See also** — [[Services/Active Directory/ADFS|ADFS]] — on-server extraction of the token-signing key + config for Golden SAML (pairs with [[Tools/AD/ADFSpoof|ADFSpoof]]).

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
