# TokenTactics

**Tags:** `#tokentactics` `#entraid` `#azuread` `#oauth` `#tokentheft` `#cloud` `#powershell`

PowerShell module (originally rvrsh3ll/0xBoku, actively maintained fork **TokenTacticsV2** by f-bader with CAE and v2 token endpoint support) for manipulating Entra ID OAuth tokens — requesting device-code tokens, refreshing an access token, and swapping a refresh token across resources/client IDs (the manual PowerShell equivalent of what [[Tools/Cloud/ROADtools|ROADtools]]'s `roadtx` does from Linux). Useful for turning one stolen refresh token into tokens for Graph, Exchange Online, SharePoint, or Azure ARM without re-authenticating.

**Source:** https://github.com/rvrsh3ll/TokenTactics (original) / https://github.com/f-bader/TokenTacticsV2 (maintained fork, recommended)
**Install:**
```powershell
git clone https://github.com/f-bader/TokenTacticsV2
Import-Module .\TokenTacticsV2\TokenTacticsV2.psd1
```

```powershell
# Device code phishing — get an initial token
Get-AzureToken -Client MSGraph -Device

# Refresh a token / swap to a different resource with the same refresh token
RefreshTo-MSGraphToken -domain <domain> -refreshToken $response.refresh_token
RefreshTo-AzureCoreManagementToken -domain <domain> -refreshToken $response.refresh_token

# Decode a JWT for inspection
ConvertFrom-JWT -token $response.access_token
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Token Theft & Abuse and FOCI Abuse sections — this tool automates the manual `curl` refresh-token exchanges shown there.
> Also used in [[Techniques/OAuth-OIDC-SAML|OAuth / OIDC / SAML Attacks]] (device code phishing, FOCI pivot, PRT escalation).

---

*Created: 2026-07-27*
*Updated: 2026-07-31*
*Model: claude-opus-5*
