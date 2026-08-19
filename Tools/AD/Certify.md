# Certify

**Tags:** `#certify` `#adcs` `#activedirectory` `#certificateservices` `#esc` `#privesc` `#dotnet` `#ghostpack`

Windows C# tool (GhostPack) for enumerating and abusing Active Directory Certificate Services (AD CS) misconfigurations — the .NET/on-host counterpart to [[Tools/AD/Certipy|Certipy]]. Enumerates CAs and certificate templates, flags vulnerable configurations (ESC1/ESC2/ESC6 patterns), and requests certificates on behalf of the current or a specified user. Commonly paired with [[Tools/Lateral Movement/Rubeus|Rubeus]] to convert the resulting certificate into a usable Kerberos ticket.

**Source:** https://github.com/GhostPack/Certify
**Install:** build from source with Visual Studio/`msbuild`, or drop a prebuilt binary — no package manager distribution.

```powershell
# Enumerate CAs
.\Certify.exe cas

# Enumerate all templates / only vulnerable ones
.\Certify.exe find
.\Certify.exe find /vulnerable
.\Certify.exe find /vulnerable /currentuser

# Request a certificate with an alternate SAN (ESC1-style)
.\Certify.exe request /ca:<domain>\<CA_Name> /template:<Template> /altname:Administrator
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] for the full ESC1–ESC16 attack methodology this tool is used against. Also [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]] (CPTS v2) — AD CS enumeration and abuse from a Windows host.

---

*Created: 2026-07-27*
*Updated: 2026-08-18*
*Model: claude-opus-5*
