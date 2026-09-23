# KrbRelayUp

**Tags:** #AD #Kerberos #relay #privesc #RBCD #LateralMovement

A one-stop **local privilege escalation** tool for domain-joined Windows hosts, wrapping the KrbRelay technique. A low-privileged user coerces local Kerberos authentication, relays the AP-REQ to LDAP (or SCM), and configures **Resource-Based Constrained Delegation** — or a **Shadow Credential** — against the machine's *own* computer account, then uses S4U to obtain a SYSTEM service ticket and spawn a SYSTEM process. It's the Kerberos-only counterpart to the classic NTLM-relay-to-LDAP local privesc, and it works where NTLM has been disabled.

**Source:** https://github.com/Dec0ne/KrbRelayUp (builds on cube0x0's KrbRelay)
**Install:** compile the C# project in Visual Studio, or use a precompiled release `KrbRelayUp.exe`.

```powershell
# RBCD back-end: relay to LDAP, create a computer account, set RBCD on the local machine
.\KrbRelayUp.exe relay -Domain <domain> -CreateNewComputerAccount -ComputerName EVIL$ -ComputerPassword Password123
.\KrbRelayUp.exe spawn -m rbcd -d <domain> -cn EVIL$ -cp Password123 -i <local_machine_sid>

# Shadow-credential back-end (no new computer account)
.\KrbRelayUp.exe full -m shadowcred -d <domain>
```

> [!warning] The RBCD path requires that LDAP signing / channel binding is **not** enforced — the same hardening gap that stops NTLM relay to LDAP stops this. Enforcing LDAP signing + EPA is the fix; note it in the report when the attack succeeds.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/Kerberos|Kerberos]] — the Kerberos-relay local-privesc section (distinct from domain-wide RBCD).
> Related tooling: [[Tools/AD/rbcd|rbcd.py]] (the RBCD write primitive from Linux), [[Tools/Lateral Movement/Rubeus|Rubeus]] (`s4u` step performed manually), [[Tools/Lateral Movement/impacket|impacket]] (`getST`/`addcomputer` for the manual equivalent).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
