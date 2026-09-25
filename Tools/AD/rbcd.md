# rbcd.py

**Tags:** `#rbcd` `#resourcebasedconstraineddelegation` `#kerberos` `#activedirectory` `#delegation` `#python`

Python script that writes `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object to configure Resource-Based Constrained Delegation (RBCD) from an attacker-controlled computer account. Several forks exist (original technique by Elad Shamir; actively maintained implementation: AlteredSecurity/RBCD, built on Impacket). Used after creating/controlling a computer account and confirming write access (`GenericAll`/`GenericWrite`/`WriteDacl`) on the target computer object.

**Source:** https://github.com/AlteredSecurity/RBCD (maintained fork, built on Impacket)
**Install:**
```bash
git clone https://github.com/AlteredSecurity/RBCD
pip install -r RBCD/requirements.txt
```

```bash
# Add EVIL$ as an allowed delegator on the target computer object
python3 rbcd.py -f EVIL -t <target_computer> -dc-ip <dc_ip> '<domain>/<user>:<pass>'
```

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] Resource-Based Constrained Delegation section for the full attack chain (create computer account → set RBCD → S4U2Proxy for a service ticket). Also [[Services/Active Directory/ACL Abuse|ACL Abuse]] — `GenericWrite` on a computer object is what enables the RBCD write in the first place.

---

*Created: 2026-07-27*
*Updated: 2026-09-25*
*Model: claude-sonnet-5*
