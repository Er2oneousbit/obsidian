# chainbreaker

**Tags:** `#chainbreaker` `#macos` `#keychain` `#credentialdumping` `#loot` `#hashcat` `#postexploitation`

Offline macOS **Keychain** extractor (n0fate) — parses a `.keychain`/`.keychain-db` file and
decrypts the stored secrets (internet & generic passwords, private/public keys, X.509 certs,
secure notes, AppleShare creds). The macOS peer of [[Tools/Credential Dumping/SharpDPAPI|SharpDPAPI]]
(Windows DPAPI) / [[Tools/Auth/Firefox Decrypt|Firefox Decrypt]] (browser store): the keychain
**is** the macOS credential store, so this is the "loot the box" step on a Mac. Supports OS X
Snow Leopard → macOS Ventura.

**Source:** https://github.com/n0fate/chainbreaker
**Install:** `git clone … && pip install -e .`

---

## Where the Keychains Live

```bash
~/Library/Keychains/login.keychain-db        # per-user — unlocked by the user's LOGIN password
/Library/Keychains/System.keychain           # system-wide — unlocked by /var/db/SystemKey (root)
```

## Extract

```bash
# Prompt for the user's login password, dump everything, export to a dir
python -m chainbreaker -pa ~/Library/Keychains/login.keychain-db -o output
#   -p / --password-prompt   ask for the password   |   -a / --dump-all   dump all records

# Non-interactive password
python -m chainbreaker --password 'Passw0rd!' -a login.keychain-db

# System keychain — unlock with the SystemKey file (root-readable)
python -m chainbreaker --unlock-file /var/db/SystemKey -a /Library/Keychains/System.keychain

# Master key recovered from memory (volatility etc.) instead of a password
python -m chainbreaker --key <masterkey-hex> -a login.keychain-db
```

## Crack the Keychain Password Offline

If you don't have the login password, pull the crackable hash and feed a cracker:

```bash
python -m chainbreaker --dump-keychain-password-hash login.keychain-db
# → crack with hashcat mode 23100 (Apple Keychain):
hashcat -m 23100 keychain.hash /usr/share/wordlists/rockyou.txt
```

Cross-links to [[Tools/Auth/hashcat|hashcat]] / [[Tools/Auth/john the ripper|john]].

---

## Live Access — the built-in `security` CLI

On a **live** compromised Mac (session unlocked, or you have the password) you often don't need
chainbreaker at all — Apple's own `security` tool reads the keychain:

```bash
security dump-keychain -d ~/Library/Keychains/login.keychain-db   # -d = decrypted (may prompt/GUI-consent)
security find-generic-password -ga <service>                       # a specific secret's cleartext
security find-internet-password -ga <server>
```

> [!warning] `security ... -d` and unlocking a locked keychain trigger a **GUI authorization
> prompt** (and are logged). chainbreaker on the *file* (with a known/cracked password or
> master key) is the quieter, offline path — take the `.keychain-db` off the box and crack/parse
> it on your side.

---

## Quick Reference

| Goal | Command |
|---|---|
| Dump a user keychain (prompt pw) | `python -m chainbreaker -pa login.keychain-db -o out` |
| Dump with known password | `python -m chainbreaker --password 'pw' -a login.keychain-db` |
| System keychain (root) | `python -m chainbreaker --unlock-file /var/db/SystemKey -a System.keychain` |
| Get crackable hash | `python -m chainbreaker --dump-keychain-password-hash login.keychain-db` |
| Crack it | `hashcat -m 23100 keychain.hash rockyou.txt` |
| Live read (built-in) | `security dump-keychain -d login.keychain-db` |

---

> [!note] **See also** — Windows credential-store peers [[Tools/Credential Dumping/SharpDPAPI|SharpDPAPI]] / [[Tools/Credential Dumping/DonPAPI|DonPAPI]]; cross-platform harvester (also does the Mac keychain) [[Tools/Auth/LaZagne|LaZagne]]; browser store [[Tools/Auth/Firefox Decrypt|Firefox Decrypt]]; crack the hash [[Tools/Auth/hashcat|hashcat]] (`-m 23100`).

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
