# ciscot7

**Tags:** #ciscot7 #cisco #passwords #credentials

`ciscot7` decodes Cisco **Type 7** passwords, which are not encryption but a trivially reversible Vigenère-style XOR against a fixed key table. Any `password 7 <hex>` / `key 7 <hex>` string pulled from an ASA/IOS `running-config` is instantly recoverable — no cracking, no wordlist. (Type 5 `$1$` md5crypt, Type 8 `$8$` PBKDF2, and Type 9 `$9$` scrypt are *real* hashes — crack those with hashcat modes 500/9200/9300 instead.)

**Source:** https://github.com/theevilbit/ciscot7 (`pip install ciscot7`)
**Install:** `pipx install ciscot7`

```bash
ciscot7 094F471A1A0A           # decode a single Type-7 string
# pull all reversible/crackable secrets from a dumped config:
grep -E 'password 7|key 7|secret [0-9]' running-config.txt
```

> [!note] **See also** — [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect / ASA]] (ASA config password cracking); [[Services/File Xfer/TFTP|TFTP]] / [[Techniques/Network Device Pentesting|Network Device Pentesting]] (looting Cisco configs). Crack the non-reversible types with [[Tools/Auth/hashcat|hashcat]].

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
