# pyAesBrute

**Tags:** `#pyAesBrute` `#pyAesCrypt` `#bruteforce` `#aes` `#cracking` `#loot` `#dictionary` `#multicore` `#ownfork`

A Python 3 dictionary brute-forcer for **AES Crypt / pyAesCrypt** (`.aes`) encrypted files. When you loot a password-protected `.aes` archive (a common backup format — `pyAesCrypt` appends `.aes` by default), pyAesBrute tries each word in a wordlist as the password and writes the decrypted output on success. It's the "crack the backup" step after you've found the archive.

**Source:** https://github.com/Er2oneousbit/pyAesBrute — own **multicore** rewrite (forked from [wyn-cmd/pyAesBrute](https://github.com/wyn-cmd/pyAesBrute), which is single-threaded)
**Install:** `git clone https://github.com/Er2oneousbit/pyAesBrute && pip install pyAesCrypt`

```bash
# python3 pybrute.py <wordlist> <encrypted .aes file> <output file>
python3 pybrute.py /usr/share/wordlists/rockyou.txt backup.aes backup.tar
```

---

## When you reach for it

You've pulled an encrypted archive off a target and need its password:

```bash
# Find .aes backups (pyAesCrypt's default extension)
find /var/backup /var/backups /opt /home -name '*.aes' 2>/dev/null

# Hint that pyAesCrypt is even in play: it shows up in a Flask/Python app's deps
curl -s "http://<t>/?file=/app/requirements.txt" | grep -i aescrypt
```

Then brute the password with pyAesBrute (above). If you already **know/guess** the password, skip brute-forcing and decrypt directly:

```bash
python3 -c "import pyAesCrypt; pyAesCrypt.decryptFile('backup.aes','backup.tar','<password>')"
```

> [!note] Like every dictionary attack, this only works for **weak/guessable** passwords — AES-256 itself isn't brute-forced, only the passphrase. The [Er2oneousbit fork](https://github.com/Er2oneousbit/pyAesBrute) adds **multicore** processing (the upstream is single-threaded), so it scales across CPUs on big wordlists. Other multithreaded options if needed: [AESCrypt-bruteforce-tool](https://github.com/pbelskiy/AESCrypt-bruteforce-tool) (loads the file once, `ncpu` threads) and [abrute](https://github.com/danielpclark/abrute) (resume/cluster support, also does `.zip`).

---

> [!note] **See also**
> The loot source that leads here: [[Services/Web Services/Flask|Flask]] (requirements.txt → pyAesCrypt → hunt `.aes` in `/var/backup`). Decrypted archives feed credential hunting in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] and wordlist/spraying work in [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]].

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
