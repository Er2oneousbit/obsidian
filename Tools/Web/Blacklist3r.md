# Blacklist3r

**Tags:** `#blacklist3r` `#aspnet` `#viewstate` `#machinekey` `#deserialization` `#web`

Recovers/identifies known ASP.NET `machineKey` values (validation + decryption keys). Many apps ship with a sample, tutorial, or hardcoded `machineKey`, or reuse one leaked publicly. Blacklist3r (the `.NET` `AspDotNetWrapper` tool) takes a captured `__VIEWSTATE` and tests it against a wordlist of known keys — when the MAC validates, you've recovered the keys needed to forge a signed ViewState and reach [[Tools/Payloads & Shells/ysoserial.net|ysoserial.net]] deserialization RCE. Also covers Forms-auth cookies and other MAC-protected blobs.

**Source:** https://github.com/NotSoSecure/Blacklist3r
**Install:** Download the `AspDotNetWrapper` release, or build the .NET solution; run under Windows or `mono`.

```bash
# Test a captured __VIEWSTATE against a known-key list
AspDotNetWrapper.exe --keypath machinekeys.txt \
  --encrypteddata <__VIEWSTATE value> --purpose=viewstate \
  --valalgo=sha1 --decalgo=aes

# Recovered keys then feed:  ysoserial.exe -p ViewState --validationkey=... --decryptionkey=...
```

---

> [!note] **See also** — [[Services/Web Services/IIS|IIS]] — recover a leaked/default `machineKey` (or one read via web.config disclosure) to forge a `__VIEWSTATE` for deserialization RCE, paired with [[Tools/Payloads & Shells/ysoserial.net|ysoserial.net]].

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
