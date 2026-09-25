# WebLogicPasswordDecryptor

**Tags:** `#weblogic` `#oracle` `#credentials` `#decryption` `#postexploitation`

Offline decryptor for Oracle WebLogic's encrypted secrets (NetSPI). WebLogic stores admin, JDBC datasource, and other passwords in a domain's `config.xml` (and `jdbc/*.xml`) as `{AES}...` / `{3DES}...` blobs, encrypted with a domain-specific key held in `SerializedSystemIni.dat`. Given both files (read after any file-read/RCE on the host), this tool recovers the cleartext — turning a foothold into reusable admin/DB credentials for lateral movement. Python (a PowerShell port also exists).

**Source:** https://github.com/NetSPI/WebLogicPasswordDecryptor
**Install:** `git clone https://github.com/NetSPI/WebLogicPasswordDecryptor` (Python).

```bash
# Need: SerializedSystemIni.dat (the key) + the {AES} ciphertext from config.xml
python3 decrypt.py --key SerializedSystemIni.dat --config config.xml
python3 decrypt.py --key SerializedSystemIni.dat --password "{AES}<base64>"
```

---

> [!note] **See also** — [[Services/Web Services/WebLogic|WebLogic]] — post-exploitation decrypt of `config.xml` `{AES}` admin/JDBC secrets using the domain's `SerializedSystemIni.dat`.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
