# davtest

**Tags:** `#davtest` `#webdav` `#upload` `#rce` `#web`

WebDAV exploitation scanner. Against a writable WebDAV-enabled server it automatically uploads test files of many extensions (`.asp`, `.aspx`, `.php`, `.jsp`, `.txt`, `.html`, …), then requests each back to determine **which ones the server will execute** — telling you exactly what shell type to drop. Can also auto-upload a backdoor and MOVE a permitted extension to an executable one. Ships with Kali.

**Source:** https://github.com/cldrn/davtest (Kali: `apt install davtest`)
**Install:** `sudo apt install davtest` — pre-installed on Kali.

```bash
# Fingerprint what a writable WebDAV root will run
davtest -url http://<target>/

# Auth + auto-upload a shell of the executable type it found
davtest -url http://<target>/ -auth user:pass -uploadfile shell.aspx -uploadloc shell.aspx
```

Interactive follow-up client: [[Tools/File Transfer/cadaver|cadaver]].

---

> [!note] **See also** — [[Services/Web Services/IIS|IIS]] — probe a WebDAV-enabled IIS root to learn which extension executes before uploading an ASP/ASPX shell.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
