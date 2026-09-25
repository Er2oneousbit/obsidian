# IIS-ShortName-Scanner

**Tags:** `#iis` `#shortname` `#tilde` `#enumeration` `#windows` `#web`

Exploits the IIS tilde (`~`) short-name (8.3 filename) information-disclosure. IIS returns a different response (404 vs 400/other) depending on whether a guessed 8.3 short name prefix matches a real file/folder, so the tool brute-forces the first six characters of every hidden file and directory under the web root — recovering partial names like `SECRET~1.ASP` that you then expand into full guesses. Affects IIS through 8.0 (and later with certain configs). Java tool.

**Source:** https://github.com/irsdl/IIS-ShortName-Scanner
**Install:** Clone the repo; run with a JRE (`java -jar iis_shortname_scanner.jar`). Needs `config.xml` alongside the jar.

```bash
# Args: <thread count> <max show length> <URL>
java -jar iis_shortname_scanner.jar 20 8 http://<target>/

# Manual equivalent — 404 = no match, 400 = prefix matches (file exists)
curl -s -o /dev/null -w "%{http_code}" "http://<target>/s*~1*/a.aspx"
```

---

> [!note] **See also** — [[Services/Web Services/IIS|IIS]] — tilde short-name enumeration to discover hidden `.aspx`/`.config`/backup filenames before content brute-forcing.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
