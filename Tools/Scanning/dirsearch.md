# dirsearch

**Tags:** #dirsearch #Fuzzing #ContentDiscovery #WebAppAttacks #Recon #Python

`dirsearch` is a Python web path scanner. Its draw over [[Tools/Scanning/ffuf|ffuf]] is that it works well out of the box — it ships a curated default wordlist, expands extensions automatically via a `%EXT%` placeholder, and filters noise without you having to baseline the target first. Good for a fast first look; reach for ffuf or [[Tools/Scanning/feroxbuster|feroxbuster]] when you need speed or fine-grained filtering.

**Source:** https://github.com/maurosoria/dirsearch
**Install:** ships in Kali (`dirsearch`), or `pipx install dirsearch`

```bash
# Default wordlist, common web extensions
dirsearch -u http://<TARGET> -e php,html,txt,bak

# Custom wordlist, recurse into what it finds
dirsearch -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -r

# Authenticated scan, saving results
dirsearch -u http://<TARGET> --cookie "session=<token>" -o results.txt --format plain

# Scan many hosts from a file, through Burp
dirsearch -l hosts.txt --proxy http://127.0.0.1:8080
```

| Flag | Description |
|---|---|
| `-e` | Extensions to append (`%EXT%` in a wordlist expands to each) |
| `-r` | Recursive scanning |
| `-R` | Max recursion depth |
| `-x` | Exclude status codes (e.g. `-x 403,404`) |
| `-i` | Include only these status codes |
| `--exclude-sizes` | Filter soft-404s by response size |
| `-t` | Threads (default 25) |
| `--random-agent` | Rotate User-Agent |

> [!note] The default wordlist is small by design. On a real target follow up with a raft or directory-list wordlist via `-w` — a clean dirsearch run is not evidence there's nothing there.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — directory and file content discovery.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
