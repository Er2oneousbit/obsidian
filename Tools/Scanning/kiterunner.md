# kiterunner

**Tags:** #kiterunner #API #Fuzzing #ContentDiscovery #WebAppAttacks #Recon #Assetnote

`kiterunner` (`kr`) is Assetnote's API-aware content discovery tool. Ordinary directory brute-forcers fire `GET /word` and miss APIs entirely — real API routes need the right **method**, **path depth**, **headers**, and often a **body** before they answer with anything but 404. Kiterunner replays full request templates from `.kite` wordlists built out of tens of thousands of real-world Swagger/OpenAPI specs, so it finds routes a wordlist scan never will.

**Source:** https://github.com/assetnote/kiterunner
**Install:** download the release binary from GitHub (Go); wordlists come separately from `wordlists.assetnote.io`

```bash
# Grab the route wordlists (.kite format)
wget https://wordlists-cdn.assetnote.io/rawdata/kiterunner/routes-large.kite.tar.gz
tar -xzf routes-large.kite.tar.gz

# Standard scan
kr scan http://<TARGET> -w routes-large.kite

# Authenticated — APIs usually 401 everything without a token
kr scan http://<TARGET> -w routes-large.kite -H "Authorization: Bearer <token>"

# Scan many hosts, tune concurrency
kr scan hosts.txt -w routes-large.kite -x 10 -j 100

# Brute mode with a plain text wordlist instead of .kite templates
kr brute http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Replay an interesting hit through Burp to inspect it properly
kr kb replay -w routes-large.kite --proxy=http://127.0.0.1:8080 "<the result line kr printed>"
```

| Flag | Description |
|---|---|
| `-w` | Wordlist (`.kite` for templates, `.txt` for brute mode) |
| `-H` | Add a header — use for auth tokens |
| `-x` | Max connections per host |
| `-j` | Max parallel hosts |
| `-d` | Preflight depth |
| `--ignore-length` | Filter out a repeated soft-404 body length |
| `kb replay` | Re-issue a single result, optionally through a proxy |

> [!tip] Always run it authenticated if you have any credential at all. An unauthenticated pass against a token-protected API returns a wall of 401s and tells you almost nothing about which routes exist.

> [!note] `.kite` files are a compiled binary format — you can't `cat` or edit them. Use `kr wordlist list` to see what's installed and `kr wordlist save` to pull one down locally.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — API endpoint discovery; pairs with [[Tools/Web/Arjun|Arjun]] for parameters once you have a route.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
