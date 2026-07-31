# katana

**Tags:** #katana #Crawler #Recon #ContentDiscovery #Fuzzing #ProjectDiscovery #JavaScript #SPA

`katana` is ProjectDiscovery's crawler, with a headless mode that drives a real browser. That matters against single-page apps: a static crawler or a directory brute-forcer sees one `index.html` and nothing else, because every route is client-side and every API path is a string inside a JavaScript bundle. Katana executes the JS, follows what the app actually loads, and with `-jc` parses the bundles for endpoints — routinely surfacing internal and deprecated paths that appear in no wordlist.

**Source:** https://github.com/projectdiscovery/katana
**Install:** `go install github.com/projectdiscovery/katana/cmd/katana@latest`, or `sudo apt install katana` on recent Kali

```bash
# Standard crawl
katana -u https://<TARGET>

# Headless + JS parsing — the mode that matters for SPAs
katana -u https://<TARGET> -headless -jc -d 3

# Authenticated, scoped to the target's own domain
katana -u https://<TARGET> -headless -jc \
  -H "Cookie: session=<token>" \
  -fs fqdn -o endpoints.txt

# Seed from robots.txt / sitemap.xml as well as links
katana -u https://<TARGET> -kf robotstxt,sitemapxml

# Pipe into the rest of the chain
katana -u https://<TARGET> -jc -silent | httpx -silent -mc 200 | tee live.txt
```

| Flag | Description |
|---|---|
| `-headless` | Drive a real browser — required for JS-rendered routes |
| `-jc` | Crawl JavaScript files for endpoints |
| `-d` | Crawl depth |
| `-fs` | Field scope (`fqdn`, `rdn`, `dn`) — keeps you in scope |
| `-kf` | Known files to seed from (`robotstxt`, `sitemapxml`) |
| `-c` / `-p` | Concurrency / parallelism |
| `-rl` | Rate limit — use it on production targets |
| `-silent` | Machine-readable output for piping |

> [!tip] Treat the output as a **wordlist**, not a finished endpoint list — many extracted strings are path fragments needing a prefix. Feed it back through [[Tools/Scanning/ffuf|ffuf]] (`-w endpoints.txt`) to confirm what actually resolves.

> [!warning] Headless mode launches a browser per target and executes attacker-reachable JavaScript on your machine. Keep the scope filter (`-fs fqdn`) on so a stray link doesn't send you crawling third-party sites that aren't in scope.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — crawling and JS endpoint extraction when directory brute-forcing comes up empty; [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — attack-surface mapping.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
