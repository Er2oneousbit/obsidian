# hakrawler

**Tags:** #hakrawler #Crawler #Recon #ContentDiscovery #JavaScript #hakluke #Golang

`hakrawler` is hakluke's fast Go web crawler for harvesting URLs and JavaScript file locations. It is a **static** crawler — it fetches pages and parses links, forms, and `<script>` src attributes, but it does **not** execute JavaScript. That makes it the fast first pass: it reads a URL on **stdin** and streams results to **stdout**, so it drops straight into a recon pipeline. When a target is a JavaScript-heavy SPA where routes and API paths only exist after the bundle runs, reach for [[Tools/Recon/katana|katana]] `-headless -jc` instead — hakrawler will see the shell `index.html` and little else.

**Source:** https://github.com/hakluke/hakrawler
**Install:** `go install github.com/hakluke/hakrawler@latest`

```bash
# Standard crawl — input on stdin, one seed URL
echo https://<TARGET> | hakrawler

# Deeper crawl, unique URLs only, capture to file
echo https://<TARGET> | hakrawler -d 3 -u | tee crawl.txt

# Include subdomains discovered along the way
echo https://<TARGET> | hakrawler -subs

# Authenticated crawl (headers use ';;' as the separator)
echo https://<TARGET> | hakrawler -h "Cookie: session=<token>;;X-API-Key: <key>"

# Route through Burp to log every request hakrawler makes
echo https://<TARGET> | hakrawler -proxy http://127.0.0.1:8080 -insecure

# Show WHERE each URL came from (href/form/script) — triage what to test first
echo https://<TARGET> | hakrawler -s -w

# Pipe the whole chain: crawl -> filter live 200s -> save
echo https://<TARGET> | hakrawler -u | httpx -silent -mc 200 | tee live.txt

# Fan out over many seeds
cat roots.txt | hakrawler -subs -u -timeout 5 > all_urls.txt
```

| Flag | Description |
|---|---|
| `-d` | Crawl depth (default `2`) |
| `-u` | Show only **unique** URLs (dedupe the stream) |
| `-subs` | Include subdomains in scope |
| `-s` | Show the **source** of each URL (href, form, script) |
| `-w` | Show the page the URL was **found on** |
| `-h` | Custom headers — `"Header: value;;Header2: value2"` (auth, API keys) |
| `-proxy` | Proxy URL — point at Burp/ZAP to capture the crawl |
| `-insecure` | Skip TLS verification (self-signed / intercepting proxy) |
| `-i` | Crawl **only inside** the seed path (scope containment) |
| `-json` | JSON output (machine-readable) |
| `-t` | Threads (default `8`) |
| `-timeout` | Max seconds per URL (default `-1`, no limit) |
| `-dr` | Disable following HTTP redirects |

> [!tip] hakrawler is **stdin-in / stdout-out by design** — it has no `-u`/`--url` input flag; you feed the seed with `echo URL |`. Treat its output as a **wordlist of candidates**, not confirmed endpoints: many are path fragments. Confirm what actually resolves by feeding it back through [[Tools/Scanning/ffuf|ffuf]] (`-w crawl.txt`) or filtering with `httpx -mc 200`.

> [!warning] v2 dropped the old flags — depth is `-d` (not the old `-depth`), and there is **no `-plain`**; plain URL-per-line is the default output. If a copied one-liner errors on an unknown flag, it was written for v1.

> [!note] **See also** — [[Tools/Recon/katana|katana]] — the headless/JS-rendering crawler for SPAs (hakrawler's heavier sibling); [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — where the crawl fits in attack-surface mapping; [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — turning crawl output into confirmed endpoints.

---

*Created: 2026-09-04*
*Updated: 2026-09-04*
*Model: claude-opus-4-8*
