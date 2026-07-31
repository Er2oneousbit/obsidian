# XSStrike

**Tags:** #XSStrike #XSS #WebAppAttacks #Scanner #Fuzzing #Python

`XSStrike` is a context-aware XSS detection suite. Rather than firing a static payload list at every parameter, it fuzzes the injection point, determines the reflection context (HTML body, attribute, JS string, comment), then generates a payload tailored to that context and validates it against its own handwritten parser. Includes a WAF-detection pass and payload-mutation engine for filtered targets.

**Source:** https://github.com/s0md3v/XSStrike
**Install:** `git clone https://github.com/s0md3v/XSStrike && cd XSStrike && pip3 install -r requirements.txt`

```bash
# Single URL, GET parameter
python3 xsstrike.py -u "http://target.com/search?q=query"

# POST data
python3 xsstrike.py -u "http://target.com/search" --data "q=query"

# Crawl the site and test every form/parameter found
python3 xsstrike.py -u "http://target.com" --crawl -l 3

# Authenticated testing + blind XSS payload injected into every parameter
python3 xsstrike.py -u "http://target.com/profile" --headers "Cookie: session=<token>" --blind
```

| Flag | Description |
|---|---|
| `-u` | Target URL |
| `--data` | POST body (switches to POST) |
| `--crawl` | Spider the target instead of testing one URL |
| `-l` | Crawl depth level |
| `--blind` | Inject the blind-XSS payload from `core/config.py` |
| `--fuzzer` | Fuzz the parameter to map the filter instead of exploiting |
| `--skip-dom` | Skip the DOM XSS scan (faster) |

> [!note] Set your callback URL in `core/config.py` before using `--blind` — it ships with a placeholder.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Cross-Site Scripting (XSS)|Cross-Site Scripting (XSS)]] — context-aware automated discovery; pairs with [[Tools/Web/dalfox|dalfox]] for speed and [[Tools/Web/Burpsuite|Burp Suite]] for manual verification.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
