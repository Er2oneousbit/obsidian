# fimap

**Tags:** #fimap #LFI #RFI #FileInclusion #Scanner #WebAppAttacks #Python

`fimap` automates the find → exploit loop for PHP file inclusion: it crawls a target for candidate parameters, tests each for local and remote inclusion, then attempts exploitation (log poisoning, `/proc/self/environ`, RFI shell) and drops into a pseudo-shell on success. Think of it as sqlmap's equivalent for LFI/RFI.

**Source:** https://github.com/kurobeats/fimap
**Install:** `git clone https://github.com/kurobeats/fimap` — Python 2, so run it under `python2` or in a container

```bash
# Single URL — mark the injection point if you know it
python2 fimap.py -u "http://<TARGET>/index.php?page=test"

# Crawl a site to depth 3 and test everything it finds
python2 fimap.py -H -u "http://<TARGET>/" -d 3 -w /tmp/fimap-results

# Harvest URLs from Google, then mass-test (bug bounty / broad scope only)
python2 fimap.py -g -q "inurl:index.php?page="

# Exploit a confirmed finding — enters the interactive exploit menu
python2 fimap.py -u "http://<TARGET>/index.php?page=test" -x
```

| Flag | Description |
|---|---|
| `-u` | Single target URL |
| `-m` | Mass-scan from a URL list (`-l <file>`) |
| `-H` | Harvest/crawl mode |
| `-d` | Crawl depth |
| `-x` | Exploit an already-confirmed target |
| `-b` | Enable blind-mode testing (no error output) |
| `-w` | Results/session file |

> [!warning] Python 2 only and effectively unmaintained — it predates PHP filter chains entirely, so it will miss the single most reliable modern LFI → RCE path. Treat it as a quick first sweep, not a verdict: a clean fimap run does **not** mean the parameter is safe.

> [!tip] Its automated exploit stages are noisy (many requests, log-poisoning attempts write to the target's logs). On a scoped engagement prefer [[Tools/Scanning/ffuf|ffuf]] for discovery and manual exploitation via [[Tools/Web/php_filter_chain_generator|php_filter_chain_generator]].

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]] — automated LFI/RFI discovery and exploitation.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
