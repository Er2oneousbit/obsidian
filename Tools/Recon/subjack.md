# subjack

**Tags:** #subjack #SubdomainTakeover #Recon #Enumeration #DNS #AttackSurface

`subjack` checks a list of subdomains for **takeover** conditions: a CNAME pointing at an external service (GitHub Pages, Heroku, S3, Azure, Fastly, Shopify…) where the resource has been deleted but the DNS record was never cleaned up. Anyone who registers that resource name then controls content served from the target's subdomain. It fingerprints each host against a fingerprint file of known "unclaimed" response bodies.

**Source:** https://github.com/haccer/subjack
**Install:** `go install github.com/haccer/subjack@latest` — fetch `fingerprints.json` from the repo

```bash
# Check a subdomain list
subjack -w subdomains.txt -t 100 -timeout 30 -o takeovers.txt -ssl

# Use the current fingerprint set and report every non-vulnerable result too
subjack -w subdomains.txt -a -v -c fingerprints.json -ssl

# Straight from an enumeration pass
subfinder -d example.com -silent | subjack -w /dev/stdin -ssl -o results.txt
```

| Flag | Description |
|---|---|
| `-w` | Subdomain list |
| `-t` | Threads |
| `-ssl` | Force HTTPS |
| `-a` | Check all hosts, not just those with a CNAME |
| `-c` | Path to `fingerprints.json` |
| `-v` | Verbose — show non-vulnerable results too |
| `-m` | Manual mode — skip fingerprint matching, just report CNAMEs |

> [!warning] Subjack is only as current as its fingerprint file, and it goes stale — providers change their unclaimed-resource pages. Cross-check with `nuclei -t http/takeovers/`, which is maintained far more actively, and confirm any hit by hand before reporting.

> [!warning] Confirming a takeover means **registering the dangling resource**. That's a real change to third-party infrastructure using the client's name — get explicit authorization first, claim the minimum needed to prove it, document it, and release it afterwards.

> [!tip] `-m` (manual mode) is useful for triage: dump every CNAME pointing off-domain, then eyeball which providers are in play. Dangling CNAMEs to decommissioned internal hosts matter too, even when no takeover is possible.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — every subdomain enumeration pass should end with a takeover check; pairs with [[Tools/Recon/subfinder|subfinder]] and [[Tools/Scanning/nuclei|nuclei]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
