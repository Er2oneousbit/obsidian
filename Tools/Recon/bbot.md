# bbot

**Tags:** #bbot #OSINT #Recon #Enumeration #SubdomainDiscovery #Automation #AttackSurface

`bbot` (Bighuge BLS OSINT Tool) is a recursive OSINT scanner and the practical successor to Recon-ng. Its distinguishing behaviour is **recursion**: every asset a module discovers is fed back in as a seed for every other applicable module, so a single domain cascades into subdomains → resolved IPs → open ports → live web hosts → screenshots → discovered endpoints → secrets, in one run. Modules are grouped into presets so you don't have to wire the chain by hand.

**Source:** https://github.com/blacklanternsecurity/bbot
**Install:** `pipx install bbot`

```bash
# Passive subdomain enumeration only — safe against any target
bbot -t example.com -p subdomain-enum -rf passive

# Full subdomain enum (passive + active brute force)
bbot -t example.com -p subdomain-enum

# Subdomains → live web hosts → screenshots
bbot -t example.com -p subdomain-enum web-screenshots

# Kitchen sink against an authorised scope
bbot -t example.com -p subdomain-enum cloud-enum web-basic -om json,csv

# Scope multiple seeds, exclude what you must not touch
bbot -t example.com 10.10.10.0/24 --blacklist prod.example.com
```

| Flag | Description |
|---|---|
| `-t` | Targets (domain, IP, CIDR, URL — mix freely) |
| `-p` | Presets (`subdomain-enum`, `web-basic`, `cloud-enum`, `email-enum`) |
| `-f` / `-rf` | Module flags / required flags (`passive`, `safe`, `aggressive`) |
| `-m` | Run specific modules |
| `--blacklist` | Hard exclusions — honour the engagement scope here |
| `-om` | Output modules (`json`, `csv`, `neo4j`) |
| `-y` | Skip the confirmation prompt |

> [!warning] Recursion is the whole point and also the hazard — bbot will happily follow a discovered asset **outside your engagement scope** (a shared-hosting neighbour, a third-party SaaS host on a CNAME). Always set `--blacklist`, and prefer `-rf passive` until you've confirmed what's in scope.

> [!tip] `-rf passive` gives you a genuinely no-contact pass — nothing touches the target, only third-party data sources. That's the right default for the first run and for anything where you're not yet cleared for active testing.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — automated recursive recon; overlaps with [[Tools/Recon/amass|amass]] and [[Tools/Recon/subfinder|subfinder]] for subdomains but chains far more afterwards.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
