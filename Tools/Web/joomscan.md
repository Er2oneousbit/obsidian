# joomscan

**Tags:** #joomscan #Joomla #WebAppAttacks #Enumeration #CMS

OWASP JoomScan is a Perl scanner dedicated to Joomla — it fingerprints the core version, enumerates installed components/extensions, flags known vulnerable versions, and finds common misconfigurations (directory listing, config/backup leaks, firewall detection). Reach for it during web-app recon once `whatweb`/`droopscan` identifies a Joomla target; it's more Joomla-aware than the generic `droopscan joomla` module and is the tool the CPTS material prefers over the older `joomlascan.py`.

**Source:** https://github.com/OWASP/joomscan
**Install:** ships in Kali (`sudo apt install joomscan`), or `git clone https://github.com/OWASP/joomscan && cd joomscan && perl joomscan.pl`

```bash
# Basic scan — version, components, known vulns
joomscan -u http://target.com

# Enumerate components/extensions specifically
joomscan -u http://target.com --enumerate-components

# Through a proxy / with a custom user-agent
joomscan -u http://target.com --proxy http://127.0.0.1:8080 --random-agent
```

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Applications|Attacking Common Applications]] — Joomla enumeration (preferred over the older `joomlascan.py`); pairs with [[Tools/Web/droopscan|droopscan]] for cross-CMS scanning.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-4-8*
