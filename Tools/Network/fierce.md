# fierce

**Tags:** #fierce #DNS #Recon #Enumeration #SubdomainDiscovery

`fierce` is a DNS reconnaissance tool that locates non-contiguous IP space and hostnames for a domain — it attempts zone transfers first, then falls back to wordlist-based subdomain brute forcing and scans nearby IPs for related hosts. A quick first pass for DNS enumeration before reaching for `subfinder` (passive) or `dnsenum`.

**Source:** https://github.com/mschwager/fierce
**Install:** ships in Kali (`fierce`), or `pipx install fierce`

```bash
# Full recon on a domain (zone transfer + subdomain brute)
fierce --domain target.com

# Use a custom subdomain wordlist and specific DNS server
fierce --domain target.com --subdomain-file subdomains.txt --dns-servers 10.10.10.10
```

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] — DNS subdomain discovery; pairs with [[Tools/Recon/subfinder|subfinder]] and [[Tools/Network/dig|dig]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-4-8*
