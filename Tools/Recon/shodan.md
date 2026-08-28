# shodan

**Tags:** #shodan #OSINT #Recon #PassiveRecon #Enumeration #AttackSurface

`shodan` indexes internet-exposed services by banner, certificate, and response content. It's the highest-value **passive** recon source: you can map a target's exposed infrastructure — open ports, software versions, expired certs, forgotten dev boxes — without ever sending a packet to them, because Shodan already scanned it. The CLI wraps the same search API the web UI uses.

**Source:** https://github.com/achillean/shodan-python
**Install:** `pipx install shodan` — then `shodan init <API_KEY>` (free key from shodan.io; filters like `net:` and `vuln:` need a paid tier)

```bash
# Set up
shodan init <API_KEY>
shodan info                     # check remaining query credits

# Core lookups
shodan host 10.10.10.10                        # everything known about one IP
shodan search "hostname:example.com"
shodan search 'org:"Example Corp"'
shodan search 'ssl.cert.subject.cn:example.com'

# Useful output shaping
shodan search --fields ip_str,port,org,hostnames 'org:"Example Corp"'
shodan download results 'org:"Example Corp"' && shodan parse --fields ip_str,port results.json.gz

# Favicon pivot — find every host running the same app
shodan search "http.favicon.hash:<murmur3_hash>"
```

| Filter | Matches |
|---|---|
| `hostname:` | Hostname substring |
| `org:` / `asn:` | Owning organisation / AS number |
| `net:` | CIDR range (paid) |
| `port:` / `product:` / `version:` | Service specifics |
| `ssl.cert.subject.cn:` | Certificate common name |
| `ssl.cert.expired:true` | Expired certificates — often forgotten hosts |
| `http.title:` / `http.html:` | Response content |
| `vuln:CVE-2021-44228` | Known-vulnerable hosts (paid) |

> [!tip] `ssl.cert.subject.cn:` and the favicon hash are the two best pivots. A cert CN or a custom favicon ties together infrastructure across different IPs, hostnames, and even cloud providers — turning one known host into the org's whole footprint.

> [!warning] Shodan data is a **snapshot from its last scan**, which can be weeks old. Everything it reports needs confirming against the live target before you act on it, and an absent service doesn't mean a closed port.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — passive attack-surface mapping. Censys (search.censys.io) covers the same ground with better certificate search.
> Also used in [[Techniques/Network Device Pentesting|Network Device Pentesting]] (CPTS v2).

---

*Created: 2026-07-30*
*Updated: 2026-07-31*
*Model: claude-opus-5*
