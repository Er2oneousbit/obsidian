# dnsrecon

**Tags:** `#dnsrecon` `#dns` `#dnsattack` `#enumeration` `#recon`

Python DNS enumeration tool. Handles standard record queries, zone transfers, subdomain brute force, reverse sweeps, and cache snooping. More structured output than dnsenum — good for scripting and saving results.

**Source:** https://github.com/darkoperator/dnsrecon
**Install:** `sudo apt install dnsrecon`

```bash
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t std
```

> [!note]
> Use `-t axfr` for zone transfer focus, `-t brt` for subdomain brute force. Combine `-t std,axfr,brt` for full sweep. Output to JSON (`-j`) for easy parsing.

---

## Scan Types (`-t`)

| Type | Description |
|------|-------------|
| `std` | Standard — NS, SOA, MX, A, AAAA, SPF, TXT |
| `axfr` | Zone transfer attempts (all NS records) |
| `brt` | Subdomain brute force |
| `rvl` | Reverse lookup on IP range |
| `snoop` | DNS cache snooping |
| `tld` | TLD expansion |
| `zonewalk` | DNSSEC zone walk |

---

## Common Usage

```bash
# Standard record enum
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t std

# Zone transfer attempt
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t axfr

# Subdomain brute force
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t brt \
  -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Full sweep (std + zone transfer + brute)
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t std,axfr,brt \
  -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse lookup sweep
dnsrecon -r 10.129.14.0/24 -n 10.129.14.128

# Output to JSON
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t std,axfr -j results.json

# Output to SQLite DB
dnsrecon -d inlanefreight.htb -n 10.129.14.128 -t std --db results.db
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-d <domain>` | Target domain |
| `-n <nameserver>` | Target nameserver IP |
| `-t <types>` | Scan types (comma-separated) |
| `-D <wordlist>` | Brute force wordlist |
| `-r <range>` | Reverse lookup CIDR range |
| `-j <file>` | JSON output |
| `--db <file>` | SQLite output |
| `--threads <n>` | Thread count for brute force |
| `-c <file>` | CSV output |

---

## Zone Transfer Output (success)

```
[+] Zone Transfer was successful
[*] NS: ns1.inlanefreight.htb 10.129.14.128
[*] A: dc01.inlanefreight.htb 10.129.14.5
[*] A: web01.internal.inlanefreight.htb 172.16.5.10
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
