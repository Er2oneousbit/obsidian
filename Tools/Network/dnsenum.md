# dnsenum

**Tags:** `#dnsenum` `#dns` `#dnsattack` `#enumeration` `#recon`

DNS enumeration tool that automates zone transfers, host and subdomain brute force, reverse lookups, and Google scraping. Good all-in-one for initial DNS recon.

**Source:** https://github.com/fwaeytens/dnsenum
**Install:** `sudo apt install dnsenum`

```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

> [!note]
> `dnsrecon` is generally preferred for more structured output and better zone transfer handling. dnsenum is still useful for quick all-in-one enumeration with Google scraping.

---

## Common Flags

| Flag | Description |
|------|-------------|
| `--dnsserver <IP>` | Specify target nameserver |
| `--enum` | Enable all enumeration (NS, MX, zone transfer, brute) |
| `-f <wordlist>` | Subdomain brute force wordlist |
| `-p <n>` | Google pages to scrape (0 = disable) |
| `-s <n>` | Google subdomains to scrape (0 = disable) |
| `-o <file>` | Output to XML file |
| `--threads <n>` | Brute force thread count (default 5) |
| `-r` | Reverse lookup on found ranges |

---

## Usage Examples

```bash
# Full enum against internal nameserver, no Google scraping
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  inlanefreight.htb

# Quick zone transfer check only
dnsenum --dnsserver 10.129.14.128 inlanefreight.htb

# With output file + more threads
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 --threads 20 \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o results.xml inlanefreight.htb

# Reverse lookup on subnet
dnsenum --dnsserver 10.129.14.128 -r 10.129.14.0/24 inlanefreight.htb
```

---

## What It Checks

1. NS records
2. MX records
3. Zone transfer (AXFR) — all nameservers
4. Subdomain brute force (wordlist)
5. Google scraping for subdomains (`-p`/`-s`)
6. Reverse lookups on found IP ranges

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
