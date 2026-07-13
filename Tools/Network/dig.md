# dig

**Tags:** `#dig` `#dns` `#dnsattack` `#enumeration` `#recon`

Command-line DNS lookup tool. More verbose and scriptable than nslookup — preferred for zone transfers, specific record type queries, and parsing output in scripts.

**Source:** Built into most Linux distros (`bind9-dnsutils`)
**Install:** `sudo apt install dnsutils`

```bash
dig inlanefreight.htb @10.129.14.128
```

> [!note]
> Use `+short` for clean IP output in scripts. Zone transfers (`axfr`) are the primary attack — attempt against every discovered nameserver.

---

## Record Type Queries

```bash
# A records (default)
dig A inlanefreight.htb @10.129.14.128

# All records
dig ANY inlanefreight.htb @10.129.14.128

# MX (mail servers)
dig MX inlanefreight.htb @10.129.14.128

# TXT (SPF, DKIM, verification tokens)
dig TXT inlanefreight.htb @10.129.14.128

# NS (nameservers)
dig NS inlanefreight.htb @10.129.14.128

# SOA (start of authority — zone admin info)
dig SOA inlanefreight.htb @10.129.14.128

# Reverse lookup (PTR)
dig -x 10.129.14.128 @10.129.14.128

# Version/chaos query (may reveal BIND version)
dig CH TXT version.bind 10.129.14.128
```

---

## Zone Transfer

```bash
# AXFR from specific nameserver
dig axfr inlanefreight.htb @10.129.14.128

# AXFR subdomain zone
dig axfr internal.inlanefreight.htb @10.129.14.128
```

> [!warning]
> Zone transfers dump the entire DNS zone — all hostnames, IPs, internal naming. Always attempt against every NS record found.

---

## Output Flags

| Flag | Effect |
|------|--------|
| `+short` | IPs/values only — clean for scripts |
| `+noall +answer` | Answer section only, no headers |
| `+nocmd` | Skip the command header line |
| `+multiline` | One record per line |

```bash
# Clean answer output
dig +noall +answer +multiline ANY inlanefreight.htb @10.129.14.128
```

---

## Subdomain Enumeration

```bash
# Manual wordlist loop
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do
  result=$(dig +short $sub.inlanefreight.htb @10.129.14.128)
  [ -n "$result" ] && echo "$sub -> $result"
done
```

Use `dnsenum` or `dnsrecon` for automated brute force.

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
