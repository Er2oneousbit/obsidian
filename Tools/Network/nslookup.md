# nslookup

**Tags:** `#nslookup` `#dns` `#dnsattack` `#enumeration` `#recon`

Cross-platform DNS query tool — available on both Windows and Linux. Useful for quick lookups and interactive querying. Prefer `dig` on Linux for zone transfers and scripted output; use `nslookup` when only a Windows shell is available.

**Source:** Built-in on Windows and most Linux distros
**Install:** `sudo apt install dnsutils` (Linux)

```bash
nslookup inlanefreight.htb 10.129.14.128
```

> [!note]
> On Windows targets during post-exploitation, `nslookup` is your primary DNS recon tool since `dig` isn't native. Specify a nameserver as the second argument to query a specific server.

---

## Query Syntax

```bash
# Default A record lookup
nslookup inlanefreight.htb

# Specify nameserver
nslookup inlanefreight.htb 10.129.14.128

# Specific record types
nslookup -query=A inlanefreight.htb 10.129.14.128
nslookup -query=ANY inlanefreight.htb 10.129.14.128
nslookup -query=MX inlanefreight.htb 10.129.14.128
nslookup -query=TXT inlanefreight.htb 10.129.14.128
nslookup -query=NS inlanefreight.htb 10.129.14.128
nslookup -query=SOA inlanefreight.htb 10.129.14.128

# Reverse lookup (PTR)
nslookup -query=PTR 10.129.14.128
```

---

## Interactive Mode

```bash
nslookup
> server 10.129.14.128     # set nameserver
> set type=ANY             # set record type
> inlanefreight.htb        # query
> set type=MX
> inlanefreight.htb
> exit
```

---

## Windows Post-Exploitation

```cmd
# Basic lookup
nslookup dc01.inlanefreight.local

# Query internal DC DNS
nslookup -query=A inlanefreight.local 172.16.5.5

# Find domain controllers (SRV records)
nslookup -query=SRV _kerberos._tcp.inlanefreight.local 172.16.5.5
nslookup -query=SRV _ldap._tcp.dc._msdcs.inlanefreight.local 172.16.5.5

# Find all DCs
nslookup -query=SRV _kerberos._tcp.dc._msdcs.inlanefreight.local 172.16.5.5
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
