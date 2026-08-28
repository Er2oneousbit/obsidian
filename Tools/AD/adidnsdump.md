# adidnsdump

**Tags:** `#adidnsdump` `#activedirectory` `#dns` `#enumeration` `#recon` `#linux`

Enumerates and dumps DNS records from Active Directory-integrated DNS zones via LDAP. AD stores DNS records as objects in the domain — any authenticated domain user can read them by default. This gives you a complete internal DNS zone dump (equivalent to a DNS zone transfer) revealing all internal hosts, IPs, shadow IT, and network infrastructure.

**Source:** https://github.com/dirkjanm/adidnsdump
**Install:** `pip install adidnsdump` — or `git clone` + `pip install .`

```bash
# Basic dump
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip>

# Output: records.csv in current directory
```

> [!note] **Why this matters** — Standard DNS queries only return records the server is configured to respond to. AD-integrated DNS stores all records as LDAP objects — adidnsdump reads them directly, including internal hosts, management interfaces, dev environments, and forgotten systems that aren't in external DNS.

---

## Usage

```bash
# Basic authenticated dump (writes ./records.csv by default)
adidnsdump -u 'INLANEFREIGHT\htb-student' -p 'Academy_student_AD!' 172.16.5.5

# Auth with an NTLM hash instead of a password (format LM:NTLM)
adidnsdump -u 'DOMAIN\user' -p ':8846f7eaee8fb117ad06bdd830b7586c' <dc-ip>

# -r / --resolve — the whole point of the tool (see note below): resolve the
# "hidden" records (node visible in LDAP, record data not readable) via live DNS
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> -r

# List zones first (no dump), then target one that isn't the current domain
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --print-zones
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --zone internal.corp.local

# Other storage locations: forest-wide zones and the legacy System partition
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --forest
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --legacy

# Include tombstoned (soft-deleted) records
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --include-tombstoned

# LDAPS, custom output path, DNS-over-TCP (helps --resolve through restrictive nets)
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --ssl --outfile /tmp/dns.csv
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> -r --dns-tcp

# Through a pivot
proxychains adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip>
```

> [!warning] **Flag reality check** — `-r`/`--resolve` is a **boolean**, not an output filename; the output file is **`--outfile`** (default `records.csv`). Dumping *other* zones is `--forest` / `--legacy` / `--zone`, **not** `--include-tombstoned` (which only adds deleted records).

> [!tip] **What "hidden records" means** — any authenticated user can *list* the DNS node objects (the names) under `DomainDnsZones`, but the ACL often blocks *reading the record data itself*. Those rows show up blank/`?`. Passing **`-r`** makes adidnsdump take each unreadable name and do a normal DNS A/AAAA/CNAME lookup against the DC, recovering the IP anyway — this is the core trick, not a CNAME-follower.

---

## Output

Output is `records.csv` — columns: type, name, value, ttl.

```bash
# View all records
cat records.csv

# A records only (hosts with IPs)
grep "^A," records.csv | sort -t',' -k3 -V    # sort by IP

# Find interesting hostnames
grep -i "vpn\|mgmt\|admin\|backup\|dev\|test\|sql\|db\|mail\|ftp\|rdp" records.csv

# Extract all IPs for nmap
grep "^A," records.csv | cut -d',' -f3 | sort -u > hosts.txt
nmap -iL hosts.txt -p 22,80,443,445,3389 --open -oA internal_scan

# Find CNAME records (load balancers, CDN, cloud services)
grep "^CNAME," records.csv

# SRV records (Kerberos, LDAP, SIPS, etc.)
grep "^SRV," records.csv

# MX records (mail servers)
grep "^MX," records.csv
```

---

## Common Finds

```bash
# Management interfaces (BMC, iDRAC, iLO)
grep -i "ilo\|idrac\|bmc\|ipmi\|mgmt\|oa\." records.csv

# Network devices
grep -i "switch\|router\|fw\|firewall\|asa\|palo\|juniper\|cisco" records.csv

# CI/CD / DevOps systems
grep -i "jenkins\|gitlab\|github\|jira\|confluence\|artifactory\|nexus\|sonar" records.csv

# Forgotten/shadow IT
grep -i "old\|legacy\|test\|dev\|staging\|backup\|temp" records.csv

# Cloud-connected internal records
grep -i "azure\|aws\|gcp\|blob\|s3" records.csv
```

---

## Alternative — Manual ldapsearch

```bash
# Pull DNS records directly via ldapsearch
ldapsearch -x -H ldap://<dc-ip> \
  -D 'DOMAIN\user' -w 'Password' \
  -b 'DC=DomainDnsZones,DC=domain,DC=local' \
  '(objectClass=dnsNode)' \
  name dnsRecord 2>/dev/null | grep -E "^name:|^dnsRecord:"
```

---

> [!note] **See also** — verify/enumerate the underlying LDAP objects with [[Tools/AD/ldapsearch|ldapsearch]] ([[Services/Network management/LDAP|LDAP]] service). The **write** side of ADIDNS — *creating* a record any authenticated user can add (WPAD/spoofing) — is `dnstool.py` from the krbrelayx toolkit, not this tool. Feed recovered A-record IPs straight into a [[Tools/AD/BloodHound|BloodHound]] collection or an nmap sweep.

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
