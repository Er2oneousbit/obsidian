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
# Basic authenticated dump
adidnsdump -u 'INLANEFREIGHT\htb-student' -p 'Academy_student_AD!' 172.16.5.5

# With LDAPS (port 636)
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --ssl

# Dump all zones (not just the default domain zone)
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --include-tombstoned

# Specify output file
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> -r records.csv

# Resolve unknown records (follow CNAME chains, resolve wildcards)
adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip> --resolve

# Through a pivot
proxychains adidnsdump -u 'DOMAIN\user' -p 'Password' <dc-ip>
```

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

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
