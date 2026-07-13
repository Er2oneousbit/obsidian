# WHOIS

**Tags:** `#whois` `#recon` `#osint` `#dnsattack` `#passivedns`

Query WHOIS databases to retrieve domain registration records — registrant name, org, email, address, nameservers, registration/expiry dates, registrar. Useful for passive recon, identifying admin contacts, finding related domains, and hunting for email addresses for phishing/social engineering.

**Source:** Built-in Linux / Sysinternals for Windows
**Install:** `sudo apt install whois`

```bash
whois inlanefreight.com
```

> [!note]
> Many modern registrations use privacy protection (GDPR/WHOIS redaction) that hides personal data. Try historical WHOIS lookups (whoisology.com, domaintools.com) to find data from before privacy services were applied.

---

## Basic Usage

```bash
# Domain lookup
whois inlanefreight.com

# IP/ASN lookup (useful for identifying netblocks)
whois 10.129.14.128

# Specify WHOIS server
whois -h whois.arin.net 10.129.14.128

# Strip WHOIS server notice lines
whois inlanefreight.com | grep -v "^%" | grep -v "^$"
```

---

## What to Extract

```bash
# Registrant / org info
whois inlanefreight.com | grep -i "registrant\|org\|email\|phone\|address"

# Nameservers
whois inlanefreight.com | grep -i "name server\|nserver"

# Dates
whois inlanefreight.com | grep -i "created\|updated\|expir"

# Registrar
whois inlanefreight.com | grep -i "registrar"
```

---

## IP / ASN Lookup

```bash
# Find netblock owner and ASN
whois 8.8.8.8

# ARIN (North America)
whois -h whois.arin.net 8.8.8.8

# RIPE (Europe)
whois -h whois.ripe.net 8.8.8.8

# Find all IPs in an org's ASN
whois -h whois.radb.net -- '-i origin AS15169'
```

---

## Online Alternatives

| Site | Use |
|------|-----|
| https://whois.domaintools.com | Historical WHOIS records |
| https://viewdns.info | IP history, reverse WHOIS |
| https://whoisology.com | Email-based reverse WHOIS |
| https://bgp.he.net | ASN/IP range lookups |
| https://search.arin.net | ARIN WHOIS search |

---

## Windows (Sysinternals)

```cmd
whois.exe inlanefreight.com
whois.exe 10.129.14.128
```

Download: https://docs.microsoft.com/en-gb/sysinternals/downloads/whois

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
