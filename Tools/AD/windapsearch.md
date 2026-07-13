# windapsearch

**Tags:** `#windapsearch` `#activedirectory` `#ldap` `#enumeration` `#linux` `#recon`

Python tool for targeted Active Directory LDAP queries from Linux. Faster and more scriptable than ldapdomaindump for specific lookups — query specific user attributes, find computers by OS, enumerate privileged group members, find unconstrained delegation targets, etc. Good complement to ldapdomaindump (bulk dump) and PowerView (Windows-side).

**Source:** https://github.com/ropnop/windapsearch
**Install:**
```bash
git clone https://github.com/ropnop/windapsearch
pip install -r requirements.txt
# Or use the Go version (windapsearch-linux-amd64) — faster, single binary
```

> [!note] **windapsearch vs ldapdomaindump** — ldapdomaindump gives you a full HTML dump of everything. windapsearch is for targeted, specific queries — "show me all Kerberoastable users" or "list members of Domain Admins". Use both.

---

## Authentication

```bash
# Basic auth
python3 windapsearch.py -d domain.local -u user -p 'Password' --dc-ip <dc-ip> <module>

# NTLM hash
python3 windapsearch.py -d domain.local -u user --hashes :<NT-hash> --dc-ip <dc-ip> <module>

# Null session (anonymous bind — rare)
python3 windapsearch.py --dc-ip <dc-ip> <module>
```

---

## Common Queries

```bash
# All domain users
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -U

# Privileged users (adminCount=1)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --admin-objects

# Domain Admins members
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -G -g "Domain Admins"

# All groups
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -G

# All computers
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -C

# Computers by OS (filter old/vulnerable)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -C \
  --attrs operatingSystem | grep -i "2008\|2003\|XP\|Windows 7"

# Domain Controllers
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --DCs
```

---

## Kerberos Attack Targets

```bash
# Kerberoastable users (SPN set on user accounts)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --kerberoastable

# ASREPRoastable users (no pre-auth required)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --asreproastable

# Unconstrained delegation (computers + users)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --unconstrained-users
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --unconstrained-computers
```

---

## Custom LDAP Filters

```bash
# Custom filter + specific attributes
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> \
  --custom "(description=*pass*)" \
  --attrs sAMAccountName,description

# Find accounts with passwords in description
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> \
  --custom "(&(objectClass=user)(description=*pass*))" \
  --attrs sAMAccountName,description

# Find users not requiring preauth
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> \
  --custom "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  --attrs sAMAccountName
```

---

## Full Enumeration One-Liner

```bash
DC="<dc-ip>"; DOM="domain.local"; U="user"; P="Password"

for module in -U -G -C --admin-objects --kerberoastable --asreproastable --unconstrained-computers --DCs; do
    echo "=== $module ==="
    python3 windapsearch.py -d $DOM -u $U -p "$P" --dc-ip $DC $module 2>/dev/null
done
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
