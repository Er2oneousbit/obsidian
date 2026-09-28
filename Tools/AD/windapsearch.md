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

# Domain Admins members — dedicated shortcut
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --da

# Members of ANY group (recurses nested groups) — this is the real flag, not -g
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -m "Domain Admins"

# All groups
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -G

# All computers
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -C

# Computers by OS (filter old/vulnerable)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> -C \
  --attrs operatingSystem | grep -i "2008\|2003\|XP\|Windows 7"

# Domain Controllers — no built-in module; filter on the DC trust-account UAC bit (8192)
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> \
  --custom "(userAccountControl:1.2.840.113556.1.4.803:=8192)" --attrs dNSHostName
```

> [!warning] **Flag reality check (ropnop/windapsearch, Python).** The enumeration modules are `-U`/`--users`, `-G`/`--groups`, `-C`/`--computers`, `-PU`/`--privileged-users`, `--da` (Domain Admins), `-m "<group>"`/`--members` (any group), `--admin-objects` (adminCount=1), `--user-spns` (Kerberoastable), `--unconstrained-users`, `--unconstrained-computers`, `--gpos`, plus `--custom`/`-s`/`-l`. There is **no** `-g`, `--DCs`, `--kerberoastable`, or `--asreproastable` — use `--da`/`-m`, the UAC filter above, `--user-spns`, and a `--custom` pre-auth filter respectively. The Go rewrite (`windapsearch-linux-amd64`) uses a different `-m <module>` scheme entirely — don't mix the two flag sets.

---

## Kerberos Attack Targets

```bash
# Kerberoastable users (SPN set on user accounts) — the flag is --user-spns
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> --user-spns

# ASREPRoastable users (no pre-auth required) — no built-in module; use --custom + the UAC bit
python3 windapsearch.py -d domain.local -u user -p 'Pass' --dc-ip <dc-ip> \
  --custom "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  --attrs sAMAccountName

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

for module in -U -G -C --admin-objects --user-spns --unconstrained-users --unconstrained-computers --gpos; do
    echo "=== $module ==="
    python3 windapsearch.py -d $DOM -u $U -p "$P" --dc-ip $DC $module 2>/dev/null
done
```


> [!note] **See also** — [[Services/Network Management/LDAP|LDAP]] service note (the AD LDAP enumeration surface this wraps); [[Techniques/LDAP Injection|LDAP Injection]] (CPTS v2).
> Also used in [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2).

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
