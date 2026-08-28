# ldapdomaindump

**Tags:** `#ldapdomaindump` `#activedirectory` `#ldap` `#enumeration` `#recon` `#linux`

Python tool that dumps Active Directory information via LDAP and outputs it as organized HTML, JSON, and CSV files. Standard first-run on internal engagements from a Linux box — gives you users, groups, computers, policy, and trust data without touching PowerView or needing a Windows foothold.

**Source:** https://github.com/dirkjanm/ldapdomaindump
**Install:** `pip install ldapdomaindump` — pre-installed on Kali

```bash
# Basic run — authenticated with domain creds
ldapdomaindump -u 'DOMAIN\user' -p 'Password123' <dc-ip>

# With LDAPS (port 636)
ldapdomaindump -u 'DOMAIN\user' -p 'Password123' <dc-ip> --no-html --no-grep -o /tmp/out
```

> [!note] **Workflow** — Run ldapdomaindump right after getting first domain credentials. Open the HTML files in a browser for a quick overview, then use the JSON/CSV for scripted analysis. Feeds directly into BloodHound-style manual review before spinning up more targeted PowerView queries.

---

## Common Usage

```bash
# Standard run — outputs to current directory
ldapdomaindump -u 'INLANEFREIGHT\htb-student' -p 'Academy_student_AD!' 172.16.5.5

# Specify output directory
ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip> -o /tmp/ldd-output/

# Use NTLM hash instead of password (pass-the-hash)
ldapdomaindump -u 'DOMAIN\user' --hashes :<NT-hash> <dc-ip>

# Anonymous LDAP (if allowed — rare but worth trying)
ldapdomaindump <dc-ip>

# LDAPS
ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip> --no-json --no-grep

# Output formats — disable what you don't need
ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip> --no-html    # skip HTML
ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip> --no-json    # skip JSON
ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip> --no-grep    # skip grepable .grep files
```

---

## Output Files

| File | Contents |
|---|---|
| `domain_users.html` | All users — enabled/disabled, last logon, password policy, groups |
| `domain_groups.html` | All groups and membership |
| `domain_computers.html` | All computer accounts — OS, last logon, DCs |
| `domain_policy.html` | Default domain policy — password policy, lockout |
| `domain_trusts.html` | Domain trusts |
| `domain_users_by_group.html` | Users organized by group membership |
| `domain_computers_by_os.html` | Computers organized by OS |

JSON equivalents exist for all the above (`.json` extension), plus grepable `.grep` files.

---

## Quick Wins from Output

```bash
# Users with passwords never expiring
grep -i "DONT_EXPIRE_PASSWD" domain_users.grep

# Disabled accounts
grep -i "disabled" domain_users.grep

# Users who haven't logged in recently
cat domain_users.json | python3 -c "
import json, sys
from datetime import datetime, timezone
users = json.load(sys.stdin)
cutoff = 90 * 86400  # 90 days in seconds
for u in users:
    ll = u.get('attributes', {}).get('lastLogon', [None])[0]
    name = u.get('attributes', {}).get('sAMAccountName', ['?'])[0]
    if ll and ll != '1601-01-01 00:00:00+00:00':
        print(f'{name}: {ll}')
"

# Admin users (adminCount=1)
grep '"adminCount": \[1\]' domain_users.json

# Computers running old OS
grep -i "Windows Server 200\|Windows XP\|Windows 7\b" domain_computers.grep

# Password policy — lockout threshold
grep -i "lockout" domain_policy.grep
```

---

## With Proxychains (through pivot)

```bash
proxychains ldapdomaindump -u 'DOMAIN\user' -p 'Password' <dc-ip>
```


> [!note] **See also** — [[Techniques/LDAP Injection|LDAP Injection]] (CPTS v2).
> Also used in [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2).

---

*Created: 2026-03-06*
*Updated: 2026-07-31*
*Model: claude-opus-5*
