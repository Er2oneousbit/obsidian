# ldapsearch

**Tags:** #ldapsearch #LDAP #ActiveDirectory #Enumeration #Recon #OpenLDAP

`ldapsearch` is the OpenLDAP command-line client — the lowest-common-denominator way to query any LDAP directory, including Active Directory. It has no AD-specific conveniences (unlike [[Tools/AD/windapsearch|windapsearch]] or [[Tools/AD/ldapdomaindump|ldapdomaindump]]), but it's present on every Kali box, speaks raw filters, and returns raw attributes — which makes it the right tool when you need exactly one thing, or when a wrapper is hiding what's actually on the wire.

**Source:** OpenLDAP — https://www.openldap.org/
**Install:** ships in Kali (`ldap-utils`), or `sudo apt install ldap-utils`

```bash
# Anonymous bind — check whether the directory allows unauthenticated reads
ldapsearch -x -H ldap://<DC_IP> -s base namingcontexts
ldapsearch -x -H ldap://<DC_IP> -b "dc=corp,dc=local" "(objectClass=*)"

# Authenticated bind
ldapsearch -x -H ldap://<DC_IP> -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" "(objectClass=user)"

# LDAPS / StartTLS when cleartext 389 is blocked or you don't want creds on the wire
ldapsearch -x -H ldaps://<DC_IP>:636 -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" "(objectClass=user)"
```

```bash
# Kerberoastable users (SPN set)
ldapsearch -x -H ldap://<DC_IP> -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# ASREPRoastable (no Kerberos pre-auth) — UAC bit 4194304
ldapsearch -x -H ldap://<DC_IP> -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Passwords left in the description field (classic misconfiguration)
ldapsearch -x -H ldap://<DC_IP> -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" \
  "(objectClass=user)" description | grep -iE "pass|pwd|cred"

# Lockout / password state before you spray anything
ldapsearch -x -H ldap://<DC_IP> -D "<user>@<domain>" -w '<pass>' -b "dc=corp,dc=local" \
  "(objectClass=user)" sAMAccountName badPwdCount lockoutTime pwdLastSet userAccountControl
```

| Flag | Description |
|---|---|
| `-x` | Simple authentication (not SASL) |
| `-H` | URI — `ldap://`, `ldaps://`, `ldapi://` |
| `-D` | Bind DN / UPN |
| `-w` / `-W` | Password inline / prompt |
| `-b` | Search base DN |
| `-s` | Scope — `base`, `one`, `sub` |
| `-LLL` | Strip comments and LDIF version — much cleaner output |
| `-E pr=1000/noprompt` | Paged results — required past AD's 1000-object cap |

> [!warning] AD caps a single search at **1000 objects** by default. Without `-E pr=1000/noprompt` you'll silently get a truncated list and mistake it for the full picture — a real risk when enumerating users or computers in a large domain.

> [!tip] Query the RootDSE first with `-s base namingcontexts` — it works anonymously on many directories and hands you the exact base DN to use, so you don't have to guess at `dc=` components.

> [!note] **See also** — [[Techniques/LDAP Injection|LDAP Injection]] — manual filter construction and enumeration; [[Services/Network management/LDAP|LDAP]] for the service itself. Bulk AD enumeration is faster with [[Tools/AD/windapsearch|windapsearch]], [[Tools/AD/ldapdomaindump|ldapdomaindump]], or [[Tools/AD/BloodHound|BloodHound]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
