# BloodHound

**Tags:** `#bloodhound` `#activedirectory` `#attackpath` `#graphanalysis` `#sharphound` `#enumeration` `#postexploitation`

Graph-based Active Directory attack path visualizer. Ingests data collected by SharpHound (or AzureHound for Azure AD) and maps relationships between users, groups, computers, GPOs, and ACLs into attack paths. Instantly answers "how do I get from this low-priv user to Domain Admin?" — essential on every internal engagement.

**Source:** https://github.com/SpecterOps/BloodHound
**Legacy CE:** https://github.com/BloodHoundAD/BloodHound (BloodHound Community Edition — still widely used)
**SharpHound:** https://github.com/BloodHoundAD/SharpHound

> [!note] There are two versions in active use: **BloodHound CE** (new, web UI, Docker-based, SpecterOps) and **BloodHound Legacy** (older Electron app + Neo4j). Most teams still use Legacy. This note covers both where they differ.

---

## Setup — BloodHound Legacy (Most Common)

```bash
# Install Neo4j (graph database backend)
apt install neo4j -y
neo4j start

# Default Neo4j credentials: neo4j:neo4j
# First login at http://localhost:7474 — change password

# Download BloodHound binary
wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64
./BloodHound --no-sandbox

# Connect to Neo4j when prompted:
# DB URL: bolt://localhost:7687
# Username: neo4j
# Password: <your new password>
```

## Setup — BloodHound CE (New)

```bash
# Requires Docker
git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound
docker compose up -d

# Access at http://localhost:8080
# Default creds printed in docker logs on first run
docker compose logs | grep -i "initial password"
```

---

## Data Collection — SharpHound

SharpHound collects AD data from a domain-joined Windows host or from a Linux attack box with credentials.

### From Windows (Domain-Joined or with Creds)

```powershell
# Download SharpHound
# https://github.com/BloodHoundAD/SharpHound/releases

# Full collection — recommended starting point
.\SharpHound.exe -c All

# All collection + GPO local group data
.\SharpHound.exe -c All,GPOLocalGroup

# Stealth collection (slower, less noisy)
.\SharpHound.exe -c All --stealth

# Target a specific domain
.\SharpHound.exe -c All -d CORP.LOCAL

# Specify DC
.\SharpHound.exe -c All --domaincontroller 10.10.10.10

# Output to specific directory
.\SharpHound.exe -c All --outputdirectory C:\Temp\

# Run as different user (pass-the-hash compatible via runas)
.\SharpHound.exe -c All --ldapusername jsmith --ldappassword 'Password123!'
```

### From Linux (BloodHound.py — No Domain Join Required)

```bash
# Install
pip3 install bloodhound
# or
git clone https://github.com/fox-it/BloodHound.py && pip3 install .

# Full collection with credentials
bloodhound-python -u jsmith -p 'Password123!' -d CORP.LOCAL -dc dc01.corp.local -c All

# With NTLM hash (pass-the-hash)
bloodhound-python -u jsmith --hashes ':aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' -d CORP.LOCAL -dc dc01.corp.local -c All

# Specify nameserver (if DNS not configured)
bloodhound-python -u jsmith -p 'Password123!' -d CORP.LOCAL -ns 10.10.10.10 -c All

# Output to specific directory
bloodhound-python -u jsmith -p 'Password123!' -d CORP.LOCAL -dc dc01.corp.local -c All --zip -o /tmp/bh/
```

> [!note] BloodHound.py output is slightly less complete than SharpHound — local admin rights and some session data may be missing. Use SharpHound from a Windows host when possible.

---

## Importing Data

```bash
# SharpHound produces a ZIP file — import directly into BloodHound
# Legacy UI: Drag and drop the ZIP onto the BloodHound window
# Or use the Upload button in the top right

# BloodHound CE: Settings → Upload Data → select ZIP
```

---

## Key Queries (Legacy — Pre-Built)

Access via the **Analysis** tab in BloodHound Legacy.

```
# Highest value targets
Find all Domain Admins
Find Shortest Paths to Domain Admins
Find Principals with DCSync Rights
Find Computers where Domain Users are Local Admin

# Starting point for a compromised user
Shortest Paths from Owned Principals
Find Shortest Path to Domain Admins from Owned Principals

# Kerberos attacks
Find AS-REP Roastable Users (DontReqPreAuth)
Find Kerberoastable Users with most privileges
Find Kerberoastable Members of High Value Groups

# ACL abuse
Find Principals with DCSync Rights
Shortest Paths to Unconstrained Delegation Systems
Find Computers with Unconstrained Delegation
Find Computers with Constrained Delegation
```

---

## Custom Cypher Queries

Run directly in the BloodHound search bar (Legacy) or Cypher tab (CE).

```cypher
// Find all users with paths to Domain Admins
MATCH p=shortestPath((u:User {enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// Find all owned users with paths to DA
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// Find all computers where a user is local admin
MATCH (u:User {name:"JSMITH@CORP.LOCAL"})-[:AdminTo]->(c:Computer)
RETURN c.name

// Find accounts with DCSync rights (GenericAll / WriteDacl / AllExtendedRights on domain)
MATCH (u)-[:DCSync|GenericAll|AllExtendedRights|WriteDacl]->(d:Domain)
RETURN u.name, d.name

// Find AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true, enabled:true})
RETURN u.name

// Find Kerberoastable users with path to DA
MATCH p=shortestPath((u:User {hasspn:true, enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// Find users with GenericWrite over other users (targeted Kerberoasting)
MATCH (u1:User)-[:GenericWrite]->(u2:User)
RETURN u1.name, u2.name

// Find all groups a user is member of (recursive)
MATCH (u:User {name:"JSMITH@CORP.LOCAL"})-[:MemberOf*1..]->(g:Group)
RETURN g.name

// Find computers with unconstrained delegation (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name

// Find users with WriteDacl on high value targets
MATCH (u:User)-[:WriteDacl]->(t)
WHERE t.highvalue=true
RETURN u.name, t.name

// Find machines where owned users have local admin
MATCH (u:User {owned:true})-[:AdminTo]->(c:Computer)
RETURN u.name, c.name
```

---

## Marking Nodes as Owned / High Value

Mark compromised accounts/machines as owned to enable "Shortest Paths from Owned Principals" queries.

```
Legacy: Right-click a node → Mark as Owned / Mark as High Value
CE: Click node → Actions → Mark as Owned
```

```cypher
// Mark a user as owned via Cypher
MATCH (u:User {name:"JSMITH@CORP.LOCAL"}) SET u.owned=true

// Mark multiple users as owned (bulk)
MATCH (u:User) WHERE u.name IN ["JSMITH@CORP.LOCAL","BSMITH@CORP.LOCAL"] SET u.owned=true

// Mark a computer as owned
MATCH (c:Computer {name:"WS01.CORP.LOCAL"}) SET c.owned=true
```

---

## Common Attack Paths to Look For

| Edge / Relationship | Abuse |
|---|---|
| `AdminTo` | Lateral movement — local admin access |
| `MemberOf` | Group membership — check what the group can do |
| `GenericAll` | Full control — reset password, add to group, modify object |
| `GenericWrite` | Write attributes — set SPN (targeted Kerberoast), set script path |
| `WriteOwner` | Take ownership → grant GenericAll |
| `WriteDacl` | Modify ACL → grant yourself GenericAll |
| `ForceChangePassword` | Reset user password without knowing current |
| `AllExtendedRights` | Includes ability to DCSync, reset passwords |
| `DCSync` | Dump all hashes from DC |
| `HasSession` | User has active session on machine — target for credential theft |
| `CanRDP` | RDP access to machine |
| `ExecuteDCOM` | DCOM lateral movement |
| `AllowedToDelegate` | Constrained delegation — ticket abuse |
| `AllowedToAct` | Resource-based constrained delegation (RBCD) |
| `AddMember` | Add users to group |
| `Owns` | Full control equivalent |
| `ReadLAPSPassword` | Read local admin password via LAPS |
| `ReadGMSAPassword` | Read GMSA managed password |

---

## Tips

> [!tip] **First thing to do after import** — Run "Find Shortest Paths to Domain Admins" and "Find AS-REP Roastable Users" immediately. These two queries often reveal a path or low-hanging fruit within seconds.

> [!tip] **Session data** — SharpHound session collection (`-c Session`) captures where users are currently logged in. Prioritise machines where DA sessions are active — lateral movement there gives immediate credential access.

> [!warning] **Detection** — SharpHound generates significant LDAP traffic. Run with `--stealth` in sensitive environments. BloodHound.py is slightly noisier. Consider running collection during business hours when LDAP traffic blends in.

```bash
# If LDAP collection is blocked, try RPC collection method
.\SharpHound.exe -c All --CollectionMethods DcOnly    # DC-only, less noisy
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
