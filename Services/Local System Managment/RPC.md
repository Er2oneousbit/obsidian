#RPC #RemoteProcedureCall #localsystemmanagement

## What is RPC?
Remote Procedure Call — protocol that allows programs to execute code on a remote system. Core to Windows management protocols (SMB, DCOM, WMI, MSRPC). The portmapper/endpoint mapper assigns dynamic ports to RPC services.

- Port **TCP 135** — RPC endpoint mapper (MSRPC)
- Port **TCP 593** — RPC over HTTP
- Dynamic ports: 1024–65535 (negotiated via 135)
- Linux rpcbind: **TCP/UDP 111** (NFS and other RPC services)

---

## Key RPC Interfaces

| Interface | GUID | Description |
|---|---|---|
| IObjectExporter | `99fcfec4-...` | DCOM object exporter |
| IRemoteSCMActivator | `000001a0-...` | Service control |
| IRemoteActivation | `4d9f4ab8-...` | Remote activation |
| MS-SAMR | `12345778-1234-abcd-ef00-01234567cffb` | Security Account Manager |
| MS-LSAD | `12345778-1234-abcd-ef00-0123456789ab` | Local Security Authority |
| MS-DRSR | `e3514235-...` | Directory Replication |
| MS-SCMR | `367abb81-...` | Service Control Manager |

---

## Enumeration

```bash
# Nmap RPC enum
nmap -p 135 --script msrpc-enum -sV <target>
nmap -sU -p 111 --script rpcinfo <target>  # Linux rpcbind

# rpcdump — list all registered RPC endpoints
impacket-rpcdump <target>
impacket-rpcdump <domain>/<user>:<pass>@<target>

# rpcinfo (Linux/NFS)
rpcinfo -p <target>

# Metasploit
use auxiliary/scanner/dcerpc/endpoint_mapper
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
```

---

## rpcclient

```bash
# Connect — null session (anonymous)
rpcclient -U "" -N <target>
rpcclient -U "" 10.129.14.128

# Connect — authenticated
rpcclient -U user%Password123 <target>
rpcclient -U domain/user%Password123 <target>
```

### rpcclient Commands

```
# Server info
srvinfo

# Domain info
querydominfo

# Enumerate domain users
enumdomusers
queryuser 0x1f4  # query specific user by RID (hex)

# Enumerate groups
enumdomgroups
querygroup 0x200

# Enumerate shares
netshareenumall
netsharegetinfo <sharename>

# Enumerate printers
enumprinters

# Password policy
getdompwinfo
getusrdompwinfo 0x1f4

# Lookup names/SIDs
lookupnames <username>
lookupsids <SID>

# Add user (if privs)
createdomuser <username>
setuserinfo2 <username> 24 <password>

# Change password
setuserinfo2 <username> 23 <newpassword>
```

---

## User RID Brute Force

```bash
# Enumerate users by RID via loop
for i in $(seq 500 1100); do
  rpcclient -N -U "" <target> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done
```

---

## impacket Tools

```bash
# Dump RPC endpoints
impacket-rpcdump <target>
impacket-rpcdump <domain>/<user>:<pass>@<target>

# lookupsid — enumerate SIDs/users
impacket-lookupsid <target>
impacket-lookupsid <domain>/<user>:<pass>@<target>
impacket-lookupsid <domain>/<user>:<pass>@<target> | grep SidTypeUser

# samrdump — enumerate SAM via RPC
impacket-samrdump <target>
impacket-samrdump <domain>/<user>:<pass>@<target>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Null session allowed | Unauthenticated user/group/share enumeration |
| RPC exposed to internet | Attack surface for DCOM/WMI exploits |
| Guest account enabled | Access to RPC info without creds |
| Unpatched RPC services | RCE via historical vulns (MS03-026, etc.) |

---

## Quick Reference

| Goal | Command |
|---|---|
| Null session connect | `rpcclient -U "" -N host` |
| Enum users | `rpcclient $> enumdomusers` |
| Query user | `rpcclient $> queryuser 0x1f4` |
| Enum shares | `rpcclient $> netshareenumall` |
| Dump RPC endpoints | `impacket-rpcdump host` |
| SID/user enum | `impacket-lookupsid host` |
| RID brute force | `for i in $(seq 500 1100); do rpcclient -N -U "" host -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name"; done` |
| Nmap | `nmap -p 135 --script msrpc-enum host` |
