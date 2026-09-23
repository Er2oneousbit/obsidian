#rpcclient #rpc #rpcattack #localsystemmanagement

#update

| **Query**                 | **Description**                                                    |
| ------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                 | Server information.                                                |
| `enumdomains`             | Enumerate all domains that are deployed in the network.            |
| `querydominfo`            | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`         | Enumerates all available shares.                                   |
| `netsharegetinfo <share>` | Provides information about a specific share.                       |
| `enumdomusers`            | Enumerates all domain users.                                       |
| `queryuser <RID>`         | Provides information about a specific user.                        |
- [Microsoft Word - SMB Access from Linux.docx (willhackforsushi.com)](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)
- `rpcclient -U'%' 10.10.110.17` connect with current session's user name to target
	- `enumdomusers` rpc command to list users

---

> [!note] **See also** — used against [[Services/File Xfer/SMB|SMB]] and [[Services/Network management/NetBIOS|NetBIOS]] (null-session enum over 139: `enumdomusers`, `queryuser`, RID cycling), plus [[Services/Local System Management/RPC|RPC]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
