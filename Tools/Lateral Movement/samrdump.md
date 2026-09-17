# samrdump

**Tags:** `#samrdump` `#impacket` `#rpc` `#lateral` `#enumeration` `#userenumeration`

Impacket's SAMR (Security Account Manager Remote Protocol) dumper — enumerates users, groups, and domain info via RPC. Works with null sessions on older systems, or with credentials/PTH. More targeted than enum4linux for quick user enumeration from Kali.

**Source:** Part of Impacket — pre-installed on Kali

```bash
# Null session user enum
samrdump.py 192.168.1.10

# Authenticated
samrdump.py DOMAIN/user:Password@192.168.1.10
```

---

## Usage

```bash
# Null session
samrdump.py 192.168.1.10

# Authenticated
samrdump.py DOMAIN/Administrator:Password@192.168.1.10

# Pass the Hash
samrdump.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# Kerberos
KRB5CCNAME=ticket.ccache samrdump.py -k DOMAIN/user@192.168.1.10 -no-pass

# Force the transport port — it's the -port OPTION (default 445), not a bare
# positional. `samrdump.py target 445` errors with "unrecognized arguments".
samrdump.py -port 139 DOMAIN/user:Password@192.168.1.10

# CSV output — real flag is -csv (comma-separated). Piping to tee just saves the
# normal table output, it does NOT produce CSV.
samrdump.py -csv DOMAIN/user:Password@192.168.1.10
samrdump.py -csv DOMAIN/user:Password@192.168.1.10 > users.csv
```

---

## What It Enumerates

- Domain name and SID
- All user accounts — username, RID, last login, account flags
- Password policy — min length, lockout threshold, lockout duration
- Groups and membership

---

## OPSEC Notes

- Generates SAMR RPC calls over SMB — Event ID **4624** on target
- Null session attempts logged as **4625** on modern Windows
- Generally quieter than enum4linux-ng since it only uses SAMR (no nmblookup, smbclient, etc.)

---

> [!note] **See also** — Same SAMR user/group enumeration from other angles: [[Tools/Lateral Movement/RPCclient|rpcclient]] (`enumdomusers`/`queryuser` interactively), [[Tools/Lateral Movement/NetExec|NetExec]] (`--users`/`--pass-pol`, sweeps a subnet), and the broader [[Tools/Lateral Movement/enum4linux|enum4linux]] (wraps samrdump + more). samrdump is the surgical, single-protocol option when you just want the user list and password policy.

---

*Created: 2026-03-06*
*Updated: 2026-08-31*
*Model: claude-opus-5*
