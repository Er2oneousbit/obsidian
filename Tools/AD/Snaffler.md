# Snaffler

**Tags:** `#snaffler` `#activedirectory` `#fileshare` `#enumeration` `#credentials` `#pillaging` `#postexploitation`

C# tool that finds credentials and sensitive files in accessible network shares and local file systems. Enumerates all domain computers, finds accessible shares, then searches for interesting files based on a ruleset covering hundreds of sensitive file types and patterns (config files, SSH keys, KeePass databases, passwords in plaintext, code with hardcoded creds, etc.). One of the highest-yield tools on internal AD engagements.

**Source:** https://github.com/SnaffCon/Snaffler
**Install:** Download pre-built binary from releases — `Snaffler.exe` and `Snaffler.pdb`

```powershell
# Basic run — enumerate all shares across the domain
.\Snaffler.exe -s -o snaffler.log

# Recommended: run from a domain-joined host with domain user context
.\Snaffler.exe -s -o snaffler.log -v Data
```

> [!note] **Snaffler vs manual share enumeration** — `Find-InterestingDomainShareFile` (PowerView) requires specifying extensions manually and is slow. Snaffler has a curated ruleset covering 300+ file patterns, auto-triage findings by severity, and is significantly faster. Use Snaffler for share pillaging on any AD engagement.

---

> [!warning] **Flag drift — several one-letter flags are easy to get wrong.** `-t` is the log *type* (`plain`/`JSON`), **not** threads (that's `-x`). `-l` is the max file *size* in bytes, **not** "scan local" (a local/UNC path is `-i`). `-y` is TSV output, **not** a rules dir (that's `-p`). `-f` finds shares via DFS. Corrected throughout below.

## Basic Usage

```powershell
# Standard run — domain share enum + file triage, log to file
.\Snaffler.exe -s -o snaffler.log

# -s streams colour-coded results to the console as they're found
.\Snaffler.exe -s -o snaffler.log -v Data

# Verbosity (-v): Trace | Debug | Info (default) | Data
.\Snaffler.exe -s -v Data    # include a snippet of the matching file content (most useful)
.\Snaffler.exe -s -v Info    # default — show what shares are being scanned

# Snaffle ONE directory / UNC path — disables computer AND share discovery (-i)
.\Snaffler.exe -s -i \\server\share -o snaffler.log
.\Snaffler.exe -s -i C:\ -o snaffler.log            # local filesystem

# Give an explicit host list — disables computer discovery only (-n, comma-separated)
.\Snaffler.exe -s -n SERVER01,SERVER02 -o snaffler.log

# Max threads (-x; keep it >= 4 or it breaks)
.\Snaffler.exe -s -x 12 -o snaffler.log
```

---

## Triage Output

Snaffler color-codes and severity-ranks findings automatically:

Snaffler tags each result with a colour token (`{Red}`/`{Yellow}`/`{Green}`/`{Black}`) in the log line — Red is the highest interest, Black the lowest:

| Token | Severity | Examples |
|---|---|---|
| `{Red}` | Critical | Private keys, KeePass databases, passwords in cleartext |
| `{Yellow}` | High | Config files with credentials, web.config, .env, connection strings |
| `{Green}` | Medium | Interesting scripts, backup files, credential-adjacent files |
| `{Black}` | Low | Generic interesting files (Office docs, etc.) |

```powershell
# Parse log for highest severity only
Select-String -Path snaffler.log -Pattern "\{Red\}"

# Filter from console output live
.\Snaffler.exe -s -v Data 2>&1 | Select-String "\{Red\}"
```

---

## File Types Snaffler Targets

Categories from the built-in ruleset:

- **Credentials**: `password`, `passwd`, `credentials`, `secret` in filename
- **Config files**: `web.config`, `appsettings.json`, `.env`, `database.yml`, `wp-config.php`
- **Keys**: `.pem`, `.ppk`, `.pfx`, `.p12`, `.key`, `.ovpn`
- **KeePass**: `.kdbx`, `.kdb`
- **Scripts**: `.ps1`, `.bat`, `.sh`, `.py` — scanned for credential patterns
- **Office docs**: `.docx`, `.xlsx` — scanned for keyword hits
- **Backups**: `.bak`, `.backup`, `.old`, `.orig`
- **SSH**: `id_rsa`, `authorized_keys`, `known_hosts`
- **DB**: `.sql`, `.sqlite`, `.db` dumps

---

## Advanced Options

```powershell
# Max file size to examine, in BYTES (-l; default 10000000 ≈ 10MB)
.\Snaffler.exe -s -l 5242880 -o snaffler.log        # 5MB cap

# Auto-copy every found file into a loot directory (-m)
.\Snaffler.exe -s -m C:\loot\ -o snaffler.log

# Custom .toml rules directory (-p)
.\Snaffler.exe -s -p C:\rules\ -o snaffler.log

# Reduce noise — skip the least-interesting (LAIM) rules; tune 0–3 (-b)
.\Snaffler.exe -s -b 3 -o snaffler.log

# Machine-readable output: TSV (-y) or JSON log type (-t JSON)
.\Snaffler.exe -s -y -o snaffler.tsv
.\Snaffler.exe -s -t JSON -o snaffler.json

# Restrict share discovery to DFS only (-f)
.\Snaffler.exe -s -f -o snaffler.log

# Run as a different user (netonly — creds for the target domain)
runas /netonly /user:DOMAIN\user "Snaffler.exe -s -o snaffler.log"
```

---

## Running via C2 / Without Dropping to Disk

```powershell
# Execute-Assembly in Cobalt Strike / Havoc / Sliver
execute-assembly /path/to/Snaffler.exe -s -o snaffler.log

# Or load into memory via PowerShell
$bytes = [System.IO.File]::ReadAllBytes("Snaffler.exe")
$asm = [System.Reflection.Assembly]::Load($bytes)
# Then invoke via reflection
```

---

## Reviewing Output

```bash
# From Kali — parse log file
grep -i "{Red}" snaffler.log
grep -i "{Yellow}" snaffler.log

# Extract UNC file paths from findings
grep -oP '\\\\[^ ]*' snaffler.log | sort -u

# Count findings by severity
grep -c "{Red}" snaffler.log
grep -c "{Yellow}" snaffler.log
```


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]] (CPTS v2) — finding creds and configs on reachable file shares. The slower, manual PowerShell alternative is `Find-InterestingDomainShareFile` in [[Tools/AD/PowerView|PowerView]]; find the shares to point it at with [[Tools/AD/BloodHound|BloodHound]] (`HasSession`/reachable hosts).

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
