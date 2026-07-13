# Snaffler

**Tags:** `#snaffler` `#activedirectory` `#fileshare` `#enumeration` `#credentials` `#pillaging` `#postexploitation`

C# tool that finds credentials and sensitive files in accessible network shares and local file systems. Enumerates all domain computers, finds accessible shares, then searches for interesting files based on a ruleset covering hundreds of sensitive file types and patterns (config files, SSH keys, KeePass databases, passwords in plaintext, code with hardcoded creds, etc.). One of the highest-yield tools on internal AD engagements.

**Source:** https://github.com/SnaffCon/Snaffler
**Install:** Download pre-built binary from releases — `Snaffler.exe` and `Snaffler.pdb`

```powershell
# Basic run — enumerate all shares across the domain
.\Snaffler.exe -s -o snaffler.log

# Recommended: run from a domain-joined host with domain user context
.\Snaffler.exe -s -o snaffler.log -v data
```

> [!note] **Snaffler vs manual share enumeration** — `Find-InterestingDomainShareFile` (PowerView) requires specifying extensions manually and is slow. Snaffler has a curated ruleset covering 300+ file patterns, auto-triage findings by severity, and is significantly faster. Use Snaffler for share pillaging on any AD engagement.

---

## Basic Usage

```powershell
# Standard run — domain share enum + file triage
.\Snaffler.exe -s -o snaffler.log

# Output to log file and console simultaneously
.\Snaffler.exe -s -o snaffler.log -v data

# Verbosity levels: Trace, Debug, Info, Data (default), Warning, Error
.\Snaffler.exe -s -v data    # show file content previews (most useful)
.\Snaffler.exe -s -v info    # show what shares are being scanned

# Target a specific share instead of full domain sweep
.\Snaffler.exe -s -i \\server\share -o snaffler.log

# Target a specific computer
.\Snaffler.exe -s -n SERVER01 -o snaffler.log

# Set thread count (default: 30)
.\Snaffler.exe -s -t 10 -o snaffler.log

# Skip domain computer enumeration — provide target list directly
.\Snaffler.exe -s -i \\server1\share,\\server2\share -o snaffler.log
```

---

## Triage Output

Snaffler color-codes and severity-ranks findings automatically:

| Color | Severity | Examples |
|---|---|---|
| Red | Critical | Private keys, KeePass databases, passwords in cleartext |
| Yellow | High | Config files with credentials, web.config, .env, connection strings |
| Green | Medium | Interesting scripts, backup files, credential-adjacent files |
| White | Low | Generic interesting files (Office docs, etc.) |

```powershell
# Parse log for highest severity only
Select-String -Path snaffler.log -Pattern "\[Red\]|\[Critical\]"

# Filter from command line output
.\Snaffler.exe -s -v data 2>&1 | Select-String "\[Red\]"
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
# Scan local file system instead of shares
.\Snaffler.exe -s -l C:\

# Max file size to examine (default: 10MB)
.\Snaffler.exe -s -x 5242880    # 5MB

# Disable file content scanning (just flag by name/extension)
.\Snaffler.exe -s -f

# Custom rules directory
.\Snaffler.exe -s -y C:\rules\

# Run as different user
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
grep -i "\[Red\]" snaffler.log
grep -i "\[Yellow\]" snaffler.log

# Extract file paths from findings
grep -oP "\\\\[^]]*" snaffler.log | sort -u

# Count findings by severity
grep -c "\[Red\]" snaffler.log
grep -c "\[Yellow\]" snaffler.log
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
