# searchsploit

**Tags:** `#searchsploit` `#exploitdb` `#exploit` `#recon`

CLI tool for searching the Exploit-DB database offline. Finds public exploits and PoCs by keyword, CVE, or application name. Faster than browsing exploit-db.com and works without internet access.

**Source:** https://github.com/offensive-security/exploit-database
**Install:** Pre-installed on Kali — `sudo apt install exploitdb`

```bash
searchsploit apache 2.4
```

> [!note]
> Keep the database updated: `sudo searchsploit -u`. Search by version number for best results. Use `-x` to read an exploit in-terminal, or `-m` to copy it to your working directory before modifying.

---

## Searching

```bash
# Keyword search
searchsploit apache
searchsploit openssh 7.2
searchsploit "wordpress 5.0"

# Search title only (reduces noise)
searchsploit -t apache 2.4

# Search with CVE
searchsploit CVE-2021-41773

# Exclude file types
searchsploit apache --exclude=".py"
searchsploit wordpress --exclude="Metasploit"

# Case sensitive
searchsploit -s Apache

# Search for specific platform
searchsploit -p linux apache
```

---

## Working with Results

```bash
# Read exploit in terminal
searchsploit -x 42966      # by EDB-ID

# Copy exploit to current directory
searchsploit -m 42966      # copies exploit file here
searchsploit -m exploits/php/webapps/42966.php

# Get the path to exploit file
searchsploit -p 42966

# Open in browser (if GUI available)
searchsploit --www 42966
```

---

## Output Formats

```bash
# JSON output (for scripting)
searchsploit --json apache 2.4

# No color (for piping)
searchsploit --no-colour apache

# Show full path
searchsploit -p apache 2.4
```

---

## Workflow

```bash
# 1. Identify service + version from nmap
# Example: Apache httpd 2.4.49

# 2. Search
searchsploit apache 2.4.49

# 3. Review results — find relevant exploit
# EDB-ID 50383 → Apache 2.4.49 Path Traversal / RCE (CVE-2021-41773)

# 4. Copy to working dir
searchsploit -m 50383

# 5. Read and understand before running
searchsploit -x 50383

# 6. Run / adapt as needed
python3 50383.py http://10.129.14.128/
```

---

## Update Database

```bash
sudo searchsploit -u
# or
sudo apt update && sudo apt upgrade exploitdb
```

Database location: `/usr/share/exploitdb/`

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-t` | Search title only |
| `-e` | Exact match |
| `-s` | Case sensitive |
| `-x <id>` | Read exploit in terminal |
| `-m <id>` | Copy exploit to CWD |
| `-p <id>` | Show full path |
| `--json` | JSON output |
| `--exclude=` | Exclude string from results |
| `--no-colour` | Plain output |
| `-u` | Update database |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
