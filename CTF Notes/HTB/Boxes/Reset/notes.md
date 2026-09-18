# HTB - Reset

Target: 10.129.45.137 (box reset again after shell upgrade broke session, was 10.129.45.133)

## Recon
-

## Services
- 22/tcp   ssh    OpenSSH 8.9p1 Ubuntu
- 80/tcp   http   Apache 2.4.52 (Ubuntu) - "Admin Login" page
- 512/tcp  exec   netkit-rsh rexecd
- 513/tcp  login?
- 514/tcp  shell  Netkit rshd
(from scans/scripts.nmap, scanned against 10.129.45.126 — pre-reset IP)

## Findings
- LFI on POST /dashboard.php (param `file=`), e.g. file=/var/log/apache2/access.log
  - request: dashboard.php, cookie-authenticated (PHPSESSID)
  - log path found by querying default apache log locations
- Password reset feature leaks a temp password for admin
  - source: reset_password.php — SQLite db at private_34eee5d2/db.sqlite (table `users`, col `password_hash`)
  - new password = bin2hex(random_bytes(4)) (8 hex chars), stored as sha1() hash
- dashboard.php LFI restricted via realpath()+strpos to ALLOWED_BASE_DIR=/var/log (explains why only /var/log/* paths work)
- /etc/hosts.equiv:
  ```
  - root
  - local
  + sadm
  ```
  (explicit deny for root/local, wildcard-host trust for sadm)
  - trust check requires the LOCAL (client-side) username to match `sadm` too, not just -l on the remote side — fixed via `sudo useradd -m sadm` on kali, then `sudo su - sadm -c 'rlogin -l sadm reset.htb'`
- sadm has a persistent tmux session (`sadm_session`, socket /tmp/tmux-1001/default) with sadm's password visible in scrollback via `tmux capture-pane -t sadm_session -p -S -32768`

## sudo -l (as sadm)
```
(ALL) PASSWD: /usr/bin/nano /etc/firewall.sh
(ALL) PASSWD: /usr/bin/tail /var/log/syslog
(ALL) PASSWD: /usr/bin/tail /var/log/auth.log
```

## Creds
- admin:admin — logs into dashboard
- admin temp password via password reset leak — TBD (value not yet recorded)

## Foothold
- LFI log poisoning (User-Agent -> access.log, 2 separate requests: poison, then trigger via file=access.log)
- Full TTY: `python3 -c 'import pty; pty.spawn("/bin/bash")'` on remote, then Ctrl+Z, then locally `stty raw -echo; fg`, answer `reset` terminal-type prompt with `xterm`, `export TERM=xterm`

## Privesc
- sudo -l requires a password for current shell user (not usable directly, fixed once sadm password recovered)
- root via GTFOBins: `sudo nano /etc/firewall.sh` (nano shell escape)

## Flags
- user: popped (LFI log poisoning shell)
- root: popped (sudo nano GTFOBins)

## Users (/etc/passwd)
- sadm:x:1001:1001:,,,:/home/sadm:/bin/bash
- _laurel:x:998:998::/var/log/laurel:/bin/false
