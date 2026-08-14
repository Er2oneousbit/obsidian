# tmux

**Tags:** `#tmux` `#terminalmultiplexer` `#workflow` `#persistence` `#logging` `#sessionmanagement`

Terminal multiplexer — runs multiple shells inside one terminal as **windows** and **panes**, and (the key property for engagements) keeps them alive **server-side** so they survive a dropped SSH/VPN or a closed laptop. Primary operator uses: a persistent workspace that outlives disconnects, logging every command+output to a file for evidence, and splitting listener / shell / notes into panes on one screen. Not an attack tool itself — but see the **[[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc#Hijacking tmux / screen Sessions|session-hijacking privesc]]** for when a *target's* tmux socket is the way in.

**Source:** https://github.com/tmux/tmux/wiki
**Install:** `sudo apt install tmux` (preinstalled on Kali)

```bash
# Start a named session (name it per-target so you can find it later)
tmux new -s htb-trick
```

> [!tip] Everything in tmux is triggered by a **prefix key** then a command key. Default prefix is `Ctrl+b` (written `C-b` below). Press and release the prefix, *then* the command — e.g. `C-b "` means `Ctrl+b`, let go, then `"`.

---

## Why it matters on an engagement

| Problem | tmux solves it |
|---|---|
| SSH/VPN drops → your shell, listeners, and running scans die | The session keeps running on the box; reattach and everything is exactly as you left it |
| Long scan (`nmap -p-`, hashcat, a slow exploit) tied to your terminal | Detach and close the laptop — it runs to completion server-side |
| No record of what you typed for the report | `pipe-pane` logs the full terminal stream to a file |
| Juggling listener + shell + notes in separate terminals | Split panes — all visible at once, one window |
| Reverse shell is fragile and you don't want to lose it | Catch it inside tmux so a reconnect doesn't kill the catcher |

---

## Sessions (detach / reattach — the core workflow)

```bash
tmux new -s <name>            # create a named session
tmux ls                       # list running sessions
tmux attach -t <name>         # reattach (alias: tmux a -t <name>)
tmux attach                   # attach to the most recent session
tmux kill-session -t <name>   # kill one session
tmux kill-server              # kill ALL sessions (everything)
```

| Inside a session | Key |
|---|---|
| Detach (leave it running) | `C-b d` |
| Rename current session | `C-b $` |
| Switch between sessions | `C-b s` (interactive list) |

> [!tip] The single most useful habit: `C-b d` to detach, `tmux a` to come back. Run your VPN, listeners, and scans inside a tmux from the start of a box — a dropped connection then costs you nothing.

---

## Windows & Panes (one screen, everything visible)

```
Windows = tabs (full-screen shells).  Panes = splits within one window.
```

| Action | Key |
|---|---|
| New window | `C-b c` |
| Next / previous window | `C-b n` / `C-b p` |
| Go to window by number | `C-b 0`–`9` |
| Split pane **vertically** (side by side) | `C-b %` |
| Split pane **horizontally** (stacked) | `C-b "` |
| Move between panes | `C-b <arrow>` |
| Toggle pane zoom (fullscreen one pane) | `C-b z` |
| Cycle pane layouts | `C-b <space>` |
| Close pane / window | `C-b x` / `C-b &` |

**Typical box layout:** one pane running the reverse-shell listener (`nc -lvnp 4444`), one pane for local tooling (payload gen, `python3 -m http.server`), one pane tailing notes.

---

## Logging for Evidence

`pipe-pane` streams a pane's entire output to a file — a timestamped record of every command and its output for the report.

```bash
# Log the current pane to a file (toggle on)
#   C-b :  opens the tmux command prompt, then type:
pipe-pane -o 'cat >> /home/kali/engagement/tmux-$(date +%F).log'

# Toggle logging off — run the same command again
```

Or start every new pane logging automatically via config (see below). For a heavier, structured transcript, `script`/`asciinema` are alternatives — but `pipe-pane` is zero-setup and already there.

> [!note] **Scrollback / copy mode** — `C-b [` enters copy mode; scroll with arrows / `PgUp`. Start selection with `<space>`, copy with `<enter>`, paste with `C-b ]`. Essential for grabbing a hash or key out of scrollback without re-running a command.

---

## Reverse Shell Stability

Catching a shell **inside** tmux means a dropped VPN doesn't kill your catcher, and you can upgrade the TTY in an adjacent pane without losing the session.

```bash
# Pane 1: the listener lives inside tmux, so it survives your disconnects
nc -lvnp 4444

# After the shell lands, upgrade to a full PTY (works cleanly inside tmux):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then background with C-z and, in your LOCAL shell:
stty raw -echo; fg
# tmux itself sets $TERM correctly, so tab-completion / vim / less behave
```

Pairs with [[Tools/Remote Access/Netcat|Netcat]], [[Tools/Remote Access/socat|socat]], and the upgrade recipes in [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

---

## Minimal `~/.tmux.conf` for pentest use

```bash
# Bigger scrollback — don't lose output from a noisy scan
set -g history-limit 50000

# Mouse: click panes, scroll, resize
set -g mouse on

# Log every new pane automatically to a per-pane file
set-hook -g after-split-window 'pipe-pane -o "cat >> /tmp/tmux-#S-#I-#P.log"'

# Index from 1 (matches the number-key layout)
set -g base-index 1
setw -g pane-base-index 1

# Reload config without restarting: C-b r
bind r source-file ~/.tmux.conf \; display "reloaded"
```

Reload with `tmux source-file ~/.tmux.conf` or the `C-b r` bind above.

---

## Scripting tmux (drive it from the CLI)

Useful for kicking off a detached job, or as the *offensive* primitive when hijacking a target socket — run a command in a **new detached session** instead of joining someone's live window:

```bash
# Create a detached session that runs one command and stays alive
tmux new -d -s scan 'nmap -p- -oA /tmp/full 10.10.11.166'

# Send keystrokes into an existing session/pane programmatically
tmux send-keys -t scan 'id' Enter

# Read a pane's contents back out (scrape output without attaching)
tmux capture-pane -t scan -p

# Against a target's socket (see the privesc note) — act without sharing their TTY:
tmux -S /tmp/tmux-0/default new-session -d 'id > /tmp/o 2>&1'
```

---

## Quick Reference

| Goal | Command / Key |
|---|---|
| New named session | `tmux new -s <name>` |
| Detach (keep running) | `C-b d` |
| List sessions | `tmux ls` |
| Reattach | `tmux a -t <name>` |
| Split side-by-side / stacked | `C-b %` / `C-b "` |
| Move between panes | `C-b <arrow>` |
| Zoom a pane | `C-b z` |
| New / next window | `C-b c` / `C-b n` |
| Scrollback (copy mode) | `C-b [` |
| Log pane to file | `C-b :` → `pipe-pane -o 'cat >> out.log'` |
| Run detached command | `tmux new -d -s job '<cmd>'` |
| Scrape a pane's output | `tmux capture-pane -t <sess> -p` |
| Kill one / all | `tmux kill-session -t <name>` / `tmux kill-server` |

---

> [!note] **See also**
> Sibling GUI terminal: [[Tools/Command Shell/Terminator|Terminator]] — local tiling + broadcast-typing; run tmux *inside* its panes for persistence. The terminal-escape-injection risk documented there applies to tmux panes too.
> Privilege escalation by hijacking a **target's** tmux/screen socket: [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc#Hijacking tmux / screen Sessions|Linux Priv Esc — Hijacking tmux / screen Sessions]].
> Shell stability / upgrade recipes: [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]], [[Tools/Remote Access/Netcat|Netcat]], [[Tools/Remote Access/socat|socat]].

---

*Created: 2026-08-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
