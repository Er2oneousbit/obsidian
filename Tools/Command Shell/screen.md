# screen

**Tags:** `#screen` `#terminalmultiplexer` `#persistence` `#sessionhijacking` `#privesc` `#gtfobins`

GNU screen — the older terminal multiplexer, tmux's sibling. Same operator value as
[[Tools/Command Shell/tmux|tmux]] (server-side persistence so shells/listeners survive a
dropped SSH/VPN), and the same offensive angle: a **target's screen socket** can be a privesc
path via **session hijacking**, and **SUID screen** has a well-known local-root
(**CVE-2017-5618**). You'll meet it on boxes that have screen but not tmux.

**Source:** https://www.gnu.org/software/screen/
**Install:** `sudo apt install screen` (often preinstalled).

> [!tip] Prefix key is **`Ctrl+a`** (`C-a`), *not* tmux's `C-b`. Press and release the prefix, then the command key.

---

## Sessions (detach / reattach)

```bash
screen -S <name>          # new named session
screen -ls                # list sessions
screen -r <name>          # reattach
screen -d -r <name>       # detach it elsewhere + reattach here (steal it back)
screen -x <name>          # attach WITHOUT detaching — multiple viewers share one session
screen -X -S <name> quit  # kill a session
```

| Inside a session | Key |
|---|---|
| Detach (leave running) | `C-a d` |
| New window | `C-a c` |
| Next / previous window | `C-a n` / `C-a p` |
| Window list | `C-a "` |
| Split horizontally / vertically | `C-a S` / `C-a |` |
| Move between regions | `C-a Tab` |
| Toggle logging to `screenlog.N` | `C-a H` |
| Scrollback (copy mode) | `C-a [` (Esc to exit) |

```bash
screen -L -S scan bash -c 'nmap -p- 10.10.11.166'   # detached, logged, one command
```

---

## Offensive: Session Hijacking (privesc)

If a higher-privileged user (often **root**) is running screen, and you can reach its socket,
you can attach and inherit their shell — no password.

```bash
# Find live screen sockets and who owns them
ls -la /var/run/screen/       # per-user dirs: S-<user>/  (older: /tmp/screens or /tmp/uscreens)
screen -ls                    # your own; but check other users' socket dirs directly

# Same-UID or a multiuser session → just attach
screen -x <user>/<session>    # e.g. screen -x root/rootsess

# A root-owned, world-accessible socket is instant root:
screen -x root/
```

Enable multiuser on a session *you* control (or one you can inject into) with
`C-a :multiuser on` then `C-a :acladd <user>`. The tmux/screen hijack privesc pattern is in
[[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc#Hijacking tmux / screen Sessions|Linux Priv Esc — Hijacking tmux / screen]].

## Offensive: SUID screen → root (CVE-2017-5618)

GNU screen **4.5.0** setuid-root failed to drop privileges when opening its log file (`-L`),
giving an **arbitrary-file-write as root** → local root (the public PoC drops a malicious
`/etc/ld.so.preload` + a rootshell `.so`). If `find / -perm -4000 2>/dev/null` shows a
setuid `screen`, check its version:

```bash
screen --version          # 4.5.0 (and some 4.5.x) = vulnerable to CVE-2017-5618
ls -la $(which screen)    # confirm the setuid bit (-rwsr-xr-x)
```

Any SUID screen is also a GTFOBins shell (`screen` spawns a shell that may keep the euid) —
see [GTFOBins — screen](https://gtfobins.github.io/gtfobins/screen/).

---

## Quick Reference

| Goal | Command / Key |
|---|---|
| New named session | `screen -S <name>` |
| Detach | `C-a d` |
| List / reattach | `screen -ls` / `screen -r <name>` |
| Steal a detached session | `screen -d -r <name>` |
| **Share/attach without detaching** | `screen -x <user>/<name>` |
| Split / switch region | `C-a S` `C-a |` / `C-a Tab` |
| Log session | `screen -L …` or `C-a H` |
| Hijack root's session | `screen -x root/<sess>` (if socket reachable) |
| SUID-screen root | check `screen --version` = 4.5.0 → CVE-2017-5618 |

---

> [!note] **See also** — the modern sibling [[Tools/Command Shell/tmux|tmux]] (same persistence, `C-b` prefix); session-hijack + SUID/CVE privesc context [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]]; GTFOBins [screen](https://gtfobins.github.io/gtfobins/screen/).

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
