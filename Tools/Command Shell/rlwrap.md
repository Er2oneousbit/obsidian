# rlwrap

**Tags:** `#rlwrap` `#readline` `#reverseshell` `#shellupgrade` `#netcat` `#workflow`

`rlwrap` wraps any command in the GNU **readline** library, giving it line editing, command
**history** (up-arrow), and optional tab-completion — even if the program has none. The
operator use: wrap a **`nc` reverse-shell listener** so the caught shell has working arrow
keys, backspace, and history instead of a raw line where every mistake mangles the terminal.
The cheap first upgrade before (or without) a full PTY.

**Source:** https://github.com/hanslub42/rlwrap
**Install:** `sudo apt install rlwrap` (in Kali/Debian repos).

---

## Wrap a Reverse-Shell Catcher

```bash
# Instead of a bare listener:
rlwrap nc -lvnp 9001
#   → the shell that lands now has up-arrow history + inline editing

# With completion + case-insensitive history search
rlwrap -cAr nc -lvnp 9001
#   -c  complete filenames   -A  force ANSI colour handling   -r  put seen words in the completion list
```

## Wrap Other Bare-REPL Tools

```bash
rlwrap sqlite3 loot.db          # add history/editing to REPLs that lack it
rlwrap python2                  # older interpreters, ftp clients, telnet, etc.
rlwrap -H ~/.rev_history nc -lvnp 9001   # keep the wrapped session's history in a named file
```

---

## Scope — What It Does and Doesn't Fix

- ✅ Line editing, backspace, **up-arrow history**, home/end — the annoyances of a raw `nc` shell.
- ❌ It is **not** a PTY: no job control (`Ctrl-Z`/`fg`), no `sudo`/password prompts that need a
  tty, no `vim`/`less`/tab-completion *on the remote box*, no `Ctrl-C` handling.

For those, still do the full upgrade after catching:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'   # then Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

> [!tip] Workflow: `rlwrap nc -lvnp 9001` to catch comfortably, then run the `pty`/`stty` upgrade
> for a full interactive TTY. rlwrap makes the *pre-upgrade* moments (typing the pty one-liner
> itself) far less painful. Catch it inside [[Tools/Command Shell/tmux|tmux]] so a drop doesn't kill it.

---

## Quick Reference

| Goal | Command |
|---|---|
| Comfortable nc catcher | `rlwrap nc -lvnp 9001` |
| + completion / colour | `rlwrap -cAr nc -lvnp 9001` |
| Persist wrapped history | `rlwrap -H ~/.rev_history nc -lvnp 9001` |
| Wrap a bare REPL | `rlwrap sqlite3 db` / `rlwrap python2` |
| Full PTY (after catch) | `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `stty raw -echo; fg` |

---

> [!note] **See also** — the full TTY-upgrade recipe in [[Tools/Command Shell/Bash|Bash]] and [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]]; catchers [[Tools/Remote Access/Netcat|Netcat]] / [[Tools/Remote Access/socat|socat]] (socat can hand you a real PTY directly); keep it alive with [[Tools/Command Shell/tmux|tmux]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
