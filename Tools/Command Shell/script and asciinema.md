# script & asciinema

**Tags:** `#script` `#asciinema` `#logging` `#evidence` `#transcript` `#reporting` `#workflow`

Two terminal-session **recorders** — the evidence-capture side of the toolkit. `script`
(util-linux, on every Linux box) writes a full typescript of a session's input+output to a
file; **asciinema** records to a compact, replayable `.cast` you can play back or share.
On an engagement they give you a timestamped, defensible record of exactly what you ran on a
host — the standalone complement to [[Tools/Command Shell/tmux|tmux]]'s `pipe-pane`.

**Source:** `script` = util-linux · asciinema = https://asciinema.org / https://github.com/asciinema/asciinema
**Install:** `script` is preinstalled (util-linux); `asciinema` → `sudo apt install asciinema` (or `pipx install asciinema`).

---

## `script` — plaintext transcript (always available)

```bash
# Record everything until you `exit` (the whole session → engagement.log)
script -q engagement-$(date +%F).log
# … do your work …
exit                       # stops recording

script -a engagement.log   # APPEND to an existing log (don't clobber)

# Timed recording → exact-speed replay (great for demonstrating an exploit)
script --log-out session.log --log-timing timing.log      # (modern util-linux)
scriptreplay --log-out session.log --log-timing timing.log
# older syntax:  script -t 2> timing.log session.log   then   scriptreplay timing.log session.log
```

> [!warning] `script` captures **raw terminal bytes** — control/escape sequences and colour
> codes end up in the file, so a plain `cat` of the log can be noisy (or itself risky, per the
> escape-injection note). View with `cat -v`, or strip ANSI: `sed 's/\x1b\[[0-9;]*m//g'`.
> It also records **secrets you type** (passwords) in the clear — store logs accordingly.

---

## asciinema — replayable cast

```bash
asciinema rec demo.cast        # record; Ctrl-D / `exit` to stop
asciinema rec -c "nmap -p- 10.10.11.166" scan.cast   # record just one command
asciinema play demo.cast       # replay locally
asciinema play -s 3 demo.cast  # 3x speed;  -i 2  caps idle gaps at 2s
asciinema upload demo.cast     # push to asciinema.org (PUBLIC by default — see OPSEC)
```

The `.cast` is JSON (timing + output) — small, diff-able, embeddable in a report/writeup.

> [!warning] **`asciinema upload` publishes to a public server.** Never upload client/engagement
> recordings — keep them local and hand them over in the report. Treat the `.cast` as sensitive
> (it contains everything on screen, secrets included).

---

## When to use which

| | `script` | asciinema | tmux `pipe-pane` |
|---|---|---|---|
| Availability | everywhere (util-linux) | install needed | needs tmux |
| Output | plaintext log (+timing) | replayable `.cast` | plaintext stream per pane |
| Best for | report evidence, grep-able transcript | demoing an exploit at real speed | passively logging a long session you're already in |

Run any of these on **your** box to log your own actions. Running a recorder **on a target**
leaves an artifact and captures into a file there — usually you'd rather log locally.

---

## Quick Reference

| Goal | Command |
|---|---|
| Record a session | `script -q engagement.log` … `exit` |
| Append to a log | `script -a engagement.log` |
| Timed record → replay | `script --log-out s.log --log-timing t.log` / `scriptreplay --log-out s.log --log-timing t.log` |
| Strip ANSI from a log | `sed 's/\x1b\[[0-9;]*m//g' engagement.log` |
| asciinema record / play | `asciinema rec demo.cast` / `asciinema play demo.cast` |
| Record one command | `asciinema rec -c "<cmd>" out.cast` |

---

> [!note] **See also** — passive per-pane logging while you work: [[Tools/Command Shell/tmux|tmux]] `pipe-pane`; the raw-bytes/escape-injection caveat when viewing logs: [[Tools/Command Shell/Terminator|Terminator]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
