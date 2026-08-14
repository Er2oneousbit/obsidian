# Terminator

**Tags:** `#terminator` `#terminalemulator` `#workflow` `#broadcast` `#tiling` `#escapeinjection`

Tiling **terminal emulator** for Linux (GTK3 + the GNOME **VTE** widget, Python, GPL-2.0, v2.1.5 May 2025). Splits one window into an arbitrary grid of terminals and — the standout for engagements — can **broadcast keystrokes to a whole group of terminals at once**, so one command runs across many SSH sessions simultaneously. It's a GUI convenience on **your** box, not a multiplexer: unlike [[Tools/Command Shell/tmux|tmux]] its splits are local windows with **no server-side persistence** — if the SSH/VPN behind a pane drops, that pane dies. Run tmux *inside* Terminator panes to get both the grid and the persistence.

**Source:** https://gnome-terminator.org · https://github.com/gnome-terminator/terminator
**Install:** `sudo apt install terminator` (in Kali/Debian repos)

```bash
terminator                       # launch
terminator -l pentest            # launch a saved layout named "pentest"
```

> [!warning] "Terminator" is an overloaded name in security. **This note is the terminal emulator.** There is also an unrelated red-team/malware tool called *Terminator* (Spyboy) — a **BYOVD AV/EDR killer** that loads the vulnerable Zemana driver (`zam64.sys` / `zamguard64.sys`) to terminate security processes from kernel mode. That belongs in [[Class notes/HTB Academy/CPTS v2 (claude)/AV & EDR Evasion|AV & EDR Evasion]], not here — see the note at the bottom.

---

## Terminator vs tmux — pick the right one (or both)

| | **Terminator** | **tmux** |
|---|---|---|
| What it is | GUI terminal *emulator* (a window) | Terminal *multiplexer* (a server) |
| Runs on | Your local box only | Local **or the target** |
| Survives SSH/VPN drop | ❌ pane dies with its connection | ✅ session keeps running server-side |
| Splitting | Mouse-driven tiling grid | Keyboard panes/windows |
| Killer feature | **Broadcast typing** to grouped terminals | **Persistence** + scriptability |
| Works over a raw shell | ❌ needs a real GUI/X session | ✅ text-only, works on any dumb shell |

> [!tip] Best practice on an engagement: **Terminator for the local grid + broadcast**, with a **tmux inside each pane** so a dropped VPN doesn't cost you the shell. Terminator gives you the layout; tmux gives you the safety net.

---

## Layout & Navigation

| Action | Default key |
|---|---|
| Split horizontally (top/bottom) | `Ctrl+Shift+O` |
| Split vertically (side by side) | `Ctrl+Shift+E` |
| Move focus between terminals | `Alt+<arrow>` |
| Next / previous terminal | `Ctrl+Shift+N` / `Ctrl+Shift+P` |
| New tab | `Ctrl+Shift+T` |
| Maximize / zoom a terminal (toggle) | `Ctrl+Shift+X` |
| Close terminal | `Ctrl+Shift+W` |
| Find in scrollback | `Ctrl+Shift+F` |
| Copy / paste | `Ctrl+Shift+C` / `Ctrl+Shift+V` |

All keybindings are rebindable in **Preferences → Keybindings**. Config lives at `~/.config/terminator/config`.

---

## Broadcast Typing (the reason to use it)

Type once, run everywhere — invaluable when you have shells on many hosts (parallel enumeration, checking a config across a fleet, running the same command on every box during lateral movement).

- Each terminal has a small **group icon** in its title bar → set/join a group.
- Then choose the broadcast scope from that menu (or bind keys to the actions `broadcast_all`, `broadcast_group`, `broadcast_off` in Preferences → Keybindings):

| Mode | Effect |
|---|---|
| **Broadcast Off** | Keystrokes go only to the focused terminal (default) |
| **Broadcast Group** | Keystrokes go to every terminal in the same group |
| **Broadcast All** | Keystrokes go to *every* terminal in the window |

> [!warning] Broadcast is a foot-gun: a `rm`, a `reboot`, or pasting a password fires on **every** grouped host at once. Confirm the mode indicator before typing anything destructive, and default back to **Broadcast Off**.

---

## Saved Layouts

Arrange the grid you want (e.g. listener / tooling / notes / target-shell), then **Preferences → Layouts → Save** the current window. Relaunch it any time:

```bash
terminator -l <layout-name>          # open a saved layout
terminator -m                        # start maximized
terminator -e 'ssh user@10.10.10.10' # run a command in the new terminal
terminator -T 'HTB - Trick'          # set the window title
```

A per-engagement layout (panes pre-wired to your VPN, listener, and notes dir) turns box setup into one command.

---

## Terminal Escape Sequence Injection — attacks *on* the emulator

The genuine attack surface of a terminal emulator isn't a CVE in Terminator specifically — it's the **ANSI / OSC escape-sequence** class that applies to **every** emulator (Terminator included, via its VTE backend). Terminals interpret in-band control sequences; if you **display attacker-controlled bytes**, those bytes can drive the terminal, not just print.

**Where untrusted bytes reach your terminal on an engagement:**
- `cat`/`less -r`ing a file, log, or `.bash_history` pulled off a target
- SSH login banners / `/etc/issue` / MOTD on a box you connect to
- Attacker-controlled **filenames** rendered by `ls`
- Error messages, `git log` messages, `strings` of a binary

**Impact classes:**

| Class | What the sequence does |
|---|---|
| **Command injection** | Set the window title via `OSC 0/2`, then abuse a *title-report* query to echo it back onto your command line — the historic RCE (e.g. **CVE-2022-23465**, SwiftTerm). Modern VTE/Terminator disable title-reporting and answerback by **default**, closing the classic RCE — but don't assume it on every emulator. |
| **Clipboard hijack** | `OSC 52` writes your system clipboard from displayed content — your next paste runs the attacker's command. |
| **Screen / content spoofing** | Cursor moves, reverse video, background-colored text, and line clears let malicious output **hide commands or fake results** — you think you saw `id → uid=1000` when the real output was rewritten. |
| **DoS / lock-up** | Pathological sequences hang or wedge the emulator. |

CVE landscape: HD Moore's *Terminal Emulator Security Issues* (2003) is the origin; live examples include **CVE-2022-23465** (SwiftTerm title→cmd injection) and **CVE-2022-28391** (BusyBox on Alpine — injection via crafted output), plus the 2021 multi-emulator cluster (CVE-2021-28847/28848/32198/33500/42095).

> [!tip] **Defense (protect your own box):** never render untrusted output raw.
> ```bash
> cat -v suspicious.log        # shows ESC as ^[ instead of executing it
> less suspicious.log          # default sanitizes control chars (avoid less -r / -R here)
> hexdump -C hostile.bin | less
> strings hostile.bin          # strip to printable only
> ```
> Reading loot from a compromised host? Pull it back and inspect with the above, not by `cat`-ing it live in your working terminal.

> [!note] **Offensive angle** — the same trick weaponizes against a **defender**: plant escape sequences in a log or file a blue-teamer will `cat` during IR, to spoof their view or hijack their clipboard. This is a natural rider on **log poisoning** — see the log-injection points in [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]].

---

## Quick Reference

| Goal | Command / Key |
|---|---|
| Launch / launch a layout | `terminator` / `terminator -l <name>` |
| Split horiz / vert | `Ctrl+Shift+O` / `Ctrl+Shift+E` |
| Move focus | `Alt+<arrow>` |
| Zoom a terminal | `Ctrl+Shift+X` |
| Broadcast to group / all / off | group icon → Broadcast Group / All / Off |
| Run a command on launch | `terminator -e '<cmd>'` |
| Config file | `~/.config/terminator/config` |
| Inspect untrusted output safely | `cat -v file` · `less file` · `hexdump -C file` |

---

> [!note] **See also**
> Sibling terminal tool with server-side persistence: [[Tools/Command Shell/tmux|tmux]] — run one inside each Terminator pane. The escape-injection risk above applies equally to any emulator, tmux panes included.
> Where the *other* "Terminator" (Spyboy BYOVD AV/EDR killer) belongs: [[Class notes/HTB Academy/CPTS v2 (claude)/AV & EDR Evasion|AV & EDR Evasion]].
> Weaponizing escape injection via log poisoning: [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]].

---

*Created: 2026-08-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
