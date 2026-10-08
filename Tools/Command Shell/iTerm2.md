# iTerm2 (and Terminal.app)

**Tags:** `#iterm2` `#macos` `#terminalemulator` `#workflow` `#broadcast` `#tmux` `#escapeinjection`

The operator's terminal **emulator** on macOS. `Terminal.app` is the built-in default; **iTerm2**
is the near-universal replacement (panes, profiles, triggers, a tmux integration, and
**broadcast input**). It's the macOS counterpart to [[Tools/Command Shell/Terminator|Terminator]]
(Linux) and [[Tools/Command Shell/Windows Terminal (wt)|Windows Terminal]] — a local GUI
convenience, not a multiplexer, but its **`tmux -CC`** integration bolts real server-side
persistence onto native iTerm2 tabs/panes. Its security relevance is a textbook one: **displaying
untrusted output was remote code execution** (CVE-2019-9535).

**Source:** https://iterm2.com · https://github.com/gnachman/iTerm2
**Install:** `brew install --cask iterm2` (Terminal.app ships with macOS).

---

## Layout & Broadcast (default keys)

| Action | Key |
|---|---|
| Split pane vertically / horizontally | `Cmd+D` / `Cmd+Shift+D` |
| Move between panes | `Cmd+Opt+<arrow>` |
| New tab / window | `Cmd+T` / `Cmd+N` |
| **Broadcast input to all panes** | `Cmd+Shift+I` (toggle) |
| Find / search scrollback | `Cmd+F` |
| Instant Replay (rewind terminal) | `Cmd+Opt+B` |

> [!tip] **Broadcast input** (`Cmd+Shift+I`, or *Shell → Broadcast Input*) types into every pane
> at once — iTerm2's version of Terminator's broadcast / tmux `synchronize-panes`. Same foot-gun:
> a `rm`/`reboot`/pasted password fires on every host. Watch the broadcast-mode banner.

## tmux Integration — GUI panes + persistence

```bash
# On a remote box (or locally), attach with -CC: tmux windows become native iTerm2 tabs/panes,
# but the SESSION still lives server-side, so a dropped SSH doesn't lose it.
tmux -CC new -s work
tmux -CC attach -t work
```

This is the reason to use iTerm2 for engagements: the tiling/mouse ergonomics of a GUI emulator
**and** the disconnect-survival of [[Tools/Command Shell/tmux|tmux]] in one.

---

## Security: Displaying Untrusted Output = RCE (CVE-2019-9535)

iTerm2 **< 3.3.6** had an RCE (CVE-2019-9535, found by Radically Open Security / disclosed via
Mozilla): its **tmux-integration** code processed control sequences in program output unsafely,
so merely **`cat`-ing a malicious file, viewing a crafted log, or SSHing to a hostile banner**
could execute commands on the operator's Mac. It's the sharpest real-world example of the
terminal **escape-sequence injection** class (full treatment in [[Tools/Command Shell/Terminator|Terminator]]):

- Patched in 3.3.6 (Oct 2019) — **update**; but the *class* affects every emulator (Terminal.app,
  iTerm2, Terminator, Windows Terminal) via clipboard (`OSC 52`), title-report, and screen-spoofing tricks.
- Reading loot pulled off a target on your Mac? Don't render it raw — `cat -v`, `less` (no `-R`),
  `hexdump -C`, `strings`. Never `cat` a hostile file straight into your working terminal.

> [!warning] **Offensive angle** — plant escape sequences in a file/log a macOS operator or
> blue-teamer will open in iTerm2/Terminal (spoof their view, hijack their clipboard, or — on an
> unpatched iTerm2 — RCE). A natural rider on log poisoning; see [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]].

---

## Quick Reference

| Goal | Key / Command |
|---|---|
| Split vert / horiz | `Cmd+D` / `Cmd+Shift+D` |
| Broadcast to all panes | `Cmd+Shift+I` |
| tmux GUI + persistence | `tmux -CC attach -t <name>` |
| macOS default shell it hosts | [[Tools/Command Shell/zsh|zsh]] |
| View untrusted output safely | `cat -v file` / `hexdump -C file` (not `less -R`) |
| Patch the RCE | iTerm2 ≥ 3.3.6 (CVE-2019-9535) |

---

> [!note] **See also** — cross-OS emulator siblings [[Tools/Command Shell/Terminator|Terminator]] (Linux) / [[Tools/Command Shell/Windows Terminal (wt)|Windows Terminal]] (Windows); persistence [[Tools/Command Shell/tmux|tmux]] (native via `-CC`); the shell it runs [[Tools/Command Shell/zsh|zsh]]; escape-injection class [[Tools/Command Shell/Terminator|Terminator]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
