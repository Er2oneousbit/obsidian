# Windows Terminal (wt.exe)

**Tags:** `#windowsterminal` `#wt` `#windows` `#terminalemulator` `#workflow` `#tiling`

Microsoft's modern, open-source terminal **emulator** for Windows — tabs, tiling panes, and
multiple **profiles** (cmd, Windows PowerShell, PowerShell 7 `pwsh`, WSL distros, SSH) in one
GPU-rendered window. It's the Windows analog of [[Tools/Command Shell/Terminator|Terminator]]:
a local-convenience emulator on **your** box (or when you're RDP'd into a Windows attack host),
**not** a multiplexer — no server-side persistence, and no built-in broadcast typing.

**Source:** https://github.com/microsoft/terminal
**Install:** default on Windows 11 and modern Windows 10; else Microsoft Store or `winget install Microsoft.WindowsTerminal`.

---

## Launch & Layout from the CLI

```powershell
wt                                   # launch (default profile)
wt -p "PowerShell"                   # open a specific profile by name
wt -p "Ubuntu" -d C:\loot            # profile + starting directory
wt new-tab -p "cmd" `; split-pane -p "PowerShell" `; split-pane -H wsl.exe
#   build a whole tab+pane layout in one command (`; separates sub-commands)
wt -w 0 nt -p "pwsh"                 # open a new tab in the EXISTING window (-w 0)
```

## Panes & Tabs (default keys)

| Action | Key |
|---|---|
| Split pane (auto/duplicate) | `Alt+Shift+D` |
| Split vertical / horizontal | `Alt+Shift++` / `Alt+Shift+-` |
| Move focus between panes | `Alt+<arrow>` |
| Resize pane | `Alt+Shift+<arrow>` |
| New tab / next tab | `Ctrl+Shift+T` / `Ctrl+Tab` |
| New tab of a profile | `Ctrl+Shift+<n>` (nth profile) |
| Close pane | `Ctrl+Shift+W` |
| Command palette | `Ctrl+Shift+P` |

Settings/keybindings are JSON: **Ctrl+,** (or `settings.json`).

---

## Notes for Operators

- **One window, every shell.** Profiles let you keep cmd, PowerShell 7, and a WSL Kali pane
  side by side — handy when pivoting between Windows-native and Linux tooling on a Windows host.
- **No persistence / no broadcast.** Unlike screen/tmux it won't survive a reboot or dropped
  RDP, and it can't type-to-all-panes like Terminator. For persistence, run tmux inside a WSL pane.
- **Escape-sequence injection applies here too.** Like any emulator, Windows Terminal interprets
  in-band control sequences; don't render untrusted output (logs, filenames, loot) raw. Same
  class documented in [[Tools/Command Shell/Terminator|Terminator]].

---

> [!note] **See also** — cross-OS emulator siblings [[Tools/Command Shell/Terminator|Terminator]] (Linux) / [[Tools/Command Shell/iTerm2|iTerm2]] (macOS); the shells it hosts [[Tools/Command Shell/Powershell|PowerShell]] / [[Tools/Command Shell/cmd.exe|cmd.exe]]; persistence via [[Tools/Command Shell/tmux|tmux]] (inside a WSL pane).

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
