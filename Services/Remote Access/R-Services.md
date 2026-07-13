#RServices #RemoteServices #rlogin #rsh #rexec #remoteaccess

## What is R-Services?
R-Services (Berkeley r-commands) — legacy suite for remote access and command execution between Unix/Linux hosts. No encryption. Authentication based on trusted host lists (`/etc/hosts.equiv` and `.rhosts`). Largely replaced by SSH.

- Ports: **TCP 512** (rexec), **TCP 513** (rlogin), **TCP 514** (rsh/rcp)
- Common on older Unix systems, some legacy environments

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

# rexec — run with explicit user/pass
rexec <target> -l <user> -p <pass> <command>

# rcp — copy files
rcp <local_file> <user>@<target>:<remote_path>
rcp <user>@<target>:<remote_file> <local_path>
```

---

## Enumeration

```bash
# Nmap
nmap -p 512,513,514 --script rexec-brute,rlogin-brute,rsh-brute -sV <target>
nmap -p 512-514 -sV <target>

# Check if rlogin responds
nc -nv <target> 513

# Metasploit
use auxiliary/scanner/rservices/rexec_login
use auxiliary/scanner/rservices/rlogin_login
use auxiliary/scanner/rservices/rsh_login
```

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

### Brute Force rlogin/rexec

```bash
hydra -L users.txt -P passwords.txt rlogin://<target>
hydra -L users.txt -P passwords.txt rexec://<target>

# Metasploit
use auxiliary/scanner/rservices/rlogin_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

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
| Brute force | `hydra -L users.txt -P pass.txt rlogin://host` |
| Sniff creds | `tcpdump -i eth0 port 512 or 513 or 514 -A` |
