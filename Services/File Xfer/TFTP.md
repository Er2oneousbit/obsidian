#TFTP #TrivialFileTransferProtocol #filetransfer

## What is TFTP?
Trivial File Transfer Protocol — simplified, unauthenticated file transfer protocol. No directory listing, no authentication, no encryption. Used in network booting (PXE), router/switch firmware updates, and embedded device configs.

- Port **UDP 69** — TFTP (UDP only)
- No authentication — access by knowing the filename
- No directory listing — must know exact file path
- Used by: routers, switches, IP phones, PXE boot servers

---

## TFTP Commands

| Command | Description |
|---|---|
| `connect <host> [port]` | Set remote host (and optionally port) |
| `get <remote_file> [local_file]` | Download file from server |
| `put <local_file> [remote_file]` | Upload file to server |
| `mode [ascii\|binary\|octet]` | Set transfer mode |
| `status` | Show connection status, mode, timeout |
| `verbose` | Toggle verbose output |
| `trace` | Toggle packet tracing |
| `timeout <seconds>` | Set per-packet timeout |
| `quit` | Exit tftp client |

---

## Connect / Access

```bash
# Connect and download (Linux)
tftp <target>
tftp> get filename.cfg

# One-liner download
tftp -g -r filename.cfg <target>
tftp -g -r /etc/passwd <target>  # if server allows path traversal

# One-liner upload
tftp -p -l localfile.txt -r remotefile.txt <target>

# TFTP client session
tftp 10.129.14.28
tftp> connect 10.129.14.28
tftp> get config.cfg
tftp> put malware.bin
```

---

## Enumeration

```bash
# Nmap
nmap -p 69 --script tftp-enum -sU <target>
nmap -sU -p 69 -sV <target>

# Enumerate common filenames
nmap -sU -p 69 --script tftp-enum --script-args tftp-enum.filelist=filenames.txt <target>

# Metasploit
use auxiliary/scanner/tftp/tftpbrute
# (brute force common filenames)
```

### Common Files to Request

```bash
tftp> get /etc/passwd
tftp> get /etc/shadow
tftp> get cisco-confg          # Cisco running config
tftp> get running-config       # Cisco/network device config
tftp> get startup-config
tftp> get network-confg
tftp> get router-confg
tftp> get pix-confg            # Cisco PIX firewall
```

---

## Attack Vectors

### Pull Sensitive Files (Network Devices)

```bash
# Cisco config typically has credentials in plaintext or type-5/type-7 hashes
tftp -g -r startup-config <target>
tftp -g -r running-config <target>

# Crack Cisco Type-7 password (easily reversible)
# Use online tools or ciscot7.py
```

### Upload Malicious Config

```bash
# If TFTP is writable, replace config or plant backdoor
tftp -p -l malicious.cfg -r startup-config <target>
```

### PXE Boot Abuse

```bash
# TFTP often serves PXE boot images — pull the boot image
tftp> get pxelinux.0
tftp> get pxelinux.cfg/default  # may reveal boot options, network info
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| World-readable server directory | Anyone can download any file |
| Writable server directory | Anyone can upload/replace files |
| No firewall restriction | Accessible from internet |
| Sensitive configs (passwords, keys) served | Credential exposure |
| Path traversal possible | Read arbitrary filesystem files |

---

## Quick Reference

| Goal | Command |
|---|---|
| Download file | `tftp -g -r filename host` |
| Upload file | `tftp -p -l local -r remote host` |
| Interactive session | `tftp host` then `get filename` |
| Common device config | `tftp -g -r running-config host` |
| Nmap enum | `nmap -sU -p 69 --script tftp-enum host` |
