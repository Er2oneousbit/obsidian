# HTB - Synced

#HTB #Synced #rsync #FileTransfer #Easy

Target: 10.129.115.18

## Services

- 873/tcp  rsync   protocol version 31

## Recon

```bash
nmap -sV --open -oA initial_scan 10.129.115.18
# 873/tcp open  rsync   (protocol version 31)

nmap -p- --open -oA full_tcp_scan 10.129.115.18
# 873/tcp open  rsync

nmap -sC -p 873 -oA script_scan 10.129.115.18
```

## Foothold

> [!warning] **Recorded notes stop at the scan.** The original file captured only the three nmap runs and the protocol version — no module listing, no file retrieval, no flag.

The box is an anonymous rsync exercise; the next steps would be listing modules and pulling the share:

```bash
rsync --list-only rsync://10.129.115.18/
rsync --list-only rsync://10.129.115.18/<module>/
rsync -av rsync://10.129.115.18/<module>/ ./loot/
```

See [[Services/File Xfer/Rsync|Rsync]] for the full enumeration and anonymous-module workflow.
