# reGeorg

**Tags:** `#reGeorg` `#pivoting` `#tunneling` `#socks` `#webshell` `#http`

Turns a web server you can upload to into a **SOCKS proxy over HTTP(S)**. You drop a tunnel webshell (`tunnel.php`/`.aspx`/`.jsp`) into the web root, then run a local Python proxy that relays TCP through ordinary HTTP requests to that shell. The go-to pivot when the target has **no TCP egress except the web port it already serves** — all traffic rides 80/443, so it passes firewalls and (often) inspection. Slow, but works where SSH/chisel/ligolo can't dial out. Successor to the original "reDuh".

**Source:** https://github.com/sensepost/reGeorg (Python 2 — use a py3 fork on modern Kali)
**Install:** `git clone https://github.com/sensepost/reGeorg`

```bash
# After uploading tunnel.php to the target web root, start the local SOCKS proxy
python2 reGeorgSocksProxy.py -p 1080 -u http://target.com/tunnel.php
# then set /etc/proxychains.conf → socks5 127.0.0.1 1080
```

> [!note] **See also**
> Covered as the "webshell-only egress" pivot in [[Class notes/HTB Academy/CPTS v2 (claude)/Pivoting, Tunneling & Port Forwarding|Pivoting, Tunneling & Port Forwarding]]. Needs an upload/write primitive first — see [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]] / [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]]. Pair with [[Tools/Remote Access/Proxychains|proxychains]] to use the resulting SOCKS proxy.

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
